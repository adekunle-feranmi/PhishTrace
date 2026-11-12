"""Phase 9 hardening regressions.

These tests pin the controls that are easy to lose in a refactor: the config
snapshot must never echo credentials, evidence downloads must stay inside the
managed data directories, the fetcher must fail closed when it is not open, and
the session cookie keeps its protective flags.
"""

from __future__ import annotations

import asyncio
import re
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from phishtrace.api.app import create_admin, create_app
from phishtrace.api.auth import SessionManager
from phishtrace.api.routes import _confined_evidence_path
from phishtrace.config import AuthConfig, Config, ProviderSettings, ReportConfig
from phishtrace.core.fetcher import FetchDenied, IsolatedFetcher
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository

PASSWORD = "Str0ng-Enough-Pass!"


def build_app(tmp_path):
    config = Config(
        host="127.0.0.1",
        data_dir=tmp_path / "data",
        auth=AuthConfig(enabled=True, session_secret="z" * 48),
        providers={
            "ghunt": ProviderSettings(
                enabled=False,
                options={"cookies": "SID=live-google-session-cookie", "legal_acknowledged": False},
            ),
            "shodan": ProviderSettings(options={"api_key_hint": "should-not-leak"}),
        },
        reports=ReportConfig(
            misp={"enabled": True, "url": "https://misp.example", "key": "misp-live-key"},
            opencti={"enabled": True, "url": "https://cti.example", "token": "opencti-live-token"},
        ),
    )
    config.data_dir.mkdir(parents=True, exist_ok=True)
    _, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))
    create_admin(config, repo, "analyst", PASSWORD)
    app = create_app(config, repo=repo, sessions=SessionManager("z" * 48))
    return app


def login(client: TestClient) -> None:
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post(
        "/login",
        data={"username": "analyst", "password": PASSWORD, "csrf_token": token, "next_url": "/"},
        follow_redirects=False,
    )
    assert response.status_code == 303


def test_config_snapshot_redacts_provider_and_integration_secrets(tmp_path):
    app = build_app(tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/config").status_code == 401
        login(client)
        snapshot = client.get("/api/config").json()

    assert snapshot["providers"]["ghunt"]["options"]["cookies"] == "[REDACTED]"
    assert snapshot["providers"]["shodan"]["options"]["api_key_hint"] == "[REDACTED]"
    assert snapshot["reports"]["misp"]["key"] == "[REDACTED]"
    assert snapshot["reports"]["opencti"]["token"] == "[REDACTED]"
    # Non-secret settings and presence flags survive.
    assert snapshot["reports"]["misp"]["url"] == "https://misp.example"
    assert snapshot["providers"]["ghunt"]["options"]["legal_acknowledged"] is False
    assert isinstance(snapshot["api_keys_present"], dict)
    assert "live-google-session-cookie" not in str(snapshot)


def test_session_cookie_is_httponly_and_samesite(tmp_path):
    app = build_app(tmp_path)
    with TestClient(app) as client:
        page = client.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        response = client.post(
            "/login",
            data={"username": "analyst", "password": PASSWORD, "csrf_token": token, "next_url": "/"},
            follow_redirects=False,
        )
    cookie = response.headers.get("set-cookie", "")
    assert "phishtrace_session=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie


def _request_for(config: Config):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(config=config)))


def test_evidence_paths_are_confined_to_managed_directories(tmp_path):
    config = Config(host="127.0.0.1", data_dir=tmp_path / "data", providers={})
    config.data_dir.mkdir(parents=True)
    config.evidence_dir.mkdir(parents=True)
    config.archive_dir.mkdir(parents=True)
    request = _request_for(config)

    inside = config.evidence_dir / "abc.bin"
    inside.write_bytes(b"evidence")
    assert _confined_evidence_path(request, str(inside)) == inside.resolve()

    with pytest.raises(HTTPException) as outside:
        _confined_evidence_path(request, "/etc/passwd")
    assert outside.value.status_code == 404

    link = config.evidence_dir / "link.bin"
    link.symlink_to("/etc/passwd")
    with pytest.raises(HTTPException) as escaped:
        _confined_evidence_path(request, str(link))
    assert escaped.value.status_code == 404

    sibling = tmp_path / "data-other" / "file.bin"
    sibling.parent.mkdir(parents=True)
    sibling.write_bytes(b"x")
    with pytest.raises(HTTPException):
        _confined_evidence_path(request, str(sibling))


def test_fetcher_fails_closed_when_not_open(tmp_path):
    config = Config(host="127.0.0.1", data_dir=tmp_path / "data", providers={})
    fetcher = IsolatedFetcher(config)
    with pytest.raises(FetchDenied) as denied:
        asyncio.run(fetcher._request("https://example.com/", None, 64))
    assert denied.value.rule == "state"
