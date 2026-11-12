from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from phishtrace.api.app import create_app, create_admin
from phishtrace.api.auth import SessionManager
from phishtrace.config import AuthConfig, Config
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository


def build_app(tmp_path, *, enabled: bool = True, max_attempts: int = 8):
    config = Config(
        host="127.0.0.1",
        data_dir=tmp_path / "data",
        auth=AuthConfig(enabled=enabled, session_secret="z" * 48, login_max_attempts=max_attempts),
        providers={},
    )
    config.data_dir.mkdir(parents=True, exist_ok=True)
    _, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))
    create_admin(config, repo, "analyst", "Str0ng-Enough-Pass!")
    app = create_app(config, repo=repo, sessions=SessionManager("z" * 48))
    return app


def login(client: TestClient, username="analyst", password="Str0ng-Enough-Pass!"):
    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    return client.post("/login", data={
        "username": username, "password": password, "csrf_token": token, "next_url": "/",
    }, follow_redirects=False)


def test_health_is_public(tmp_path):
    with TestClient(build_app(tmp_path)) as client:
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["app"] == "PhishTrace"
        assert "providers" in body
        assert response.headers["x-content-type-options"] == "nosniff"


def test_ui_requires_authentication(tmp_path):
    with TestClient(build_app(tmp_path)) as client:
        response = client.get("/", follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert client.get("/api/investigations").status_code == 401


def test_login_flow_and_csrf(tmp_path):
    with TestClient(build_app(tmp_path)) as client:
        page = client.get("/login")
        assert page.status_code == 200
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        bad = client.post("/login", data={"username": "analyst", "password": "wrong", "csrf_token": token})
        assert bad.status_code == 401
        response = login(client)
        assert response.status_code == 303
        session = client.get("/api/session")
        assert session.status_code == 200
        assert session.json()["user"]["username"] == "analyst"
        csrf = session.json()["csrf"]
        assert client.get("/").status_code == 200
        # logout requires CSRF
        assert client.post("/logout").status_code == 403
        assert client.post("/logout", headers={"X-CSRF-Token": csrf}, follow_redirects=False).status_code == 303
        assert client.get("/api/session").status_code == 401


def test_login_csrf_mismatch_rejected(tmp_path):
    with TestClient(build_app(tmp_path)) as client:
        response = client.post("/login", data={
            "username": "analyst", "password": "Str0ng-Enough-Pass!", "csrf_token": "wrong",
        })
        assert response.status_code == 403


def test_login_rate_limit(tmp_path):
    with TestClient(build_app(tmp_path, max_attempts=1)) as client:
        page = client.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        first = client.post("/login", data={"username": "analyst", "password": "bad", "csrf_token": token})
        assert first.status_code == 401
        token2 = client.cookies.get("phishtrace_csrf")
        second = client.post("/login", data={"username": "analyst", "password": "bad", "csrf_token": token2})
        assert second.status_code == 429
        assert "retry-after" in {k.lower() for k in second.headers}


def test_auth_disabled_local_mode(tmp_path):
    with TestClient(build_app(tmp_path, enabled=False)) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/investigations").status_code == 200
        assert client.get("/api/session").json()["auth_enabled"] is False


def test_audit_log_records_login(tmp_path):
    with TestClient(build_app(tmp_path)) as client:
        login(client)
        session = client.get("/api/session").json()
        entries = client.get("/api/audit", headers={"X-CSRF-Token": session["csrf"]}).json()["entries"]
        assert any(entry["action"] == "login" for entry in entries)
