from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from phishtrace.api.auth import (
    LoginThrottle, PasswordPolicyError, SessionManager, hash_password, validate_password,
    verify_password,
)
from phishtrace.config import Config, ConfigError, is_loopback_host, load_config, validate_bind
from phishtrace.models import iso, parse_timestamp, utcnow


# --------------------------------------------------------------------- config
def test_loopback_detection():
    assert is_loopback_host("127.0.0.1")
    assert is_loopback_host("::1")
    assert is_loopback_host("localhost")
    assert not is_loopback_host("0.0.0.0")
    assert not is_loopback_host("10.0.0.5")


def test_non_loopback_without_auth_is_refused():
    with pytest.raises(ConfigError):
        validate_bind("0.0.0.0", auth_enabled=False, session_secret=None)


def test_non_loopback_with_auth_but_no_secret_is_refused():
    with pytest.raises(ConfigError):
        validate_bind("0.0.0.0", auth_enabled=True, session_secret=None)


def test_non_loopback_with_auth_and_secret_is_allowed():
    validate_bind("0.0.0.0", auth_enabled=True, session_secret="x" * 40)


def test_env_and_yaml_layering(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("host: 0.0.0.0\nauth:\n  enabled: true\nport: 9999\n", encoding="utf-8")
    monkeypatch.setenv("PHISHTRACE_SESSION_SECRET", "s" * 48)
    loaded = load_config(cfg, env_file=tmp_path / "missing.env")
    assert loaded.host == "0.0.0.0"
    assert loaded.port == 9999


def test_yaml_authentication_required_for_network_bind(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("host: 0.0.0.0\nauth:\n  enabled: false\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(cfg, env_file=tmp_path / "missing.env")


def test_dotenv_parsing(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nDEMO_KEY='abc'\nexported=1\nQUOTED=\"a b c\"\nEXISTING=fromfile\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("EXISTING", "fromenv")
    from phishtrace.config import load_dotenv
    env = load_dotenv(env_file)
    assert env["DEMO_KEY"] == "abc"
    assert env["QUOTED"] == "a b c"
    assert env["EXISTING"] == "fromenv"


def test_redacted_config_has_no_secrets(tmp_path):
    config = Config(data_dir=tmp_path, env={"VIRUSTOTAL_API_KEY": "SECRET"}, auth={"enabled": True, "session_secret": "topsecret"})
    blob = str(config.redacted())
    assert "SECRET" not in blob
    assert "topsecret" not in blob
    assert config.redacted()["api_keys_present"]["VIRUSTOTAL_API_KEY"] is True


# ----------------------------------------------------------------------- auth
def test_password_hashing_and_policy():
    hashed = hash_password("CorrectHorse9!Battery")
    assert hashed.startswith("$argon2")
    assert verify_password("CorrectHorse9!Battery", hashed)
    assert not verify_password("wrong", hashed)
    with pytest.raises(PasswordPolicyError):
        validate_password("short", "admin")
    with pytest.raises(PasswordPolicyError):
        validate_password("alllowercase123", "admin")
    with pytest.raises(PasswordPolicyError):
        validate_password("AdminPassword!9", "admin")
    validate_password("Str0ng-Enough-Pass!", "admin")


def test_session_roundtrip_and_tamper():
    manager = SessionManager("x" * 40, ttl_hours=1)
    session = manager.issue("user-1", "analyst")
    loaded = manager.load(session["token"])
    assert loaded["uid"] == "user-1"
    assert loaded["csrf"] == session["csrf"]
    assert manager.load(session["token"] + "tampered") is None
    assert manager.load(None) is None


def test_expired_session_rejected(monkeypatch):
    manager = SessionManager("y" * 40, ttl_hours=1)
    token = manager.issue("u", "a")["token"]
    import itsdangerous

    def fake_loads(*args, **kwargs):
        raise itsdangerous.SignatureExpired("expired")

    monkeypatch.setattr(manager.serializer, "loads", fake_loads)
    assert manager.load(token) is None


def test_login_throttle():
    throttle = LoginThrottle(max_attempts=2, window_seconds=60)
    key = "1.2.3.4|admin"
    assert not throttle.blocked(key)
    throttle.fail(key)
    throttle.fail(key)
    assert throttle.blocked(key)
    assert throttle.retry_after(key) > 0
    throttle.success(key)
    assert not throttle.blocked(key)


# ------------------------------------------------------------------ timestamps
def test_timestamp_normalization():
    assert iso(datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)) == "2024-01-02T03:04:05Z"
    assert iso("2024-01-02T03:04:05") == "2024-01-02T03:04:05Z"
    assert iso("2024-01-02") == "2024-01-02T00:00:00Z"
    assert iso("20240102030405") == "2024-01-02T03:04:05Z"
    assert iso(1704164645) == "2024-01-02T03:04:05Z"
    assert parse_timestamp("not-a-date") is None
    assert parse_timestamp("Wed, 02 Oct 2024 13:00:00 GMT").year == 2024


# --------------------------------------------------------------------- storage
def test_investigation_and_dedup(repo):
    inv = repo.create_investigation(seed="hxxps://evil[.]example/login", seed_type="url",
                                    seed_normalized="https://evil.example/login", config_snapshot={})
    first, created = repo.ensure_indicator(inv["id"], type="domain", value="evil.example",
                                            normalized_value="evil.example", depth=1)
    again, created_again = repo.ensure_indicator(inv["id"], type="domain", value="evil.example",
                                                  normalized_value="evil.example", depth=2, tags=["feed"])
    assert created and not created_again
    assert first["id"] == again["id"]
    assert again["depth"] == 1
    assert "feed" in again["tags"]
    repo.add_edge(inv["id"], src_id=first["id"], dst_id=first["id"], relation="self",
                  provider="demo", confidence=0.5, selector_strength="weak")
    edge, edge_created = repo.add_edge(inv["id"], src_id=first["id"], dst_id=first["id"], relation="self",
                                       provider="demo", confidence=0.9, selector_strength="medium")
    assert edge_created is False
    assert edge["confidence"] == 0.9
    sighting = {
        "platform": "mastodon", "post_url": "https://example.social/@a/1", "post_id": "1",
        "indicator_form_matched": "evil[.]example", "text_excerpt": "phish", "posted_at": utcnow(),
    }
    _, s1 = repo.add_sighting(inv["id"], sighting)
    _, s2 = repo.add_sighting(inv["id"], sighting)
    assert s1 and not s2
    assert repo.counts(inv["id"])["sightings"] == 1


def test_finalize_and_purge(repo):
    inv = repo.create_investigation(seed="example.com", seed_type="domain",
                                    seed_normalized="example.com", config_snapshot={})
    repo.finalize(inv["id"], status="completed", coverage={}, stats={}, summary={})
    assert repo.get_investigation(inv["id"])["status"] == "completed"
    # purge cutoff in the future removes it
    result = repo.purge_older_than(-1)
    assert result["count"] >= 1
    assert repo.get_investigation(inv["id"]) is None
