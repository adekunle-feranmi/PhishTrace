"""Phase 6 tests: web console backend, live progress and generated UI assets.

The fixture provider is deliberately deterministic: it never touches the
network, emits one IP observation and one dated timeline event. That exercises
the graph, timeline, evidence browser and progress path without making the
suite depend on an external service.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from phishtrace.api.app import create_app
from phishtrace.api.auth import hash_password
from phishtrace.config import AuthConfig
from phishtrace.core.registry import Registry
from phishtrace.providers.base import BaseProvider, ProviderMeta
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository
from phishtrace.tests.conftest import make_config

SEED = "https://login-secure.example.com/verify"
EVENT_AT = "2024-02-03T00:00:00+00:00"


class UiFixtureProvider(BaseProvider):
    meta = ProviderMeta(
        name="ui_fixture",
        accepts=("url",),
        emits=("ip",),
        category="fixture",
        reliability=0.9,
        description="Phase 6 deterministic provider",
    )

    async def run(self, ctx):
        observation = ctx.emit(
            "ip", "93.184.216.34", "resolves-to", "strong",
            observed_at=EVENT_AT, tags=["fixture"],
            meta={"fixture": True},
        )
        ctx.event(
            EVENT_AT,
            kind="domain-registered",
            label="fixture domain registration",
            detail="Deterministic Phase 6 event",
            url="https://example.com/whois",
            indicator_value=ctx.indicator.normalized if ctx.indicator else None,
            precision="day",
        )
        return ctx.result


def build_app(tmp_path: Path, *, auth_enabled: bool = False):
    overrides = {"providers": {}}
    if auth_enabled:
        overrides["auth"] = AuthConfig(
            enabled=True,
            session_secret="phase6-test-session-secret-0123456789abcdef",
            cookie_secure=False,
        )
    config = make_config(tmp_path, **overrides)
    engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))
    registry = Registry(config, provider_classes=[UiFixtureProvider])
    app = create_app(config, repo=repo, registry=registry)
    return app, config, repo


def wait_for_run(app, investigation_id: str, timeout: float = 20.0) -> dict:
    snapshot = app.state.runs.wait(investigation_id, timeout)
    assert snapshot is not None, "run manager lost the investigation"
    assert not snapshot["running"], f"run still active after {timeout}s: {snapshot}"
    return snapshot


# --------------------------------------------------------------------- pages
def test_console_pages_and_assets_render(tmp_path):
    app, config, _ = build_app(tmp_path)
    with TestClient(app) as client:
        index = client.get("/")
        assert index.status_code == 200
        body = index.text
        for marker in ("New investigation", "Investigation summary", "Kit lab",
                       "Coverage", "Evidence browser", "Infrastructure &amp; persona graph"):
            assert marker in body
        assert "/static/app.js" in body and "/static/style.css" in body
        assert "console is loading" not in body.lower()

        script = client.get("/static/app.js")
        assert script.status_code == 200
        assert "EventSource" in script.text
        assert ".innerHTML" not in script.text, "untrusted values must use textContent"

        style = client.get("/static/style.css")
        assert style.status_code == 200
        assert "--accent" in style.text

        headers = index.headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["content-security-policy"]


# --------------------------------------------------------------------- start
def test_start_run_live_progress_and_reuse(tmp_path):
    app, config, repo = build_app(tmp_path)
    with TestClient(app) as client:
        response = client.post("/api/investigations", json={
            "seed": f"hxxps://{SEED.removeprefix('https://')}",
            "run_sightings": False,
        })
        assert response.status_code == 202, response.text
        payload = response.json()
        assert payload["reused"] is False
        investigation_id = payload["investigation_id"]
        assert len(investigation_id) == 32
        assert payload["seed"]["normalized"] == SEED

        snapshot = wait_for_run(app, investigation_id)
        assert snapshot["stage"] == "done"
        assert snapshot["state"] == "finished"

        progress = client.get(f"/api/investigations/{investigation_id}/progress?after=0")
        assert progress.status_code == 200
        data = progress.json()
        assert data["terminal"] is True
        assert data["stage"] == "done"
        assert data["status"] in {"completed", "partial"}
        assert data["counts"]["indicators"] >= 2
        assert data["cursor"] >= 1
        assert any(event["event"] == "seed" for event in data["events"])
        assert any(event["event"] == "node.done" for event in data["events"])
        assert data["coverage"]["ran"] >= 1
        assert data["providers"]["total"] >= 1

        # Incremental polling returns only newer events and never rewinds.
        incremental = client.get(
            f"/api/investigations/{investigation_id}/progress?after={data['cursor']}"
        ).json()
        assert incremental["events"] == []
        assert incremental["cursor"] == data["cursor"]

        graph = client.get(f"/api/investigations/{investigation_id}/graph").json()
        assert len(graph["nodes"]) >= 2
        assert graph["edges"], "fixture observation must create an edge"
        assert all(edge.get("src") and edge.get("dst") for edge in graph["edges"])

        timeline = client.get(f"/api/investigations/{investigation_id}/timeline").json()
        assert timeline["merged"]["earliest_observed"]["occurred_at"].startswith("2024-02-03")
        assert timeline["timeline"][0]["stage"] == "registration"
        assert timeline["merged"]["wording"]["timeline"] == "earliest observed"

        coverage = client.get(f"/api/investigations/{investigation_id}/coverage").json()
        assert coverage["coverage"]["ran"] == ["ui_fixture"]
        assert any(row["provider"] == "ui_fixture" and row["status"] == "ran"
                   for row in coverage["providers"])

        detail = client.get(f"/api/investigations/{investigation_id}").json()
        before_nodes = detail["counts"]["indicators"]
        before_edges = detail["counts"]["edges"]

        # Idempotent start: terminal investigation is reused, no duplicate graph.
        again = client.post("/api/investigations", json={"seed": SEED, "run_sightings": False})
        assert again.status_code == 200, again.text
        assert again.json()["reused"] is True
        assert again.json()["investigation_id"] == investigation_id
        graph_again = client.get(f"/api/investigations/{investigation_id}/graph").json()
        assert len(graph_again["nodes"]) == before_nodes
        assert len(graph_again["edges"]) == before_edges


def test_start_validation_and_invalid_kind(tmp_path):
    app, _, _ = build_app(tmp_path)
    with TestClient(app) as client:
        assert client.post("/api/investigations", json={"seed": "   "}).status_code == 422
        assert client.post("/api/investigations", json={"seed": "x" * 3000}).status_code == 422
        invalid = client.post("/api/investigations", json={"seed": "not a seed", "kind": "nonsense"})
        assert invalid.status_code == 422
        assert "invalid seed" in invalid.json()["detail"]


def test_progress_for_unknown_investigation_is_404(tmp_path):
    app, _, _ = build_app(tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/investigations/deadbeef/progress").status_code == 404
        assert client.get("/api/investigations/deadbeef/progress/stream").status_code == 404


def test_sse_stream_closes_immediately_for_terminal_run(tmp_path):
    app, config, repo = build_app(tmp_path)
    investigation = repo.create_investigation(
        seed=SEED, seed_type="url", seed_normalized=SEED,
        config_snapshot=config.redacted(), owner="local",
    )
    repo.finalize(
        investigation["id"], status="completed", coverage={"providers": [], "ran": [], "skipped": [], "failed": []},
        stats={"duration_ms": 12}, summary={"headline": "fixture"},
    )
    with TestClient(app) as client:
        response = client.get(f"/api/investigations/{investigation['id']}/progress/stream")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["cache-control"] == "no-store"
        body = response.text
        assert "event: progress" in body
        assert "event: end" in body
        assert '"terminal": true' in body
        assert '"stage": "done"' in body


# ------------------------------------------------------------------- evidence
def test_sightings_evidence_preview_and_raw_download(tmp_path):
    app, config, repo = build_app(tmp_path)
    investigation = repo.create_investigation(
        seed=SEED, seed_type="url", seed_normalized=SEED,
        config_snapshot=config.redacted(), owner="local",
    )
    repo.finalize(
        investigation["id"], status="completed", coverage={}, stats={}, summary={},
    )
    repo.add_sighting(investigation["id"], {
        "platform": "mastodon", "post_url": "https://social.example/@analyst/123",
        "post_id": "123", "author_handle": "@analyst", "role": "promoter",
        "posted_at": datetime(2024, 2, 4, 12, 0, tzinfo=timezone.utc),
        "text_excerpt": "fresh phishing kit for sale",
        "indicator_form_matched": "url",
    })
    record = repo.evidence_store.put_text(
        provider="ui_fixture",
        request={"url": SEED},
        text="<html><body>fixture capture</body></html>",
        url=SEED,
        status_code=200,
        content_type="text/html",
    )
    repo.add_evidence(investigation["id"], record)

    with TestClient(app) as client:
        sightings = client.get(f"/api/investigations/{investigation['id']}/sightings").json()
        assert sightings["count"] == 1
        assert sightings["sightings"][0]["platform"] == "mastodon"
        assert sightings["sightings"][0]["role"] == "promoter"

        evidence = client.get(f"/api/investigations/{investigation['id']}/evidence").json()
        assert evidence["count"] == 1
        row = evidence["evidence"][0]
        assert row["sha256"] == record.sha256

        detail = client.get(
            f"/api/investigations/{investigation['id']}/evidence/{row['id']}"
        ).json()
        assert "fixture capture" in detail["preview"]
        assert detail["raw_response_path"] == row["raw_response_path"]
        # The console renders HTML in a sandboxed frame, so the API has to say
        # what the capture is instead of leaving the client to guess.
        assert detail["kind"] == "html"
        assert detail["preview_truncated"] is False
        assert detail["preview_limit"] == 100_000

        raw = client.get(f"/api/investigations/{investigation['id']}/evidence/{row['id']}/raw")
        assert raw.status_code == 200
        assert b"fixture capture" in raw.content
        assert raw.headers["content-type"].startswith("text/html")

        missing = client.get(
            f"/api/investigations/{investigation['id']}/evidence/not-a-real-evidence-id"
        )
        assert missing.status_code == 404


# ------------------------------------------------------------------------ kits
def test_kit_endpoint_rejects_non_http_and_is_gated_without_active_fetch(tmp_path):
    app, config, repo = build_app(tmp_path)
    investigation = repo.create_investigation(
        seed=SEED, seed_type="url", seed_normalized=SEED,
        config_snapshot=config.redacted(), owner="local",
    )
    with TestClient(app) as client:
        bad = client.post(
            f"/api/investigations/{investigation['id']}/kit",
            json={"url": "javascript:alert(1)", "force": True},
        )
        assert bad.status_code == 422

        gated = client.post(
            f"/api/investigations/{investigation['id']}/kit",
            json={"url": "https://suspected-kit.example/login.php", "force": True},
        )
        assert gated.status_code == 200, gated.text
        payload = gated.json()
        assert payload["persisted"] is False
        assert payload["skipped"], "active_fetch must gate the isolated fetcher"
        assert "active" in payload["skipped"].lower() or "disabled" in payload["skipped"].lower()
        assert client.get(f"/api/investigations/{investigation['id']}/kits").json()["kits"] == []


# ------------------------------------------------------------------------ auth
def test_auth_enabled_start_requires_csrf_and_enforces_owner(tmp_path):
    app, config, repo = build_app(tmp_path, auth_enabled=True)
    analyst = repo.create_user("analyst", hash_password("Analyst-Password-42!"), is_admin=False)
    other = repo.create_user("other", hash_password("Other-Password-42!"), is_admin=False)
    analyst_session = app.state.sessions.issue(analyst["id"], "analyst")
    other_session = app.state.sessions.issue(other["id"], "other")

    with TestClient(app) as client:
        client.cookies.set(config.auth.cookie_name, analyst_session["token"])
        missing_csrf = client.post("/api/investigations", json={"seed": SEED, "run_sightings": False})
        assert missing_csrf.status_code == 403

        response = client.post(
            "/api/investigations",
            json={"seed": SEED, "run_sightings": False},
            headers={"X-CSRF-Token": analyst_session["csrf"]},
        )
        assert response.status_code == 202, response.text
        investigation_id = response.json()["investigation_id"]
        wait_for_run(app, investigation_id)

        assert client.get(f"/api/investigations/{investigation_id}").status_code == 200

        other_client = TestClient(app)
        other_client.cookies.set(config.auth.cookie_name, other_session["token"])
        forbidden = other_client.get(f"/api/investigations/{investigation_id}")
        assert forbidden.status_code == 403
        assert other_client.get(f"/api/investigations/{investigation_id}/graph").status_code == 403
        other_client.close()
