"""Phase 10 API tests: entity index, entity detail and suspect ranking."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from phishtrace.api.app import create_app
from phishtrace.core.entities import EntityResolver
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository
from phishtrace.tests.conftest import make_config


def build_app(tmp_path: Path):
    config = make_config(tmp_path, providers={})
    _, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))
    return create_app(config, repo=repo), repo


def seed_case(repo, seed: str, phone: str = "+15550100432") -> str:
    inv = repo.create_investigation(
        seed=seed, seed_type="domain", seed_normalized=seed, config_snapshot={"test": True}
    )["id"]
    root, _ = repo.ensure_indicator(
        inv, type="domain", value=seed, normalized_value=seed, meta={"seed": True}, tags=["seed"]
    )
    number, _ = repo.ensure_indicator(inv, type="phone", value=phone, normalized_value=phone)
    repo.add_edge(
        inv, src_id=root["id"], dst_id=number["id"], relation="contact-phone",
        provider="test", confidence=0.8, selector_strength="strong",
    )
    EntityResolver(repo).resolve(inv)
    return inv


def test_entity_index_and_filters(tmp_path):
    app, repo = build_app(tmp_path)
    seed_case(repo, "a.evil-example.com")

    with TestClient(app) as client:
        payload = client.get("/api/entities").json()
        assert payload["count"] == len(payload["entities"]) == 2
        kinds = {row["kind"] for row in payload["entities"]}
        assert kinds == {"identity", "case"}

        identities = client.get("/api/entities?kind=identity").json()["entities"]
        assert identities
        assert all(row["kind"] == "identity" for row in identities)

        hit = client.get("/api/entities?q=15550100432").json()
        assert hit["count"] == 1
        assert hit["entities"][0]["investigation_count"] == 1

        assert client.get("/api/entities?kind=bogus").status_code == 422


def test_entity_detail_by_id_and_key(tmp_path):
    app, repo = build_app(tmp_path)
    seed_case(repo, "a.evil-example.com")

    with TestClient(app) as client:
        by_key = client.get("/api/entities/phone:%2B15550100432")
        assert by_key.status_code == 200
        body = by_key.json()
        assert body["label"] == "+15550100432"
        assert len(body["members"]) == 1
        assert body["cases"][0]["seed"] == "a.evil-example.com"

        by_id = client.get(f"/api/entities/{body['id']}").json()
        assert by_id["id"] == body["id"]
        assert {link["relation"] for link in by_id["links"]} == {"observed-in-case"}

        assert client.get("/api/entities/phone:%2B000").status_code == 404


def test_investigation_entities_and_suspects_routes(tmp_path):
    app, repo = build_app(tmp_path)
    inv = seed_case(repo, "a.evil-example.com")

    with TestClient(app) as client:
        entities = client.get(f"/api/investigations/{inv}/entities").json()
        assert entities["count"] >= 2

        suspects = client.get(f"/api/investigations/{inv}/suspects").json()
        assert suspects["candidate_count"] == 1
        top = suspects["suspects"][0]
        assert top["label"] == "+15550100432"
        assert top["score"] == 45
        assert top["caveats"]

        assert client.get("/api/investigations/deadbeef/suspects").status_code == 404
        assert client.get("/api/investigations/deadbeef/entities").status_code == 404
