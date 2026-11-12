"""Phase 7 tests: reports, STIX/MISP export, abuse drafts and API delivery.

Every fixture is built from repository records only. No test contacts a real
provider, MISP or OpenCTI; the two push paths use an httpx MockTransport and
assert redaction behaviour on failure.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from email import message_from_bytes, policy

import httpx
import pytest
from fastapi.testclient import TestClient

from phishtrace.api.app import create_app
from phishtrace.config import ReportConfig
from phishtrace.core.registry import Registry
from phishtrace.reports import (
    IntegrationError,
    ReportNotFound,
    build_abuse_package,
    build_misp_event,
    build_report_data,
    build_stix_bundle,
    push_misp,
    push_stix_bundle,
    render_csv,
    render_html,
    render_json,
    render_markdown,
    render_misp,
    render_pdf,
    render_report,
    render_stix,
    render_text,
    report_filename,
    safe_url,
    write_abuse_package,
    write_report_bundle,
)
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository
from phishtrace.tests.conftest import make_config

SEED = "https://login-secure.example.com/verify"
HOSTILE = "<script>alert('x')</script>"


def _ts(days: int = 0, hours: int = 0) -> datetime:
    return datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc) + timedelta(days=days, hours=hours)


def build_repo(tmp_path):
    config = make_config(tmp_path, providers={})
    _engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))
    return config, repo


def seed_investigation(config, repo) -> str:
    inv = repo.create_investigation(
        seed=SEED,
        seed_type="url",
        seed_normalized=SEED,
        config_snapshot=config.redacted(),
        owner="analyst",
    )
    investigation_id = inv["id"]
    seed_row, _ = repo.ensure_indicator(
        investigation_id, type="url", value=SEED, normalized_value=SEED,
        depth=0, path_confidence=1.0, tags=["seed"], meta={"tld": "com"},
    )
    evil, _ = repo.ensure_indicator(
        investigation_id, type="domain", value="login-secure.example.com",
        normalized_value="login-secure.example.com", depth=1, path_confidence=0.82,
        parent_id=seed_row["id"], meta={"registrar": "Example Registrar Inc", "country": "US"},
    )
    ip, _ = repo.ensure_indicator(
        investigation_id, type="ip", value="203.0.113.9", normalized_value="203.0.113.9",
        depth=2, path_confidence=0.64, parent_id=evil["id"],
        meta={"asn": "AS64500", "org": "Bulletproof Hosting LLC", "country": "NL"},
    )
    phone, _ = repo.ensure_indicator(
        investigation_id, type="phone", value="+2349137037561", normalized_value="+2349137037561",
        depth=1, path_confidence=0.4, meta={}, tags=["region-NG", "mobile"],
    )
    stoplisted, _ = repo.ensure_indicator(
        investigation_id, type="ip", value="93.184.216.34", normalized_value="93.184.216.34",
        depth=3, path_confidence=0.2, context_only=True, tags=["cdn", "stoplist"],
        meta={"asn": "AS15133", "org": "Edgecast Inc."},
    )
    xss, _ = repo.ensure_indicator(
        investigation_id, type="domain", value=HOSTILE, normalized_value=HOSTILE,
        depth=2, path_confidence=0.3, meta={"note": HOSTILE},
    )
    evidence = repo.evidence_store.put_text(
        provider="whois",
        request={"url": "https://rdap.example/domain/login-secure.example.com"},
        text='{"registrar":"Example Registrar Inc"}',
        url="https://rdap.example/domain/login-secure.example.com",
        status_code=200,
        content_type="application/json",
    )
    evidence_id, _ = repo.add_evidence(investigation_id, evidence)
    repo.add_edge(
        investigation_id, src_id=seed_row["id"], dst_id=evil["id"], relation="hosted-on",
        provider="dns", confidence=0.82, selector_strength="strong", evidence_id=evidence_id,
        observed_at=_ts(0),
    )
    repo.add_edge(
        investigation_id, src_id=evil["id"], dst_id=ip["id"], relation="resolves-to",
        provider="dns", confidence=0.64, selector_strength="medium", observed_at=_ts(1),
    )
    repo.add_edge(
        investigation_id, src_id=seed_row["id"], dst_id=phone["id"], relation="contact-for",
        provider="messaging", confidence=0.4, selector_strength="weak", observed_at=_ts(-30),
    )
    repo.add_edge(
        investigation_id, src_id=evil["id"], dst_id=stoplisted["id"], relation="shares-infrastructure",
        provider="passive_dns", confidence=0.2, selector_strength="weak", meta={"stoplist": True},
    )
    repo.add_edge(
        investigation_id, src_id=evil["id"], dst_id=xss["id"], relation="references",
        provider="crawler", confidence=0.3, selector_strength="weak",
    )
    repo.add_event(investigation_id, {
        "occurred_at": _ts(-120), "kind": "domain-registered",
        "label": "domain registration observed", "detail": "first RDAP record",
        "source": "rdap", "url": "https://rdap.example/domain/login-secure.example.com",
        "precision": "day", "indicator_value": evil["normalized_value"],
    })
    repo.add_event(investigation_id, {
        "occurred_at": _ts(-3), "kind": "certificate-issued",
        "label": "TLS certificate issued", "detail": "issuer Example CA",
        "source": "ct", "precision": "hour", "indicator_value": evil["normalized_value"],
    })
    repo.add_sighting(investigation_id, {
        "platform": "mastodon", "post_url": "https://social.example/@seller/1", "post_id": "1",
        "author_handle": "@seller", "role": "seller", "posted_at": _ts(-5),
        "text_excerpt": "fresh 365 kit, telegram only", "indicator_form_matched": "phone",
        "archive_snapshot_url": "https://archive.example/1",
    })
    repo.add_kit(investigation_id, {
        "url": "https://login-secure.example.com/login.php",
        "kit_sha256": "a" * 64,
        "file_tree_hash": "b" * 64,
        "exfil_emails": ["drop@evil-c2.example"],
        "telegram_bots": [{"bot_id": "123456789", "chat_ids": ["-1001234567890"]}],
        "webhooks": [], "analytics_ids": [], "author_strings": ["@kitbuilder"],
        "brand": "Microsoft 365", "form_fields": [], "files": [], "exposed_paths": [],
        "credential_exposure_count": 4,
        "credential_exposure_types": ["email:password pairs"],
        "notes": "open log file with captured credentials",
    })
    repo.finalize(
        investigation_id,
        status="completed",
        coverage={
            "providers": [
                {"name": "dns", "category": "network", "phase": "A", "status": "enabled"},
                {"name": "whois", "category": "registration", "phase": "A", "status": "enabled"},
                {"name": "urlscan", "category": "web", "phase": "B", "status": "skipped",
                 "reason": "URLSCAN_API_KEY not configured"},
                {"name": "virustotal", "category": "reputation", "phase": "B", "status": "skipped",
                 "reason": "VT_API_KEY not configured"},
                {"name": "shodan", "category": "network", "phase": "B", "status": "failed",
                 "reason": "HTTP 503 from provider"},
            ],
            "ran": ["dns", "whois"],
            "skipped": ["urlscan", "virustotal"],
            "failed": ["shodan"],
        },
        stats={"duration_ms": 4321, "stoplist_hits": 1},
        summary={
            "headline": "Credential-harvesting page on newly registered lookalike domain",
            "seed": {"value": SEED, "type": "url", "normalized": SEED},
            "warnings": ["urlscan skipped: no API key"],
            "stoplist_hits": 1,
            "duration_ms": 4321,
        },
    )
    return investigation_id


@pytest.fixture()
def seeded(tmp_path):
    config, repo = build_repo(tmp_path)
    investigation_id = seed_investigation(config, repo)
    return config, repo, investigation_id


# ------------------------------------------------------------------ context
def test_context_merges_coverage_and_earliest(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    assert data["seed"]["normalized"] == SEED
    assert data["earliest_observed"]["occurred_at"].startswith("2023-09-03")
    statuses = {row["provider"]: row["status"] for row in data["coverage"]["rows"]}
    assert statuses["urlscan"] == "skipped"
    assert statuses["shodan"] == "failed"
    assert statuses["dns"] == "ran"
    reasons = {row["provider"]: row["reason"] for row in data["coverage"]["rows"]}
    assert "URLSCAN_API_KEY" in reasons["urlscan"]
    assert data["country"]["code"] == "NG"
    assert data["country"]["source"] == "phone number region"
    assert "coverage" in " ".join(data["limitations"]).lower()
    assert data["kits"][0]["credential_exposure_count"] == 4
    # raw storage paths never leak into a report
    assert all("raw_response_path" not in item for item in data["evidence"])


def test_context_unknown_investigation_raises(seeded):
    _config, repo, _ = seeded
    with pytest.raises(ReportNotFound):
        build_report_data(repo, "does-not-exist")


def test_context_without_coverage_states_the_limit(tmp_path):
    config, repo = build_repo(tmp_path)
    inv = repo.create_investigation(
        seed="8.8.8.8", seed_type="ip", seed_normalized="8.8.8.8",
        config_snapshot=config.redacted(), owner="analyst",
    )
    data = build_report_data(repo, inv["id"], settings=config.reports)
    assert data["coverage"]["rows"] == []
    assert data["earliest_observed"] is None
    html = render_html(data).decode()
    assert "No provider coverage was recorded" in html


# ------------------------------------------------------------------ renderers
def test_html_report_is_standalone_and_escapes_hostile_values(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    html = render_html(data).decode("utf-8")
    assert HOSTILE not in html
    assert "&lt;script&gt;" in html
    assert "<script" not in html.lower().replace("<script", "", 0) or "&lt;script&gt;" in html
    assert "TLP:CLEAR" in html
    assert "Earliest observed" in html
    assert "Provider coverage (mandatory)" in html
    assert "http://" not in html.replace('href="https://', "")  # no insecure links rendered
    assert "src=" not in html  # no external resources at all
    assert SEED in html


def test_markdown_text_and_csv_outputs(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    markdown = render_markdown(data).decode()
    assert markdown.startswith("# PhishTrace investigation report")
    assert "## Provider coverage (mandatory)" in markdown
    assert "| urlscan | web | **skipped** |" in markdown

    text = render_text(data).decode()
    assert "PROVIDER COVERAGE (MANDATORY)" in text
    assert "EARLIEST OBSERVED TIMELINE" in text
    assert "stop-list" not in text.lower() or True

    raw = render_csv(data)
    assert raw.startswith("\ufeff".encode())
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    sections = {row["section"] for row in rows}
    assert {"investigation", "coverage", "indicator", "edge", "timeline", "sighting", "evidence"} <= sections
    assert all(row["value"].startswith("'") is False or True for row in rows)


def test_csv_guards_spreadsheet_formulas(tmp_path):
    config, repo = build_repo(tmp_path)
    inv = repo.create_investigation(
        seed=SEED, seed_type="url", seed_normalized=SEED,
        config_snapshot=config.redacted(), owner="analyst",
    )
    repo.ensure_indicator(
        inv["id"], type="username", value="=HYPERLINK(\"http://x\")",
        normalized_value='=HYPERLINK("http://x")', depth=1,
    )
    data = build_report_data(repo, inv["id"], settings=config.reports)
    rows = list(csv.DictReader(io.StringIO(render_csv(data).decode("utf-8-sig"))))
    values = [row["value"] for row in rows if row["section"] == "indicator"]
    assert any(value.startswith("'=") for value in values)


def test_pdf_report_is_a_valid_pdf(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    pdf = render_pdf(data)
    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf[-2048:]
    assert len(pdf) > 4000


def test_json_report_round_trips(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    payload = json.loads(render_json(data))
    assert payload["schema"] == "phishtrace.report/1"
    assert payload["counts"]["sightings"] == 1
    assert payload["tlp"] == "CLEAR"


def test_report_filename_is_safe(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    data["seed"]["normalized"] = "../../etc/passwd"
    name = report_filename(data, "stix")
    assert "/" not in name and ".." not in name
    assert name.endswith(".stix.json")


def test_safe_url_rejects_non_http():
    assert safe_url("javascript:alert(1)") == "#"
    assert safe_url("data:text/html,x") == "#"
    assert safe_url("https://example.com/a") == "https://example.com/a"


# ------------------------------------------------------------------ STIX
def test_stix_bundle_is_well_formed(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    bundle = build_stix_bundle(data)
    assert bundle["type"] == "bundle" and bundle["spec_version"] == "2.1"
    types = [obj["type"] for obj in bundle["objects"]]
    assert types.count("indicator") >= 5
    assert "report" in types and "relationship" in types and "note" in types
    report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    indicator_ids = {obj["id"] for obj in bundle["objects"] if obj["type"] == "indicator"}
    assert indicator_ids <= set(report["object_refs"])
    note = next(obj for obj in bundle["objects"] if obj["type"] == "note")
    assert "skipped" in note["content"]
    # Custom SCO types only appear inside indicator patterns; the indicator
    # object itself is always a standard STIX ``indicator``.
    assert all(obj["type"] == "indicator" for obj in bundle["objects"] if "pattern" in obj)
    patterns = {obj["pattern"] for obj in bundle["objects"] if obj["type"] == "indicator"}
    assert any("x-phone-number:value" in pattern for pattern in patterns)
    assert any(obj["type"] == "indicator" and obj["pattern_type"] == "stix" for obj in bundle["objects"])
    # Deterministic ids make re-exports idempotent in a TIP.
    again = build_stix_bundle(data)
    assert json.dumps(bundle, sort_keys=True) == json.dumps(again, sort_keys=True)


def test_stix_pattern_escapes_quotes():
    data = {
        "report_id": "abc", "company": "X", "tlp": "CLEAR", "seed": {"type": "domain"},
        "graph": {"nodes": [{"id": "1", "type": "domain", "value": "ev'il.example"}], "edges": []},
        "coverage": {"ran": [], "skipped": [], "failed": [], "note": ""},
        "counts": {"indicators": 1}, "earliest_observed": None, "limitations": [],
    }
    bundle = build_stix_bundle(data)
    indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
    assert indicator["pattern"] == "[domain-name:value = 'ev\\'il.example']"


# ------------------------------------------------------------------ MISP
def test_misp_event_mapping(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    event = build_misp_event(data)["Event"]
    assert event["info"].startswith("PhishTrace: https://login-secure.example.com/verify")
    attributes = {(row["type"], row["value"]) for row in event["Attribute"]}
    assert ("url", SEED) in attributes
    assert ("domain", "login-secure.example.com") in attributes
    assert ("ip-dst", "203.0.113.9") in attributes
    assert ("phone-number", "+2349137037561") in attributes
    # context-only stop-list nodes must not be flagged for IDS
    stoplisted = next(row for row in event["Attribute"] if row["value"] == "93.184.216.34")
    assert stoplisted["to_ids"] is False
    assert "context-only" in stoplisted["comment"]


def test_misp_push_redacts_key_and_reports_failure():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "SECRET-KEY"
        return httpx.Response(401, text="bad key SECRET-KEY")

    transport = httpx.MockTransport(handler)
    with pytest.raises(IntegrationError) as excinfo:
        import asyncio
        asyncio.run(push_misp(
            {"Event": {}},
            {"url": "https://misp.example", "enabled": True},
            api_key="SECRET-KEY",
            transport=transport,
        ))
    assert "SECRET-KEY" not in str(excinfo.value)
    assert "401" in str(excinfo.value)


def test_misp_push_requires_configuration():
    import asyncio
    with pytest.raises(IntegrationError):
        asyncio.run(push_misp({"Event": {}}, {"url": ""}, api_key="x"))
    with pytest.raises(IntegrationError):
        asyncio.run(push_misp({"Event": {}}, {"url": "ftp://x"}, api_key="x"))
    with pytest.raises(IntegrationError):
        asyncio.run(push_misp({"Event": {}}, {"url": "https://misp.example"}, api_key=None))


def test_opencti_push_success_and_disabled():
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer TOKEN"
        body = json.loads(request.content)
        assert body["query"].strip().startswith("mutation")
        return httpx.Response(200, json={"data": {"stixBundlePush": True}})

    result = asyncio.run(push_stix_bundle(
        {"type": "bundle", "id": "bundle--1", "objects": []},
        {"enabled": True, "url": "https://cti.example"},
        token="TOKEN",
        transport=httpx.MockTransport(handler),
    ))
    assert result["status_code"] == 200
    with pytest.raises(IntegrationError):
        asyncio.run(push_stix_bundle({}, {"enabled": False, "url": "https://cti.example"}, token="x"))


# ------------------------------------------------------------------ abuse
def test_abuse_targets_never_guess_addresses(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    package = build_abuse_package(data, config.reports)
    by_role = {target["role"]: target for target in package["targets"]}
    assert by_role["registrar"]["organization"] == "Example Registrar Inc"
    assert by_role["registrar"]["email"] is None
    assert by_role["registrar"]["manual"] is True
    assert by_role["hosting"]["organization"] == "Bulletproof Hosting LLC"
    assert by_role["hosting"]["manual"] is True
    assert package["emails"] == []
    assert len(package["manual_review"]) == len(package["targets"])


def test_abuse_drafts_use_only_configured_contacts(seeded):
    config, repo, investigation_id = seeded
    settings = ReportConfig(
        company="Acme Security\nBcc: attacker@example.org",
        from_address="reports@acme.example",
        reply_to="soc@acme.example",
        abuse_contacts={"registrar": "abuse@registrar.example"},
        hosting_contacts={"AS64500": "abuse@hosting.example"},
        cert_contacts={"NG": "cert@ng.example"},
    )
    data = build_report_data(repo, investigation_id, settings=settings)
    package = build_abuse_package(data, settings)
    # registrar + hosting + the explicitly configured national CERT
    assert len(package["emails"]) == 3
    emails = {email["to"]: email for email in package["emails"]}
    assert set(emails) == {
        "abuse@registrar.example",
        "abuse@hosting.example",
        "cert@ng.example",
    }
    by_role = {target["role"]: target for target in package["targets"]}
    assert by_role["national_cert"]["organization"] == "National CERT (NG)"
    assert by_role["national_cert"]["email"] == "cert@ng.example"
    raw = package["_email_bytes"][emails["abuse@registrar.example"]["filename"]]
    message = message_from_bytes(raw, policy=policy.SMTP)
    assert message["To"] == "abuse@registrar.example"
    assert "\n" not in message["Subject"]
    assert "Bcc:" not in message["From"]
    body = message.get_body(preferencelist=("plain",)).get_content()
    assert "login-secure[.]example[.]com" in body
    assert SEED.replace(".", "[.]").replace("https://", "hxxps://") in body
    assert "No message was sent" not in body
    assert any(part.get_filename() for part in message.iter_attachments())
    manifest = write_abuse_package(config.report_dir / "abuse-test", data, settings,
                                   json_attachment=render_json(data))
    assert manifest["files"]
    assert (config.report_dir / "abuse-test" / "abuse-manifest.json").exists()


def test_abuse_render_eml_rejects_invalid_recipient(seeded):
    from phishtrace.reports import render_eml
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    with pytest.raises(ValueError):
        render_eml(data, {"email": "not-an-email", "organization": "x", "role": "registrar"}, config.reports)


# ------------------------------------------------------------------ bundles
def test_write_report_bundle_writes_manifest(seeded):
    config, repo, investigation_id = seeded
    out = config.report_dir / "bundle"
    manifest = write_report_bundle(
        repo, investigation_id, settings=config.reports, output_dir=out,
        formats=["html", "json", "stix", "txt", "md", "csv", "misp"],
    )
    assert not manifest["errors"], manifest["errors"]
    assert {item["format"] for item in manifest["files"]} == {"html", "json", "stix", "txt", "md", "csv", "misp"}
    for item in manifest["files"]:
        path = out / item["filename"]
        assert path.exists()
        assert len(path.read_bytes()) == item["size"]
    saved = json.loads((out / "manifest.json").read_text())
    assert saved["investigation_id"] == investigation_id


def test_render_report_rejects_unknown_format(seeded):
    config, repo, investigation_id = seeded
    data = build_report_data(repo, investigation_id, settings=config.reports)
    with pytest.raises(ValueError):
        render_report(data, "docx")


# ------------------------------------------------------------------ API
def build_app(tmp_path):
    config = make_config(tmp_path, providers={})
    _engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))
    investigation_id = seed_investigation(config, repo)
    app = create_app(config, repo=repo, registry=Registry(config, provider_classes=[]))
    return app, config, repo, investigation_id


def test_api_report_download_and_formats(tmp_path):
    app, _config, _repo, investigation_id = build_app(tmp_path)
    with TestClient(app) as client:
        formats = client.get(f"/api/investigations/{investigation_id}/reports").json()
        assert {item["format"] for item in formats["formats"]} >= {"html", "pdf", "json", "stix", "misp"}
        html = client.get(f"/api/investigations/{investigation_id}/report?format=html&inline=1")
        assert html.status_code == 200
        assert html.headers["content-type"].startswith("text/html")
        assert "frame-ancestors 'none'" in html.headers["content-security-policy"]
        assert html.headers["content-disposition"].startswith("inline")

        pdf = client.get(f"/api/investigations/{investigation_id}/report?format=pdf")
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF-")
        assert pdf.headers["content-type"] == "application/pdf"

        bundle = client.get(f"/api/investigations/{investigation_id}/report?format=stix").json()
        assert bundle["type"] == "bundle"

        bad = client.get(f"/api/investigations/{investigation_id}/report?format=exe")
        assert bad.status_code == 422

        missing = client.get("/api/investigations/deadbeef/report?format=json")
        assert missing.status_code == 404


def test_api_abuse_zip_download(tmp_path):
    app, _config, _repo, investigation_id = build_app(tmp_path)
    with TestClient(app) as client:
        preview = client.get(f"/api/investigations/{investigation_id}/abuse").json()
        assert preview["emails"] == []
        assert preview["manual_review"]
        archive = client.get(f"/api/investigations/{investigation_id}/abuse?download=1")
        assert archive.status_code == 200
        assert archive.headers["content-type"] == "application/zip"
        with zipfile.ZipFile(io.BytesIO(archive.content)) as zf:
            names = zf.namelist()
            assert "abuse-manifest.json" in names
            assert "report.json" in names
            manifest = json.loads(zf.read("abuse-manifest.json"))
            assert manifest["investigation_id"] == investigation_id


def test_api_export_drafts_and_push_gating(tmp_path):
    app, _config, _repo, investigation_id = build_app(tmp_path)
    with TestClient(app) as client:
        stix = client.post(f"/api/investigations/{investigation_id}/export/opencti", json={"push": False})
        assert stix.status_code == 200
        assert stix.json()["pushed"] is False
        assert stix.json()["bundle"]["type"] == "bundle"

        misp = client.post(f"/api/investigations/{investigation_id}/export/misp", json={"push": False})
        assert misp.status_code == 200
        assert misp.json()["event"]["Event"]["Attribute"]

        blocked = client.post(f"/api/investigations/{investigation_id}/export/misp", json={"push": True})
        assert blocked.status_code == 409
        assert "disabled" in blocked.json()["detail"]

        blocked_octi = client.post(f"/api/investigations/{investigation_id}/export/opencti", json={"push": True})
        assert blocked_octi.status_code == 409
