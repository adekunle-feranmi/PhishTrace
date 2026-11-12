"""Phase 5 tests: isolated SSRF-safe fetcher and static kit analyzer.

Every test talks only to :class:`KitFixtureServer`, a harmless loopback server
that serves static phishing-kit *shapes*. No test touches the internet, no
payload is executed, and no real credential is captured.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from phishtrace.analyzers.kit import (
    KitAnalyzer,
    credential_signals,
    inspect_zip,
    kind_for,
    redact_secret_text,
    safe_member_name,
    simhash64,
)
from phishtrace.config import FetcherConfig
from phishtrace.core.fetcher import FetchDenied, IsolatedFetcher, fetcher_for
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository
from phishtrace.tests.conftest import make_config
from phishtrace.tests.kit_fixture import (
    ARCHIVE_EMAIL,
    EXFIL_EMAIL,
    LOG_TEXT,
    PNG_BYTES,
    RESULTS_CSV,
    TELEGRAM_BOT_ID,
    TELEGRAM_CHAT_ID,
    TELEGRAM_TOKEN,
    KitFixtureServer,
)

RAW_SECRETS = ("Passw0rd!2026", "hunter2", "Summer2026!", "Winter2025!", "qwerty123")


def kit_config(tmp_path, **overrides):
    """Config that permits loopback fetches and enables active fetching."""
    base = {"allow_localhost": True, "active_fetch": True}
    base.update(overrides)
    return make_config(tmp_path, fetcher=FetcherConfig(**base))


async def run_analysis(server: KitFixtureServer, tmp_path, path: str = "/", **kwargs):
    config = kit_config(tmp_path, **kwargs.pop("fetcher", {}))
    analyzer = KitAnalyzer(config)
    try:
        return await analyzer.analyze(server.url + path, force=True, **kwargs)
    finally:
        await analyzer.close()


# --------------------------------------------------------------------------- #
# Gating
# --------------------------------------------------------------------------- #


async def test_gate_requires_active_fetch(tmp_path):
    with KitFixtureServer() as server:
        analyzer = KitAnalyzer(make_config(tmp_path))  # active_fetch defaults to False
        try:
            report = await analyzer.analyze(server.url, force=True)
        finally:
            await analyzer.close()
    assert report.skipped
    assert "active fetching is disabled" in report.skipped
    assert report.files == []
    assert server.paths() == []


async def test_gate_requires_hostile_verdict_or_force(tmp_path):
    with KitFixtureServer() as server:
        analyzer = KitAnalyzer(kit_config(tmp_path))
        try:
            report = await analyzer.analyze(server.url)
        finally:
            await analyzer.close()
        assert report.skipped
        assert "confirmed hostile verdict" in report.skipped
        assert server.paths() == []

        verdict_report = await run_analysis(server, tmp_path, verdict="phishing", max_probes=0)
        assert verdict_report.skipped is None
        assert verdict_report.status_code == 200


# --------------------------------------------------------------------------- #
# Full signal extraction
# --------------------------------------------------------------------------- #


async def test_full_kit_signal_extraction(tmp_path):
    with KitFixtureServer() as server:
        report = await run_analysis(server, tmp_path)
        assert report.skipped is None
        assert report.status_code == 200
        assert "Microsoft 365" in report.title
        assert report.brand == "Microsoft 365"
        assert report.brand_confidence == "high"

        emails = {item["value"] for item in report.exfil_emails}
        assert EXFIL_EMAIL in emails
        assert ARCHIVE_EMAIL in emails

        bots = {bot["bot_id"]: bot for bot in report.telegram_bots}
        assert TELEGRAM_BOT_ID in bots
        assert TELEGRAM_CHAT_ID in bots[TELEGRAM_BOT_ID]["chat_ids"]
        assert bots[TELEGRAM_BOT_ID]["token_redacted"] is True

        hook_kinds = {hook["kind"] for hook in report.webhooks}
        assert {"generic", "telegram"} <= hook_kinds

        analytics = {item["value"] for item in report.analytics_ids}
        assert {"G-ABCDEFGHIJ", "UA-123456-7"} <= analytics

        field_names = {field["name"].lower() for field in report.form_fields}
        assert {"email", "password", "otp"} <= field_names
        assert any(field["form_action"].endswith("/post.php") for field in report.form_fields)

        authors = " ".join(report.author_strings).lower()
        assert "kitbuilder" in authors and "kit_support" in authors

        urls = {item.url for item in report.files}
        assert any(url.endswith("/assets/app.js") for url in urls)
        assert any(url.endswith("/assets/style.css") for url in urls)
        assert all(url.startswith(server.url) for url in urls)
        # A third-party CDN referenced by the page is recorded, never fetched.
        assert not any("tracker.js" in record["path"] for record in server.records)

        blob = json.dumps(report.as_dict())
        assert TELEGRAM_TOKEN not in blob
        for secret in RAW_SECRETS:
            assert secret not in blob

        relations = {pivot["relation"] for pivot in report.pivots}
        assert {"kit-exfil-email", "kit-telegram-exfil"} <= relations
        assert all(pivot["confidence"] <= 1.0 for pivot in report.pivots)


async def test_probe_exposure_and_credential_masks(tmp_path):
    with KitFixtureServer() as server:
        report = await run_analysis(server, tmp_path)

    by_path = {item.path: item for item in report.files}
    assert by_path["/logs/"].kind == "log"
    assert by_path["/results"].kind == "log"
    assert by_path["/config.php"].kind == "source"

    exposed = {item["path"]: item for item in report.exposed_paths}
    assert exposed["/admin"]["kind"] == "challenge"
    assert exposed["/admin"]["status_code"] == 403

    assert report.credential_exposure_count >= 5
    assert "email:password pairs" in report.credential_exposure_types
    assert report.credential_masks
    assert all("***@" in mask for mask in report.credential_masks)
    assert any("not recounted" in note for note in report.notes)

    blob = json.dumps(report.as_dict())
    for secret in RAW_SECRETS:
        assert secret not in blob


async def test_archive_is_inspected_in_memory(tmp_path):
    with KitFixtureServer() as server:
        report = await run_analysis(server, tmp_path, max_probes=0)

    members = {member["path"] for member in report.archive_members}
    assert {"index.html", "config.php", "readme.txt"} <= members
    assert not any("evil" in path for path in members)
    assert any("skipped unsafe archive member" in note for note in report.notes)
    assert ARCHIVE_EMAIL in {item["value"] for item in report.exfil_emails}
    assert report.file_tree_hash

    # Nothing from the archive (and no traversal target) was written to disk.
    written = {path.name for path in tmp_path.rglob("*") if path.is_file()}
    assert not ({"evil.php", "index.html", "readme.txt", "config.php"} & written)


async def test_archive_seed_url_is_inspected(tmp_path):
    with KitFixtureServer() as server:
        report = await run_analysis(server, tmp_path, path="/kit.zip", max_probes=0)
    assert report.status_code == 200
    assert report.kit_sha256
    assert {"config.php", "readme.txt"} <= {m["path"] for m in report.archive_members}


# --------------------------------------------------------------------------- #
# Redirect handling
# --------------------------------------------------------------------------- #


async def test_redirect_chain_is_recorded(tmp_path):
    with KitFixtureServer() as server:
        report = await run_analysis(server, tmp_path, path="/go", max_probes=0)
    assert report.status_code == 200
    assert report.final_url.endswith("/final")
    assert report.title == "Final lure"
    assert report.redirects
    assert report.redirects[0]["status"] == 302
    assert report.redirects[0]["to"].endswith("/final")


async def test_redirect_to_metadata_service_is_denied(tmp_path):
    config = kit_config(tmp_path)
    with KitFixtureServer() as server:
        fetcher = IsolatedFetcher(config)
        try:
            result = await fetcher.fetch(server.url + "/private-redirect")
        finally:
            await fetcher.close()
    assert result.content == b""
    assert result.error
    assert any(item["rule"] == "ssrf" for item in fetcher.denied)


# --------------------------------------------------------------------------- #
# SSRF / policy enforcement
# --------------------------------------------------------------------------- #


async def test_special_ranges_are_denied(tmp_path):
    config = make_config(
        tmp_path, fetcher=FetcherConfig(allow_localhost=False, active_fetch=True)
    )
    cases = {
        "http://127.0.0.1:8080/": "ssrf",
        "http://100.64.0.1/": "ssrf",
        "http://192.0.2.10/": "ssrf",
        "http://169.254.169.254/latest/meta-data/": "ssrf",
        "http://[::1]/": "ssrf",
        "gopher://127.0.0.1/": "scheme",
    }
    fetcher = IsolatedFetcher(config)
    try:
        for url, rule in cases.items():
            with pytest.raises(FetchDenied) as excinfo:
                await fetcher.validate(url)
            assert excinfo.value.rule == rule, url
    finally:
        await fetcher.close()


async def test_blocked_port_is_denied_before_connecting(tmp_path):
    fetcher = IsolatedFetcher(kit_config(tmp_path))
    try:
        with pytest.raises(FetchDenied) as excinfo:
            await fetcher.validate("http://127.0.0.1:22/")
    finally:
        await fetcher.close()
    assert excinfo.value.rule == "port"
    assert fetcher.denied == []


async def test_cookies_are_not_reused_between_requests(tmp_path):
    with KitFixtureServer() as server:
        report = await run_analysis(server, tmp_path, max_probes=0)
        assert report.status_code == 200  # the landing page sets a cookie
        record = server.record_for("/assets/app.js")
        assert record is not None
        assert record["cookie"] is None


# --------------------------------------------------------------------------- #
# Bounds and budgets
# --------------------------------------------------------------------------- #


async def test_byte_cap_truncates_landing_content(tmp_path):
    with KitFixtureServer() as server:
        report = await run_analysis(
            server, tmp_path, path="/big", max_probes=0, fetcher={"max_bytes": 2048}
        )
    assert report.status_code == 200
    assert report.truncated is True
    assert report.files[0].size == 2048
    assert any("truncated" in note for note in report.notes)


async def test_zero_probe_budget_skips_path_guessing(tmp_path):
    with KitFixtureServer() as server:
        report = await run_analysis(server, tmp_path, max_probes=0)
        paths = server.paths()
    assert "/logs/" not in paths
    assert "/results" not in paths
    assert "/admin" not in paths
    # The archive linked from the landing page is still inspected.
    assert report.archive_members


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


async def test_repository_persistence_and_evidence_dedupe(tmp_path):
    config = kit_config(tmp_path)
    _engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))

    with KitFixtureServer() as server:
        investigation = repo.create_investigation(
            seed=server.url,
            seed_type="url",
            seed_normalized=server.url,
            config_snapshot={},
            owner="test",
        )
        fetcher = fetcher_for(config, repo, investigation_id=investigation["id"])
        analyzer = KitAnalyzer(
            config,
            fetcher=fetcher,
            repo=repo,
            investigation_id=investigation["id"],
        )
        try:
            first = await analyzer.analyze(server.url + "/", force=True, persist=True)
            second = await analyzer.analyze(server.url + "/", force=True, persist=True)
        finally:
            await analyzer.close()

        assert first.kit_id and second.kit_id
        kits = repo.list_kits(investigation["id"])
        assert len(kits) == 2
        assert kits[0]["url"].rstrip("/") == server.url.rstrip("/")
        assert kits[0]["kit_sha256"] == first.kit_sha256
        assert kits[0]["exfil_emails"]

        evidence = repo.list_evidence(investigation["id"])
        assert evidence
        assert {row["provider"] for row in evidence} == {"kit"}
        # The same body can legitimately appear at several URLs (/logs, /logs/),
        # but no (URL, digest) pair may be stored twice across repeated runs.
        pairs = {(row["url"], row["sha256"]) for row in evidence}
        assert len(pairs) == len(evidence)


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_credential_signals_counts_and_masks():
    count, types, masks = credential_signals(LOG_TEXT + "\n" + RESULTS_CSV)
    assert count >= 5
    assert "email:password pairs" in types
    assert masks
    masked = " ".join(masks)
    for secret in RAW_SECRETS:
        assert secret not in masked


def test_secret_text_redaction():
    text = (
        f"bot {TELEGRAM_TOKEN} "
        "https://discord.com/api/webhooks/123456789/abcdefSECRET "
        "https://hooks.slack.com/services/T000/B000/XXXXXXXX"
    )
    redacted = redact_secret_text(text)
    assert TELEGRAM_TOKEN not in redacted
    assert "abcdefSECRET" not in redacted
    assert "T000/B000/XXXXXXXX" not in redacted
    assert TELEGRAM_BOT_ID in redacted


def test_safe_member_name_rules():
    assert safe_member_name("../../evil.php") is None
    assert safe_member_name("/etc/passwd") is None
    assert safe_member_name("C:\\windows\\system32\\evil.dll") is None
    assert safe_member_name("") is None
    assert safe_member_name("dir\\file.txt") == "dir/file.txt"
    assert safe_member_name("a/./b.txt") == "a/b.txt"


def test_inspect_zip_skips_oversized_and_unsafe_members():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("small.txt", "ok")
        archive.writestr("big.bin", b"x" * 2_100_000)
        archive.writestr("../escape.txt", "nope")
    members, warnings = inspect_zip(buffer.getvalue())
    assert [member["path"] for member in members] == ["small.txt"]
    assert any("oversized member" in warning for warning in warnings)
    assert any("unsafe archive member" in warning for warning in warnings)


def test_inspect_zip_handles_corrupt_archive():
    members, warnings = inspect_zip(b"not a zip at all")
    assert members == []
    assert warnings and "could not be opened" in warnings[0]


def test_simhash_is_stable_and_content_sensitive():
    first = b"<html><body>Microsoft 365 login</body></html>"
    second = b"<html><body>Microsoft 365 login</body></html>"
    different = b"<html><body>Netflix payment update</body></html>"
    assert simhash64(first) == simhash64(second)
    assert simhash64(first) != simhash64(different)
    assert simhash64(b"ab") == "0" * 16
    assert len(simhash64(first)) == 16


def test_kind_for_classification():
    assert kind_for("/index.html", "text/html", b"<html>") == "html"
    assert kind_for("/assets/app.js", "application/javascript", b"const x = 1") == "js"
    assert kind_for("/assets/style.css", "text/css", b"body{}") == "css"
    assert kind_for("/assets/logo.png", "image/png", PNG_BYTES) == "image"
    assert kind_for("/results", "text/csv", RESULTS_CSV.encode()) == "log"
    assert kind_for("/logs/", "text/plain", LOG_TEXT.encode()) == "log"
    assert kind_for("/config.php", "text/plain", b"<?php echo 1;") == "source"
    assert kind_for("/post.php", "application/x-httpd-php", b"<?php echo 1;") == "source"
    assert kind_for("/kit.zip", "application/zip", b"PK\x03\x04") == "archive"
    assert kind_for("/api", "application/json", b"{}") == "json"
    assert kind_for("/blob", "application/octet-stream", b"\x00\x01\x02") == "binary"
