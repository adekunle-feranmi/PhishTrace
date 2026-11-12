"""Keyed providers and wrapped CLI tools.

Every test here is offline: HTTP goes through ``httpx.MockTransport`` and the
CLI wrappers run against tiny stubs written into ``tmp_path``: a ``sh`` shim on
POSIX, a ``.cmd`` shim on Windows, both invoking the running interpreter.  The
suite therefore never contacts a vendor API and never needs an OSINT tool to be
installed, while still exercising the real argv building, process control,
parsing and evidence recording paths on either platform.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import pytest

from phishtrace.config import ProviderSettings
from phishtrace.core.registry import discover_providers
from phishtrace.providers.base import BaseProvider, ProviderMeta
from phishtrace.providers.keyed import (
    AbuseIPDBProvider, AlienVaultOTXProvider, CensysProvider, GreyNoiseProvider,
    HybridAnalysisProvider, MalwareBazaarProvider, SecurityTrailsProvider,
    ShodanProvider, VirusTotalProvider, WhoisXmlProvider,
)
from phishtrace.providers.tool_wrappers import (
    DnstwistProvider, GhuntProvider, HoleheProvider, MaigretProvider,
    PhoneInfogaProvider, SherlockProvider, SpiderfootProvider, TheHarvesterProvider,
)
from phishtrace.storage.evidence import redact_url
from phishtrace.tests.conftest import make_config
from phishtrace.tests.providers_harness import json_response, route, run_provider
from phishtrace.tools import ToolNotAvailable, ToolRunner, validate_target
from phishtrace.tools.runner import ToolTargetError

SEED_DOMAIN = "evil-login.example"
SEED_IP = "203.0.113.55"
SHA_A = "a" * 64
SHA_B = "b" * 64


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def stub(tmp_path: Path, name: str, body: str, *, data: str | None = None) -> Path:
    """Write an executable stub that runs ``body`` (Python source).

    A bare script is not executable on Windows, and ``/bin/sh`` may not exist
    there at all, so every stub is a two-line shim around the interpreter that
    is already running the tests: ``sh`` + ``exec`` on POSIX, ``.cmd`` on
    Windows.  ``data`` is materialised as ``<name>.dat`` beside the script so
    JSON and CSV payloads never have to survive shell quoting.
    """
    script = tmp_path / f"{name}_stub.py"
    script.write_text(body, encoding="utf-8")
    if data is not None:
        (tmp_path / f"{name}.dat").write_text(data, encoding="utf-8")
    if os.name == "nt":
        path = tmp_path / f"{name}.cmd"
        path.write_text(
            f'@echo off\r\n"{sys.executable}" "%~dp0{script.name}" %*\r\n',
            encoding="utf-8", newline="",
        )
        return path
    path = tmp_path / name
    path.write_text(
        f'#!/bin/sh\nexec "{sys.executable}" "$(dirname "$0")/{script.name}" "$@"\n',
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


_DAT_BODY = (
    "import pathlib, sys\n"
    "sys.stdout.write(pathlib.Path(__file__).with_name({dat!r}).read_text(encoding='utf-8'))\n"
    "sys.stdout.flush()\n"
)


def payload_tool(tmp_path: Path, name: str, text: str, *, body: str | None = None) -> Path:
    """Stub that echoes ``text`` to stdout, optionally through a custom body."""
    return stub(tmp_path, name, body or _DAT_BODY.format(dat=f"{name}.dat"), data=text)


def file_tool(tmp_path: Path, name: str, filename: str, text: str) -> Path:
    """Stub that writes ``text`` to ``filename`` inside its working directory."""
    body = (
        "import pathlib\n"
        "pathlib.Path({target!r}).write_text("
        "pathlib.Path(__file__).with_name({dat!r}).read_text(encoding='utf-8'), encoding='utf-8')\n"
    ).format(target=filename, dat=f"{name}.dat")
    return stub(tmp_path, name, body, data=text)


def note_text(run) -> str:
    return "\n".join(run.result.notes)


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #
VIRUSTOTAL_PAYLOAD = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 7, "suspicious": 2, "harmless": 60,
                                    "undetected": 5, "timeout": 1},
            "last_analysis_date": 1767225600,
            "reputation": -42,
            "tags": ["phishing", "credential-harvest"],
            "last_dns_records": [
                {"type": "A", "value": "203.0.113.66"},
                {"type": "NS", "value": "ns1.evil-login.example"},
                {"type": "CNAME", "value": "cdn.edge.example"},
                {"type": "TXT", "value": "v=spf1 -all"},
            ],
            "resolutions": [{"ip_address": "198.51.100.9", "date": 1700000000}],
            "asn": 64500,
            "as_owner": "Bulletproof Hosting LLC",
            "country": "NL",
            "subdomains": ["mail.evil-login.example", "not a domain"],
            "registrar": "Cheap Names BV",
            "creation_date": 1704067200,
        }
    }
}


async def test_virustotal_domain_emits_dns_asn_and_subdomains(tmp_path):
    run = await run_provider(
        tmp_path, VirusTotalProvider, SEED_DOMAIN,
        route({"virustotal.com/api/v3/domains/": VIRUSTOTAL_PAYLOAD}),
        env={"VIRUSTOTAL_API_KEY": "vt-test-key"},
    )
    assert run.values("ip") == {"203.0.113.66", "198.51.100.9"}
    assert "ns1.evil-login.example" in run.values("domain")
    assert "cdn.edge.example" in run.values("domain")
    assert "mail.evil-login.example" in run.values("domain")
    assert "not a domain" not in run.values("domain")
    assert run.values("asn") == {"AS64500"}

    event = next(e for e in run.result.events if e.kind == "reputation-check")
    assert event.meta["malicious"] == 7
    assert event.meta["suspicious"] == 2
    assert event.occurred_at is not None

    registrar = next(o for o in run.result.observations if o.relation == "registered-with")
    assert registrar.context_only is True
    assert registrar.meta["registrar"] == "Cheap Names BV"

    request = run.requests[0]
    assert request.headers["x-apikey"] == "vt-test-key"
    assert "vt-test-key" not in str(request.url)


async def test_virustotal_url_identifier_is_base64url(tmp_path):
    seed = "https://evil-login.example/login?user=victim"
    run = await run_provider(
        tmp_path, VirusTotalProvider, seed,
        route({"virustotal.com/api/v3/urls/": {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 0, "suspicious": 1},
            "last_analysis_date": 1767225600,
        }}}}),
        env={"VIRUSTOTAL_API_KEY": "vt-test-key"},
    )
    encoded = base64.urlsafe_b64encode(
        run.ctx.indicator.normalized.encode()).decode().rstrip("=")
    assert f"/api/v3/urls/{encoded}" in str(run.requests[0].url)
    assert run.result.partial is False


async def test_virustotal_without_key_is_skipped_locally(tmp_path):
    run = await run_provider(tmp_path, VirusTotalProvider, SEED_DOMAIN, route({}))
    assert run.requests == []
    assert run.result.partial is True
    assert "VIRUSTOTAL_API_KEY not configured" in note_text(run)


# --------------------------------------------------------------------------- #
# Shodan
# --------------------------------------------------------------------------- #
async def test_shodan_resolves_domain_then_reads_host(tmp_path):
    payload = {
        "ports": [80, 443, 8080],
        "asn": "AS64501",
        "org": "Fast VPS",
        "country_code": "DE",
        "hostnames": ["vpn.evil-login.example"],
        "domains": ["evil-login.example"],
        "last_update": "2026-02-01T10:00:00",
        "vulns": {"CVE-2021-44228": {}, "CVE-2020-0001": {}},
    }
    run = await run_provider(
        tmp_path, ShodanProvider, SEED_DOMAIN,
        route({"/dns/resolve": {SEED_DOMAIN: "203.0.113.66"},
               "/shodan/host/": payload}),
        env={"SHODAN_API_KEY": "shodan-test-key-123"},
    )
    assert "203.0.113.66" in run.values("ip")
    assert run.values("asn") == {"AS64501"}
    assert "vpn.evil-login.example" in run.values("domain")
    hosted = next(o for o in run.result.observations if o.relation == "hosted-domain")
    assert hosted.context_only is True

    event = next(e for e in run.result.events if e.kind == "service-exposure")
    assert event.meta["ports"] == [80, 443, 8080]
    assert event.meta["vulns"] == ["CVE-2020-0001", "CVE-2021-44228"]

    # The query-string key must never reach the evidence table verbatim.
    rows = run.repo.list_evidence(run.investigation_id)
    assert rows
    serialized = json.dumps(rows, default=str)
    assert "shodan-test-key-123" not in serialized
    assert any("[REDACTED]" in (row.get("url") or "") for row in rows)


async def test_shodan_failure_is_partial_not_fatal(tmp_path):
    run = await run_provider(
        tmp_path, ShodanProvider, SEED_IP,
        route({"/shodan/host/": json_response({"error": "rate limited"}, status=503)}),
        env={"SHODAN_API_KEY": "shodan-test-key-123"},
    )
    assert run.result.partial is True
    assert "shodan host lookup failed" in note_text(run)
    assert run.result.observations == []


# --------------------------------------------------------------------------- #
# Censys
# --------------------------------------------------------------------------- #
async def test_censys_bearer_token_and_certificate_names(tmp_path):
    payload = {
        "result": {
            "resource": {
                "ip": "203.0.113.77",
                "service_count": 2,
                "services": [
                    {"port": 443, "protocol": "HTTP", "scan_time": "2026-01-02T03:04:05Z",
                     "cert": {"names": ["*.evil-login.example", "mail.evil-login.example", "bad name"]}},
                    {"port": 22, "protocol": "SSH", "scan_time": "2026-01-02T03:04:05Z"},
                ],
                "autonomous_system": {"asn": 64502, "name": "Example Hosting", "country_code": "US"},
                "location": {"country_code": "US"},
                "labels": ["cdn"],
            }
        }
    }
    run = await run_provider(
        tmp_path, CensysProvider, "203.0.113.77",
        route({"api.platform.censys.io/v3/global/asset/host/": payload}),
        env={"CENSYS_API_TOKEN": "censys_pat_test"},
    )
    assert run.values("domain") == {"evil-login.example", "mail.evil-login.example"}
    assert run.values("asn") == {"AS64502"}
    event = next(e for e in run.result.events if e.kind == "service-exposure")
    assert event.meta["ports"] == [443, 22]

    request = run.requests[0]
    assert request.method == "GET"
    assert request.headers["authorization"] == "Bearer censys_pat_test"


async def test_censys_malformed_result_is_partial(tmp_path):
    run = await run_provider(
        tmp_path, CensysProvider, "203.0.113.77",
        route({"api.platform.censys.io": {"result": {"resource": {}}}}),
        env={"CENSYS_API_TOKEN": "censys_pat_test"},
    )
    assert run.result.partial is True
    assert "no host resource" in note_text(run)


# --------------------------------------------------------------------------- #
# SecurityTrails
# --------------------------------------------------------------------------- #
async def test_securitytrails_current_dns_and_subdomains(tmp_path):
    payload = {
        "current_dns": {
            "a": {"values": [{"ip": "203.0.113.70"}]},
            "mx": {"values": [{"hostname": "mx.evil-login.example"}]},
            "ns": {"values": [{"nameserver": "ns1.other.example"}]},
        },
        "subdomains": ["www", "api", "deep.label", ""],
        "whois": {"registrar": "Cheap Names BV", "createdDate": "2025-05-05"},
    }
    run = await run_provider(
        tmp_path, SecurityTrailsProvider, SEED_DOMAIN,
        route({"api.securitytrails.com/v1/domain/": payload}),
        env={"SECURITYTRAILS_API_KEY": "st-test-key"},
    )
    assert run.values("ip") == {"203.0.113.70"}
    assert "mx.evil-login.example" in run.values("domain")
    assert run.values("nameserver") == {"ns1.other.example"}
    assert "www.evil-login.example" in run.values("domain")
    assert "deep.label.evil-login.example" not in run.values("domain")
    registrar = next(o for o in run.result.observations if o.relation == "registered-with")
    assert registrar.meta["registrar"] == "Cheap Names BV"
    assert registrar.context_only is True


# --------------------------------------------------------------------------- #
# AlienVault OTX
# --------------------------------------------------------------------------- #
async def test_otx_pulses_passive_dns_and_urls(tmp_path):
    payload = {
        "pulse_info": {"pulses": [
            {"id": "p1", "name": "Credential phishing wave", "created": "2026-01-05T00:00:00",
             "tags": ["phishing", "office365"], "malware_families": ["Emotet"],
             "adversary": "Unknown"},
            {"id": "p2", "name": "Second pulse", "modified": "2026-02-05T00:00:00",
             "tags": ["credential-harvest"]},
        ]},
        "passive_dns": [
            {"address": "203.0.113.90", "hostname": "login.evil-login.example",
             "first": "2025-12-01T00:00:00"},
        ],
        "url_list": [{"url": f"https://{SEED_DOMAIN}/login", "date": "2025-12-02T00:00:00"}],
    }
    run = await run_provider(
        tmp_path, AlienVaultOTXProvider, SEED_DOMAIN,
        route({"otx.alienvault.com/api/v1/indicators/domain/": payload}),
        env={"OTX_API_KEY": "otx-test-key"},
    )
    kinds = [event.kind for event in run.result.events]
    assert kinds.count("ti-pulse") == 2
    coverage = next(e for e in run.result.events if e.kind == "ti-coverage")
    assert coverage.meta["pulses"] == 2
    assert "phishing" in coverage.meta["tags"]
    assert coverage.meta["malware_families"] == ["Emotet"]

    assert "203.0.113.90" in run.values("ip")
    assert "login.evil-login.example" in run.values("domain")
    assert f"https://{SEED_DOMAIN}/login" in run.values("url")


# --------------------------------------------------------------------------- #
# AbuseIPDB
# --------------------------------------------------------------------------- #
async def test_abuseipdb_confidence_reports_and_hostnames(tmp_path):
    payload = {"data": {
        "abuseConfidenceScore": 87, "totalReports": 12,
        "lastReportedAt": "2026-03-01T12:00:00+00:00",
        "isp": "Fast VPS", "usageType": "Data Center/Web Hosting/Transit",
        "countryCode": "DE", "domain": "evil-host.example",
        "hostnames": ["mail.evil-host.example"],
    }}
    run = await run_provider(
        tmp_path, AbuseIPDBProvider, "203.0.113.88",
        route({"api.abuseipdb.com/api/v2/check": payload}),
        env={"ABUSEIPDB_API_KEY": "abuse-test-key"},
    )
    event = next(e for e in run.result.events if e.kind == "reputation-check")
    assert event.meta["abuse_confidence"] == 87
    assert event.meta["reports"] == 12

    hosted = next(o for o in run.result.observations if o.value == "evil-host.example")
    assert hosted.context_only is True
    hostname = next(o for o in run.result.observations if o.value == "mail.evil-host.example")
    assert hostname.context_only is False


# --------------------------------------------------------------------------- #
# GreyNoise
# --------------------------------------------------------------------------- #
async def test_greynoise_riot_marks_shared_service_as_context(tmp_path):
    payload = {"ip": "203.0.113.99", "noise": False, "riot": True, "classification": "benign",
               "name": "Cloudflare", "link": "https://viz.greynoise.io/ip/203.0.113.99",
               "last_seen": "2026-04-01"}
    run = await run_provider(
        tmp_path, GreyNoiseProvider, "203.0.113.99",
        route({"api.greynoise.io/v3/community/": payload}),
        env={"GREYNOISE_API_KEY": "gn-test-key"},
    )
    observation = next(o for o in run.result.observations if o.relation == "known-benign-service")
    assert observation.context_only is True
    assert observation.meta["service"] == "Cloudflare"
    assert "riot" in observation.tags
    event = next(e for e in run.result.events if e.kind == "reputation-check")
    assert event.meta["classification"] == "benign"


# --------------------------------------------------------------------------- #
# Hybrid Analysis
# --------------------------------------------------------------------------- #
async def test_hybrid_analysis_hash_search_picks_highest_threat_score(tmp_path):
    payload = [
        {"sha256": SHA_A, "threat_score": 100, "verdict": "malicious",
         "vx_family": "Emotet", "analysis_start_time": "2026-01-01T00:00:00",
         "type": "PE32 executable"},
        {"sha256": SHA_B, "threat_score": 20, "verdict": "suspicious",
         "analysis_start_time": "2026-01-02T00:00:00"},
    ]
    run = await run_provider(
        tmp_path, HybridAnalysisProvider, SHA_A,
        route({"hybrid-analysis.com/api/v2/search/hash": {"sha256s": [SHA_A], "reports": payload}}),
        env={"HYBRID_ANALYSIS_API_KEY": "ha-test-key"},
    )
    assert {SHA_A, SHA_B} <= run.values("file_hash")
    event = next(e for e in run.result.events if e.kind == "sandbox-report")
    assert event.meta["threat_score"] == 100
    assert event.meta["family"] == "Emotet"

    request = run.requests[0]
    assert request.method == "GET"
    assert SHA_A in str(request.url)
    assert request.headers["api-key"] == "ha-test-key"


async def test_hybrid_analysis_empty_result_is_partial(tmp_path):
    run = await run_provider(
        tmp_path, HybridAnalysisProvider, SHA_A,
        route({"hybrid-analysis.com": {"sha256s": [], "reports": []}}),
        env={"HYBRID_ANALYSIS_API_KEY": "ha-test-key"},
    )
    assert run.result.partial is True
    assert "no reports" in note_text(run)


async def test_greynoise_404_is_no_record_not_failure(tmp_path):
    run = await run_provider(
        tmp_path, GreyNoiseProvider, SEED_IP,
        route({"api.greynoise.io": json_response(
            {"ip": SEED_IP, "noise": False, "message": "IP not observed"}, 404)}),
        env={"GREYNOISE_API_KEY": "gn-test-key"},
    )
    assert run.result.partial is False
    assert "no observation record" in note_text(run)


async def test_hybrid_analysis_404_is_no_reports_not_failure(tmp_path):
    run = await run_provider(
        tmp_path, HybridAnalysisProvider, SHA_A,
        route({"hybrid-analysis.com": json_response({"message": "Not Found"}, 404)}),
        env={"HYBRID_ANALYSIS_API_KEY": "ha-test-key"},
    )
    assert run.result.partial is False
    assert "no reports" in note_text(run)


# --------------------------------------------------------------------------- #
# MalwareBazaar
# --------------------------------------------------------------------------- #
async def test_malwarebazaar_sample_metadata_and_tag_domains(tmp_path):
    payload = {"query_status": "ok", "data": [{
        "sha256_hash": SHA_A, "signature": "Emotet", "file_name": "invoice.doc",
        "file_type_mime": "application/msword", "reporter": "anonymous",
        "delivery_method": "web download", "imphash": "deadbeef",
        "first_seen": "2026-02-02 03:04:05",
        "tags": ["emotet", "evil-drop.example", "maldoc"],
    }]}
    run = await run_provider(
        tmp_path, MalwareBazaarProvider, SHA_A,
        route({"mb-api.abuse.ch/api/v1/": payload}),
    )
    event = next(e for e in run.result.events if e.kind == "malware-sample")
    assert event.meta["file_name"] == "invoice.doc"
    assert event.meta["imphash"] == "deadbeef"

    dropped = next(o for o in run.result.observations if o.value == "evil-drop.example")
    assert dropped.context_only is True
    assert "evil-drop.example" not in {o.value for o in run.result.observations
                                      if o.type == "domain" and not o.context_only}

    request = run.requests[0]
    assert b"get_info" in request.content
    assert "Auth-Key" not in request.headers


async def test_malwarebazaar_unknown_hash_is_partial(tmp_path):
    run = await run_provider(
        tmp_path, MalwareBazaarProvider, SHA_A,
        route({"mb-api.abuse.ch": {"query_status": "hash_not_found", "data": []}}),
    )
    assert run.result.partial is True
    assert "no record" in note_text(run)


# --------------------------------------------------------------------------- #
# WhoisXML
# --------------------------------------------------------------------------- #
async def test_whoisxml_registrar_nameservers_and_contact(tmp_path):
    payload = {"WhoisRecord": {
        "createdDate": "2025-11-11T00:00:00Z",
        "expiresDate": "2026-11-11T00:00:00Z",
        "registrarName": "Cheap Names BV",
        "estimatedDomainAge": 365,
        "contactEmail": "abuse@privacy.example",
        "registrant": {"country": "NL", "organization": "Privacy Guard"},
        "nameServers": {"hostNames": ["ns1.evil-login.example", "ns2.evil-login.example"]},
    }}
    run = await run_provider(
        tmp_path, WhoisXmlProvider, SEED_DOMAIN,
        route({"whoisxmlapi.com/whoisserver/WhoisService": payload}),
        env={"WHOISXML_API_KEY": "whois-test-key"},
    )
    assert run.values("nameserver") == {"ns1.evil-login.example", "ns2.evil-login.example"}
    event = next(e for e in run.result.events if e.kind == "domain-registered")
    assert event.meta["registrar"] == "Cheap Names BV"
    assert event.meta["registrant_country"] == "NL"

    contact = next(o for o in run.result.observations if o.type == "email")
    assert contact.value == "abuse@privacy.example"
    assert contact.context_only is True

    # apiKey travels in the query string for this vendor: the stored URL must be scrubbed.
    rows = run.repo.list_evidence(run.investigation_id)
    serialized = json.dumps(rows, default=str)
    assert "whois-test-key" not in serialized
    assert any("apiKey=[REDACTED]" in (row.get("url") or "") for row in rows)


# --------------------------------------------------------------------------- #
# Shared keyed behaviour
# --------------------------------------------------------------------------- #
async def test_keyed_providers_report_missing_keys_without_requests(tmp_path):
    cases = [
        (VirusTotalProvider, SEED_DOMAIN),
        (ShodanProvider, SEED_IP),
        (CensysProvider, SEED_IP),
        (SecurityTrailsProvider, SEED_DOMAIN),
        (AlienVaultOTXProvider, SEED_DOMAIN),
        (AbuseIPDBProvider, SEED_IP),
        (GreyNoiseProvider, SEED_IP),
        (HybridAnalysisProvider, SHA_A),
        (WhoisXmlProvider, SEED_DOMAIN),
    ]
    for provider_cls, seed in cases:
        run = await run_provider(tmp_path, provider_cls, seed, route({}))
        assert run.result.partial is True, provider_cls.meta.name
        assert run.result.observations == [], provider_cls.meta.name
        assert run.requests == [], provider_cls.meta.name


def test_redact_url_scrubs_only_secret_values():
    assert (redact_url("https://api.example/v1?key=abc&ip=1.2.3.4")
            == "https://api.example/v1?key=[REDACTED]&ip=1.2.3.4")
    assert (redact_url("https://api.example/v1?apiKey=abc&domainName=x.example")
            == "https://api.example/v1?apiKey=[REDACTED]&domainName=x.example")
    assert redact_url("https://api.example/v1") == "https://api.example/v1"
    assert redact_url(None) is None


# --------------------------------------------------------------------------- #
# Registry wiring
# --------------------------------------------------------------------------- #
def test_registry_exposes_phase_b_and_c_providers():
    errors: list = []
    classes = discover_providers(errors)
    assert errors == []
    by_name = {cls.meta.name: cls for cls in classes}

    phase_b = {"abuseipdb", "alienvault_otx", "censys", "greynoise", "hybrid_analysis",
               "malwarebazaar", "securitytrails", "shodan", "virustotal", "whoisxml"}
    phase_c = {"dnstwist", "ghunt", "holehe", "maigret", "phoneinfoga", "sherlock",
               "spiderfoot", "theharvester"}
    assert {name for name, cls in by_name.items() if cls.meta.phase == "B"} == phase_b
    assert {name for name, cls in by_name.items() if cls.meta.phase == "C"} == phase_c
    assert by_name["censys"].meta.api_keys == ("CENSYS_API_TOKEN",)


def test_tool_provider_availability_gates(tmp_path):
    stub_path = stub(tmp_path, "holehe", "exit 0\n")
    base = make_config(tmp_path)

    gated = HoleheProvider(ProviderSettings(enabled=True, options={"path": str(stub_path)}))
    ok, reason = gated.can_run(base)
    assert ok is False
    assert "legal acknowledgement" in (reason or "")

    acknowledged = HoleheProvider(ProviderSettings(
        enabled=True, options={"path": str(stub_path), "legal_acknowledged": True}))
    assert acknowledged.can_run(base) == (True, None)

    disabled = HoleheProvider(ProviderSettings(enabled=False))
    assert disabled.can_run(base)[1] == "disabled in config.yaml"


class _MissingToolProvider(BaseProvider):
    meta = ProviderMeta(name="missing-tool", accepts=("domain",),
                        requires_tool="phishtrace-no-such-tool")

    async def run(self, ctx):  # pragma: no cover - never executed
        return ctx.result


def test_missing_binary_is_reported_not_crashed(tmp_path):
    provider = _MissingToolProvider(ProviderSettings(enabled=True))
    ok, reason = provider.can_run(make_config(tmp_path))
    assert ok is False
    assert "not installed" in (reason or "")


# --------------------------------------------------------------------------- #
# ToolRunner
# --------------------------------------------------------------------------- #
async def test_runner_executes_json_tool_and_parses_stdout(tmp_path):
    path = payload_tool(tmp_path, "json-tool", json.dumps({"ok": True, "n": 3}))
    result = await ToolRunner("json-tool", path=str(path)).run([])
    assert result.ok is True
    assert result.exit_code == 0
    assert result.json_stdout() == {"ok": True, "n": 3}
    assert Path(result.command[0]).stem == "json-tool"


async def test_runner_collects_named_and_json_reports(tmp_path):
    path = stub(
        tmp_path, "writer",
        "import json, pathlib\n"
        "pathlib.Path('harvest.json').write_text("
        "json.dumps({'emails': ['a@evil-login.example']}), encoding='utf-8')\n"
        "pathlib.Path('report_user.json').write_text("
        "json.dumps({'GitHub': {'status': {'status': 'Claimed'}}}), encoding='utf-8')\n"
        "pathlib.Path('notes.txt').write_text('ignored', encoding='utf-8')\n",
    )
    result = await ToolRunner("writer", path=str(path)).run(
        [], collect=("harvest.json",), collect_json=True)
    assert result.ok is True
    assert set(result.files) == {"harvest.json", "report_user.json"}
    assert json.loads(result.files["harvest.json"])["emails"] == ["a@evil-login.example"]
    assert result.workdir is not None
    assert not Path(result.workdir).exists(), "scratch directory must be removed"


async def test_runner_times_out_and_kills_process_group(tmp_path):
    path = stub(tmp_path, "sleeper", "import time\ntime.sleep(30)\n")
    result = await ToolRunner("sleeper", path=str(path)).run([], timeout=1)
    assert result.ok is False
    assert result.timed_out is True
    assert "timed out" in (result.reason or "")
    assert result.duration_ms < 15_000


async def test_runner_caps_output(tmp_path):
    path = stub(tmp_path, "flood", "import sys\nsys.stdout.write('A' * 200000)\nsys.stdout.flush()\n")
    result = await ToolRunner("flood", path=str(path), max_output=4096).run([])
    assert result.truncated is True
    assert len(result.stdout.encode()) <= 4096
    assert "exceeded" in (result.reason or "")


async def test_runner_sanitizes_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHTRACE_TEST_SECRET", "leak-me")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.example:8080")
    path = stub(
        tmp_path, "envdump",
        "import os, pathlib\n"
        "dump = ''.join(f'{k}={v}\\n' for k, v in sorted(os.environ.items()))\n"
        "pathlib.Path('env.txt').write_text(dump, encoding='utf-8')\n",
    )
    result = await ToolRunner("envdump", path=str(path)).run([], collect=("env.txt",))
    env_text = result.files["env.txt"].decode()
    assert "leak-me" not in env_text
    assert "PHISHTRACE_TEST_SECRET" not in env_text
    assert "HTTPS_PROXY" not in env_text
    assert "HOME=" in env_text
    assert "PATH=" in env_text


async def test_runner_reports_exit_code_and_stderr_tail(tmp_path):
    path = stub(
        tmp_path, "failer",
        "import sys\nsys.stderr.write('auth failed badly\\n')\nsys.exit(3)\n",
    )
    result = await ToolRunner("failer", path=str(path)).run([])
    assert result.ok is False
    assert result.exit_code == 3
    assert "exit code 3" in (result.reason or "")
    assert "auth failed badly" in (result.reason or "")


def test_missing_binary_raises_tool_not_available():
    with pytest.raises(ToolNotAvailable):
        ToolRunner("phishtrace-definitely-not-installed")


def test_validate_target_rejects_argv_injection():
    assert validate_target("evil-login.example") == "evil-login.example"
    for bad in ["-d/etc/passwd", "--json", "evil example", "evil\nlogin", "münchen.example",
                "x" * 513, ""]:
        with pytest.raises(ToolTargetError):
            validate_target(bad)


# --------------------------------------------------------------------------- #
# Tool wrappers (stubbed binaries, no network)
# --------------------------------------------------------------------------- #
async def test_dnstwist_emits_registered_lookalikes_only(tmp_path):
    payload = [
        {"domain": "evil-login.co", "fuzzer": "tld-swap",
         "dns_a": ["203.0.113.80"], "dns_mx": ["mx.evil-login.co"],
         "dns_ns": ["ns1.evil-login.co"]},
        {"domain": "evil-login.example", "fuzzer": "addition", "dns_a": ["203.0.113.81"]},
        {"domain": "evil-login.net", "fuzzer": "tld-swap", "dns_a": []},
    ]
    script = payload_tool(
        tmp_path, "dnstwist", json.dumps(payload),
        body=(
            "import pathlib, sys\n"
            "if sys.argv[1:3] != ['--format', 'json']:\n"
            "    sys.exit(9)\n"
            "sys.stdout.write("
            "pathlib.Path(__file__).with_name('dnstwist.dat').read_text(encoding='utf-8'))\n"
        ),
    )
    run = await run_provider(
        tmp_path, DnstwistProvider, SEED_DOMAIN, route({}),
        options={"path": str(script)},
    )
    assert run.requests == []
    lookalike = next(o for o in run.result.observations if o.value == "evil-login.co")
    assert lookalike.relation == "lookalike-domain"
    assert lookalike.context_only is True
    assert lookalike.meta["dns_a"] == ["203.0.113.80"]
    assert "203.0.113.80" in run.values("ip")
    values = run.values("domain")
    assert "evil-login.example" not in values
    assert "evil-login.net" not in values

    rows = run.repo.list_evidence(run.investigation_id)
    tool_rows = [row for row in rows if row["provider"] == "dnstwist"]
    assert tool_rows, "tool output must be preserved as evidence"
    assert tool_rows[0]["url"] == "tool://dnstwist"


async def test_sherlock_maps_claimed_profiles(tmp_path):
    payload = {
        "GitHub": {"url_user": "https://github.com/eviluser",
                   "status": {"status": "Claimed"}},
        "Reddit": {"url_user": "https://www.reddit.com/user/eviluser",
                   "status": "Claimed"},
        "Empty": {"url_user": "https://empty.example/eviluser",
                  "status": {"status": "Available"}},
    }
    script = payload_tool(tmp_path, "sherlock", json.dumps(payload))
    run = await run_provider(
        tmp_path, SherlockProvider, "eviluser", route({}),
        options={"path": str(script)}, seed_type="username",
    )
    urls = run.values("url")
    assert urls == {"https://github.com/eviluser", "https://www.reddit.com/user/eviluser"}
    assert all(o.context_only for o in run.result.observations)
    assert any(o.meta.get("platform") == "GitHub" for o in run.result.observations)
    event = next(e for e in run.result.events if e.kind == "username-enumeration")
    assert "2 public profile" in event.label


async def test_maigret_reads_ndjson(tmp_path):
    rows = [
        {"sitename": "GitHub", "url_user": "https://github.com/eviluser",
         "status": {"status": "Claimed"}},
        {"sitename": "Empty", "url_user": "https://empty.example/eviluser",
         "status": {"status": "Available"}},
    ]
    body = "".join(json.dumps(row) + "\n" for row in rows)
    script = payload_tool(tmp_path, "maigret", body)
    run = await run_provider(
        tmp_path, MaigretProvider, "eviluser", route({}),
        options={"path": str(script)}, seed_type="username",
    )
    assert run.values("url") == {"https://github.com/eviluser"}


async def test_holehe_lists_registered_services(tmp_path):
    script = payload_tool(
        tmp_path, "holehe",
        "[+] github.com\n[+] twitter.com\n[-] instagram.com\n",
    )
    run = await run_provider(
        tmp_path, HoleheProvider, "analyst@evil-login.example", route({}),
        options={"path": str(script), "legal_acknowledged": True},
    )
    observation = run.result.observations[0]
    assert observation.type == "email"
    assert observation.meta["services"] == ["github.com", "twitter.com"]
    assert observation.context_only is True
    event = next(e for e in run.result.events if e.kind == "email-registration")
    assert "2 service" in event.label


async def test_theharvester_filters_out_of_scope_results(tmp_path):
    payload = {
        "emails": ["analyst@evil-login.example", "stranger@elsewhere.example"],
        "hosts": ["vpn.evil-login.example", "outside.example"],
        "ips": ["203.0.113.90"],
        "urls": [f"https://{SEED_DOMAIN}/owa/"],
    }
    script = file_tool(tmp_path, "theharvester", "harvest.json", json.dumps(payload))
    run = await run_provider(
        tmp_path, TheHarvesterProvider, SEED_DOMAIN, route({}),
        options={"path": str(script)},
    )
    assert run.values("email") == {"analyst@evil-login.example"}
    assert run.values("domain") == {"vpn.evil-login.example"}
    assert run.values("ip") == {"203.0.113.90"}
    assert run.values("url") == {f"https://{SEED_DOMAIN}/owa/"}


async def test_spiderfoot_maps_csv_findings(tmp_path):
    csv_body = (
        '"Type","Data","Source"\n'
        '"Internet Name","mail.evil-login.example","sfp_dns"\n'
        '"IP Address","203.0.113.100","sfp_dns"\n'
        '"Phone Number","+15550100","sfp_phone"\n'
        '"Bitcoin Address","1BoatSLRHtKNngkdXEeobR76b53LETtpyT","sfp_btc"\n'
        '"Something Else","ignored","sfp_x"\n'
    )
    script = payload_tool(tmp_path, "spiderfoot", csv_body)
    run = await run_provider(
        tmp_path, SpiderfootProvider, SEED_DOMAIN, route({}),
        options={"path": str(script)},
    )
    assert "mail.evil-login.example" in run.values("domain")
    assert "203.0.113.100" in run.values("ip")
    phone = next(o for o in run.result.observations if o.type == "phone")
    assert phone.context_only is True
    bitcoin = next(o for o in run.result.observations if o.type == "btc_address")
    assert bitcoin.context_only is True


async def test_phoneinfoga_extracts_carrier_metadata(tmp_path):
    script = payload_tool(
        tmp_path, "phoneinfoga",
        "Carrier: Example Telecom\nCountry: US\nLine type: mobile\n",
    )
    run = await run_provider(
        tmp_path, PhoneInfogaProvider, "+15550100", route({}),
        options={"path": str(script)},
    )
    observation = run.result.observations[0]
    assert observation.type == "phone"
    assert observation.context_only is True
    assert observation.meta["carrier"] == "Example Telecom"
    assert observation.meta["country"] == "US"
    assert observation.meta["line_type"] == "mobile"


async def test_ghunt_keeps_existence_but_drops_profile_fields(tmp_path):
    payload = {"services": {"youtube": {}, "photos": {}}, "profile": {"name": "Alice Example"}}
    script = file_tool(tmp_path, "ghunt", "ghunt.json", json.dumps(payload))
    cookies = tmp_path / "cookies.txt"
    cookies.write_text("# Netscape HTTP Cookie File\n", encoding="utf-8")
    run = await run_provider(
        tmp_path, GhuntProvider, "analyst@evil-login.example", route({}),
        options={"path": str(script), "cookies": str(cookies), "legal_acknowledged": True},
    )
    observation = run.result.observations[0]
    assert observation.meta["services"] == ["photos", "youtube"]
    assert observation.meta["service_count"] == 2
    assert "profile" not in json.dumps(observation.meta)
    assert "Alice" not in json.dumps([o.model_dump() for o in run.result.observations],
                                    default=str)


async def test_wrapper_without_binary_reports_partial(tmp_path):
    provider = DnstwistProvider(ProviderSettings(enabled=True, options={"path": "/nonexistent/dnstwist"}))
    ok, reason = provider.can_run(make_config(tmp_path))
    assert ok is False
    assert "dnstwist" in (reason or "")
