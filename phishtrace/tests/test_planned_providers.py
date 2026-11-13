"""Tests for the formerly planned providers (search, commercial feeds, breach).

Offline only: HTTP goes through ``httpx.MockTransport``; breach providers are
additionally exercised behind their legal gate.  No test contacts a vendor.
"""

from __future__ import annotations

import base64

import pytest

from phishtrace.config import ProviderSettings
from phishtrace.core.registry import Registry
from phishtrace.providers.breach import DeHashedProvider, IntelXProvider
from phishtrace.providers.commercial import (
    CriminalIpProvider, DomainToolsProvider, GreyNoiseRiotProvider,
    NetlasProvider, SilentPushProvider, ValidinProvider,
)
from phishtrace.providers.search import (
    BraveSearchProvider, GoogleCseProvider, SerpApiProvider, XSearchProvider,
    YouTubeProvider,
)
from phishtrace.tests.conftest import make_config
from phishtrace.tests.providers_harness import json_response, route, run_provider, run_sightings

SEED_URL = "https://evil.example/login"
PLANNED = {
    "youtube", "x_search", "serpapi", "brave_search", "google_cse",
    "domaintools", "validin", "silentpush", "netlas", "criminalip",
    "greynoise_ri", "dehashed", "intelx",
}


# --------------------------------------------------------------------------- #
# Registry coverage
# --------------------------------------------------------------------------- #
def test_all_planned_providers_discoverable(tmp_config):
    registry = Registry(tmp_config)
    names = {status.name for status in registry.statuses()}
    assert PLANNED <= names
    assert not registry.load_errors


def test_keyed_planned_providers_skip_without_keys(tmp_config):
    statuses = {status.name: status for status in Registry(tmp_config).statuses()}
    for name in ("serpapi", "brave_search", "youtube", "x_search", "domaintools",
                 "validin", "silentpush", "netlas", "criminalip", "dehashed", "intelx"):
        assert statuses[name].status == "skipped", f"{name} unexpectedly runnable without a key"
    # greynoise_ri also needs GREYNOISE_API_KEY (shared with the greynoise provider)
    assert statuses["greynoise_ri"].status == "skipped"
    assert "GREYNOISE_API_KEY" in statuses["greynoise_ri"].reason


def test_breach_providers_blocked_by_legal_gate(tmp_path):
    config = make_config(tmp_path / "legalgate", env={
        "DEHASHED_API_KEY": "k", "DEHASHED_EMAIL": "analyst@example.com",
        "INTELX_API_KEY": "00000000-0000-0000-0000-000000000000",
    })
    registry = Registry(config)
    for name in ("dehashed", "intelx"):
        status = registry.status(name)
        assert status.status == "skipped"
        assert "legal acknowledgement" in (status.reason or "")


def test_domaintools_requires_username_pair(tmp_path):
    config = make_config(tmp_path / "dt", env={"DOMAINTOOLS_API_KEY": "k"})
    provider = DomainToolsProvider(ProviderSettings(enabled=True))
    missing = provider.missing_keys(config)
    assert "DOMAINTOOLS_API_KEY" not in missing
    assert "DOMAINTOOLS_USERNAME" in missing
    provider2 = DomainToolsProvider(ProviderSettings(enabled=True, options={"username": "acct"}))
    assert provider2.missing_keys(config) == []


# --------------------------------------------------------------------------- #
# Search providers
# --------------------------------------------------------------------------- #
async def test_serpapi_records_sightings(tmp_path):
    payload = {"organic_results": [
        {"position": 1, "title": "evil.example scam reports", "link": "https://blog.example.org/evil",
         "snippet": "evil.example used in a phishing wave", "date": "1 day ago"},
        {"position": 2, "title": "cooking recipes", "link": "https://recipes.net/x",
         "snippet": "nothing to do with the seed"},
    ]}
    run = await run_sightings(tmp_path, SerpApiProvider, "evil.example",
                              route({"serpapi.com": payload}), env={"SERPAPI_KEY": "skey"})
    assert len(run.result.sightings) == 1
    sighting = run.result.sightings[0]
    assert sighting.platform == "google"
    assert sighting.post_url == "https://blog.example.org/evil"
    assert sighting.evidence_id
    # the API key travels in the query string and must never be recorded verbatim
    from phishtrace.storage.evidence import redact_url
    assert "api_key=skey" in str(run.requests[0].url)
    assert "skey" not in (redact_url(str(run.requests[0].url)) or "")
    assert run.values("url") == {"https://blog.example.org/evil"}


async def test_brave_search_records_sightings(tmp_path):
    payload = {"web": {"results": [
        {"title": "evil.example", "url": "https://blog.example.org/brave",
         "description": "about evil.example", "age": "2 days ago"},
    ]}}
    run = await run_sightings(tmp_path, BraveSearchProvider, "evil.example",
                              route({"api.search.brave.com": payload}), env={"BRAVE_API_KEY": "bkey"})
    assert len(run.result.sightings) == 1
    assert run.result.sightings[0].platform == "brave"
    headers = run.requests[0].headers
    assert headers.get("x-subscription-token") == "bkey"


async def test_google_cse_needs_key_and_cx(tmp_path):
    payload = {"items": [
        {"title": "evil.example", "link": "https://blog.example.org/cse",
         "snippet": "about evil.example", "displayLink": "blog.example.org"},
    ]}
    run = await run_sightings(tmp_path, GoogleCseProvider, SEED_URL, route({}),
                              env={"GOOGLE_CSE_API_KEY": "k"})
    assert run.result.sightings == []
    assert any("GOOGLE_CSE_CX" in note for note in run.result.notes)
    run = await run_sightings(
        tmp_path, GoogleCseProvider, "evil.example", route({"customsearch": payload}),
        env={"GOOGLE_CSE_API_KEY": "k", "GOOGLE_CSE_CX": "cx123"})
    assert len(run.result.sightings) == 1
    params = run.requests[0].url.params
    assert params.get("cx") == "cx123" and params.get("key") == "k"


async def test_youtube_records_video_and_channel(tmp_path):
    payload = {"items": [
        {"id": {"videoId": "abc123"},
         "snippet": {"title": "evil.example phishing exposed", "description": "about evil.example",
                     "publishedAt": "2025-03-04T10:00:00Z", "channelTitle": "Fraud Watch", "channelId": "UCx"}},
        {"id": {"channelId": "UCx"},
         "snippet": {"title": "evil.example updates", "channelTitle": "Fraud Watch", "channelId": "UCx"}},
    ]}
    run = await run_sightings(tmp_path, YouTubeProvider, "evil.example",
                              route({"googleapis.com/youtube": payload}), env={"YOUTUBE_API_KEY": "ykey"})
    assert len(run.result.sightings) == 2
    assert run.result.sightings[0].post_url == "https://www.youtube.com/watch?v=abc123"
    assert run.result.sightings[0].author_handle == "Fraud Watch"
    assert run.values("username") == {"youtube.com/channel/UCx"}


async def test_x_search_records_tweets(tmp_path):
    payload = {
        "data": [{"id": "1", "text": "phishing kit at evil.example", "author_id": "42",
                  "created_at": "2025-03-04T10:00:00Z"}],
        "includes": {"users": [{"id": "42", "username": "scamhunter", "name": "S",
                                "created_at": "2020-01-01T00:00:00Z"}]},
    }
    run = await run_sightings(tmp_path, XSearchProvider, "evil.example",
                              route({"api.twitter.com": payload}), env={"X_BEARER_TOKEN": "tok"})
    assert len(run.result.sightings) == 1
    sighting = run.result.sightings[0]
    assert sighting.post_url == "https://x.com/scamhunter/status/1"
    assert sighting.author_handle == "scamhunter"
    assert sighting.author_created_at and sighting.author_created_at.year == 2020
    assert run.requests[0].headers.get("authorization") == "Bearer tok"


async def test_x_search_reports_tier_rejection(tmp_path):
    run = await run_sightings(tmp_path, XSearchProvider, SEED_URL,
                              route({"api.twitter.com": json_response({"detail": "forbidden"}, 403)}),
                              env={"X_BEARER_TOKEN": "tok"})
    assert run.result.sightings == []
    assert any("403" in note for note in run.result.notes)


# --------------------------------------------------------------------------- #
# Commercial feeds
# --------------------------------------------------------------------------- #
async def test_domaintools_parses_whois(tmp_path):
    payload = {"whois": {"parsed": {
        "registrar": "NameCheap", "created_date": "2024-02-01", "expiration_date": "2026-02-01",
        "name_servers": ["NS1.EXAMPLE-DNS.com", "ns2.example-dns.com"],
        "email": "abuse@example-dns.com", "whois_server": "whois.namecheap.com",
    }}}
    run = await run_provider(tmp_path, DomainToolsProvider, "evil.example",
                             route({"api.domaintools.com": payload}),
                             env={"DOMAINTOOLS_API_KEY": "k", "DOMAINTOOLS_USERNAME": "acct"})
    assert run.values("nameserver") == {"ns1.example-dns.com", "ns2.example-dns.com"}
    emails = [obs for obs in run.result.observations if obs.type == "email"]
    assert emails and emails[0].context_only is True
    assert any(event.kind == "domain-registered" and event.occurred_at.year == 2024
               for event in run.result.events)
    assert run.requests[0].url.params.get("api_username") == "acct"


async def test_validin_parses_dns_history(tmp_path):
    payload = {"query_key": "evil.example", "status": "finished", "records": {
        "A": [{"key": "evil.example", "value": "203.0.113.9", "value_type": "ip4",
               "first_seen": 1713463200, "last_seen": 1727719200}],
        "NS": [{"key": "evil.example", "value": "ns1.bad-dns.net", "value_type": "dom",
                "first_seen": 1713463200, "last_seen": 1727719200}],
        "WAYWARD_NS": [{"key": "sibling.example", "value": "ns1.bad-dns.net", "value_type": "raw",
                        "first_seen": 1713463200, "last_seen": 1727719200}],
    }, "records_returned": 3, "limited": False}
    run = await run_provider(tmp_path, ValidinProvider, "evil.example",
                             route({"app.validin.com": payload}), env={"VALIDIN_API_KEY": "vkey"})
    assert run.values("ip") == {"203.0.113.9"}
    assert run.values("nameserver") == {"ns1.bad-dns.net"}
    wayward = [obs for obs in run.result.observations if obs.relation == "wayward-nameserver"]
    assert wayward and wayward[0].context_only is True
    ip_obs = [obs for obs in run.result.observations if obs.type == "ip"][0]
    assert ip_obs.observed_at is not None and ip_obs.observed_at.year == 2024
    assert any(event.kind == "historical-dns" for event in run.result.events)
    assert run.requests[0].headers.get("authorization") == "Bearer vkey"


async def test_validin_ip_history(tmp_path):
    payload = {"records": {"A": [{"key": "203.0.113.55", "value": "host1.evil.example",
                                  "value_type": "dom", "first_seen": 1713463200, "last_seen": 1727719200}]}}
    # A/AAAA rows carry IP values; a dom value in an A bucket is skipped defensively.
    run = await run_provider(tmp_path, ValidinProvider, "203.0.113.55",
                             route({"app.validin.com": payload}), env={"VALIDIN_API_KEY": "vkey"})
    assert run.result.observations == []
    assert any("no usable" in note for note in run.result.notes)
    assert "ip/dns/history/203.0.113.55" in str(run.requests[0].url)


async def test_silentpush_enrichment(tmp_path):
    payload = {"data": {"sp_risk_score": 3, "asn": "AS64500", "ips": ["203.0.113.9"],
                        "whois": {"create_date": "2024-02-01", "registrar": "Porkbun",
                                  "email": "reg@example-dns.com"}}}
    run = await run_provider(tmp_path, SilentPushProvider, "evil.example",
                             route({"api.silentpush.com": payload}), env={"SILENTPUSH_API_KEY": "skey"})
    assert run.values("asn") == {"AS64500"}
    assert run.values("ip") == {"203.0.113.9"}
    emails = [obs for obs in run.result.observations if obs.type == "email"]
    assert emails and emails[0].context_only
    assert any("risk score 3" in event.label for event in run.result.events)
    assert run.requests[0].headers.get("x-api-key") == "skey"


async def test_netlas_domain_assets(tmp_path):
    payload = {"items": [{"data": {"domain": "www.evil.example", "a": ["203.0.113.9"],
                                   "aaaa": [], "ns": ["ns1.bad-dns.net"], "mx": []}}]}
    run = await run_provider(tmp_path, NetlasProvider, "evil.example",
                             route({"app.netlas.io": payload}), env={"NETLAS_API_KEY": "nkey"})
    assert run.values("ip") == {"203.0.113.9"}
    assert run.values("nameserver") == {"ns1.bad-dns.net"}
    subs = [obs for obs in run.result.observations if obs.relation == "subdomain-observed"]
    assert subs and subs[0].context_only
    assert any(event.kind == "host-response-survey" for event in run.result.events)
    assert run.requests[0].headers.get("authorization") == "Bearer nkey"


async def test_criminalip_ip_report(tmp_path):
    payload = {"ip": "203.0.113.55",
               "issues": {"is_vpn": True, "is_hosting": False, "is_scanner": True},
               "score": {"inbound": "Critical", "outbound": "Moderate"},
               "port": {"count": 1, "data": [{"open_port_no": 3389, "app_name": "ms-wbt-server"}]},
               "domain": {"count": 1, "data": [{"domain": "xyhaidy.shop"}]}}
    run = await run_provider(tmp_path, CriminalIpProvider, "203.0.113.55",
                             route({"api.criminalip.io": payload}), env={"CRIMINALIP_API_KEY": "ckey"})
    assert run.values("port") == {"3389"}
    connected = [obs for obs in run.result.observations if obs.type == "domain"]
    assert connected and connected[0].context_only
    assert any("Critical" in event.label for event in run.result.events)
    assert run.requests[0].headers.get("x-api-key") == "ckey"


async def test_criminalip_domain_report(tmp_path):
    payload = {"data": {"count": 1, "reports": [{
        "scan_id": "5573122", "score": "Low", "jarm": "29d29d", "reg_dtime": "2023-06-15 02:16:29",
        "url": ["http://example.com"], "issue": ["spf1"]}]}}

    run = await run_provider(tmp_path, CriminalIpProvider, "evil.example",
                             route({"api.criminalip.io": payload}), env={"CRIMINALIP_API_KEY": "ckey"})
    assert any("scored Low" in event.label for event in run.result.events)
    urls = [obs for obs in run.result.observations if obs.type == "url"]
    assert urls and urls[0].context_only


async def test_greynoise_riot_marks_benign(tmp_path):
    payload = {"riot": True, "classification": "benign", "name": "Cloudflare",
               "common_owners": ["Cloudflare, Inc."], "last_updated": "2025-01-01T00:00:00Z",
               "ip": "203.0.113.55"}
    run = await run_provider(tmp_path, GreyNoiseRiotProvider, "203.0.113.55",
                             route({"api.greynoise.io": payload}), env={"GREYNOISE_API_KEY": "gkey"})
    benign = [obs for obs in run.result.observations if obs.relation == "known-benign-service"]
    assert benign and benign[0].context_only and benign[0].meta.get("service") == "Cloudflare"
    assert any("RIOT" in event.label for event in run.result.events)
    assert run.requests[0].headers.get("key") == "gkey"


async def test_greynoise_riot_no_record(tmp_path):
    run = await run_provider(tmp_path, GreyNoiseRiotProvider, "203.0.113.55",
                             route({"api.greynoise.io": {"riot": False}}),
                             env={"GREYNOISE_API_KEY": "gkey"})
    assert run.result.observations == []
    assert any("not in the RIOT" in note for note in run.result.notes)


# --------------------------------------------------------------------------- #
# Breach providers (legal gate + parsing)
# --------------------------------------------------------------------------- #
BREACH_OPTIONS = {"legal_acknowledged": True}


async def test_dehashed_parses_entries(tmp_path):
    payload = {"success": True, "count": 2, "entries": [
        {"email": "victim@example.com", "username": "v1ctim", "database": "BreachA"},
        {"email": "admin@evil.example", "username": "", "database": "BreachA"},
    ]}
    run = await run_provider(
        tmp_path, DeHashedProvider, "victim@example.com",
        route({"api.dehashed.com": payload}),
        env={"DEHASHED_API_KEY": "dkey", "DEHASHED_EMAIL": "analyst@example.com"},
        options=BREACH_OPTIONS, seed_type="email")
    emails = [obs for obs in run.result.observations if obs.type == "email"]
    assert {obs.value for obs in emails} == {"victim@example.com", "admin@evil.example"}
    assert all(obs.context_only for obs in emails)
    usernames = [obs for obs in run.result.observations if obs.type == "username"]
    assert {obs.value for obs in usernames} == {"v1ctim"}
    assert any("BreachA" in event.label for event in run.result.events)
    expected = base64.b64encode(b"analyst@example.com:dkey").decode()
    assert run.requests[0].headers.get("authorization") == f"Basic {expected}"


async def test_dehashed_gated_without_acknowledgement(tmp_path):
    provider = DeHashedProvider(ProviderSettings(enabled=True))
    config = make_config(tmp_path, env={"DEHASHED_API_KEY": "k", "DEHASHED_EMAIL": "a@b.c"})
    runnable, reason = provider.can_run(config)
    assert not runnable
    assert "legal acknowledgement" in reason


async def test_intelx_search_flow(tmp_path):
    search_id = "11111111-2222-3333-4444-555555555555"
    start = {"id": search_id, "status": 0}
    result = {"status": 0, "count": 1, "records": [{
        "systemid": "abc", "name": "Evil phishing kit leak.txt", "date": "2024-06-01 10:00:00",
        "bucket": "leak", "type": 1, "storageid": "s1"}]}
    run = await run_provider(
        tmp_path, IntelXProvider, "evil.example",
        route({"/intelligent/search/result": result, "/intelligent/search": start}),
        env={"INTELX_API_KEY": "00000000-0000-0000-0000-000000000000"},
        options={"legal_acknowledged": True, "api_base": "https://free.intelx.io"})
    assert len(run.requests) == 2
    assert run.requests[0].headers.get("x-key") == "00000000-0000-0000-0000-000000000000"
    results = [event for event in run.result.events if event.kind == "intelx-result"]
    assert len(results) == 1
    assert results[0].url == "https://intelx.io/?did=abc"
    assert any(event.kind == "intelx-summary" for event in run.result.events)


async def test_intelx_gated_without_acknowledgement(tmp_path):
    provider = IntelXProvider(ProviderSettings(enabled=True))
    config = make_config(tmp_path, env={"INTELX_API_KEY": "00000000-0000-0000-0000-000000000000"})
    runnable, reason = provider.can_run(config)
    assert not runnable
    assert "legal acknowledgement" in reason
