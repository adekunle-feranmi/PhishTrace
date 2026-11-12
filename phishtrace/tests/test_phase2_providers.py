"""Provider parsing tests. All HTTP is mocked; no live service is contacted."""

from __future__ import annotations

import httpx

from phishtrace.core.registry import Registry
from phishtrace.normalizer import normalize_indicator
from phishtrace.providers.archives import MementoProvider, WaybackProvider
from phishtrace.providers.certificates import CertSpotterProvider, CrtShProvider
from phishtrace.providers.domain_intel import (
    DnsIntelProvider, HackerTargetProvider, RdapProvider, ThreatMinerProvider,
)
from phishtrace.providers.feeds import (
    OpenPhishProvider, PhishingDatabaseProvider, PhishStatsProvider, PhishTankProvider,
    ThreatFoxProvider, UrlhausProvider,
)
from phishtrace.providers.infrastructure import (
    HudsonRockProvider, IpinfoProvider, ShodanInternetDbProvider, TyposquatProvider,
)
from phishtrace.providers.social import BlueskyProvider, MastodonProvider, RedditProvider, TelegramPublicProvider
from phishtrace.providers.urlscan import UrlscanProvider
from phishtrace.tests.providers_harness import json_response, route, run_provider, run_sightings, text_response


# --------------------------------------------------------------------------- #
# Certificates
# --------------------------------------------------------------------------- #

async def test_crt_sh_parses_names_events_and_evidence(tmp_path):
    payload = [
        {"id": 1, "name_value": "evil.example\n*.evil.example\nsibling.example.net",
         "not_before": "2025-01-02T03:04:05", "not_after": "2025-04-02T03:04:05",
         "issuer_name": "C=US, O=Let's Encrypt", "serial_number": "abc"},
        {"id": 2, "name_value": "evil.example", "not_before": "2024-11-01T00:00:00",
         "issuer_name": "C=US, O=Let's Encrypt"},
    ]
    run = await run_provider(tmp_path, CrtShProvider, "evil.example",
                             route({"crt.sh": payload}))
    domains = {obs.value for obs in run.observations("domain")}
    # The seed itself is already a graph node; only new infrastructure is emitted.
    assert "sibling.example.net" in domains
    assert "evil.example" not in domains
    assert run.result.events, "certificate issuance must produce a timeline event"
    assert run.result.events[0].kind == "certificate-issuance"
    evidence = run.repo.list_evidence(run.investigation_id)
    assert evidence and evidence[0]["provider"] == "crt_sh"
    assert "request" in evidence[0]


async def test_crt_sh_degrades_on_http_error(tmp_path):
    run = await run_provider(tmp_path, CrtShProvider, "evil.example",
                             lambda request: httpx.Response(503, text="down"))
    assert run.result.observations == []
    assert run.result.partial is True
    assert any("unavailable" in note for note in run.result.notes)


async def test_certspotter_parses_issuances(tmp_path):
    payload = [{"id": "c1", "dns_names": ["evil.example", "www.evil.example"],
                "not_before": "2025-02-02T00:00:00Z",
                "issuer": {"name": "R3"}}]
    run = await run_provider(tmp_path, CertSpotterProvider, "evil.example",
                             route({"api.certspotter.com": payload}))
    assert {"www.evil.example"} <= run.values("domain")
    assert any(event.kind == "certificate-issuance" for event in run.result.events)


# --------------------------------------------------------------------------- #
# RDAP / DNS / passive DNS
# --------------------------------------------------------------------------- #

async def test_rdap_registration_events_nameservers_and_registrant_email(tmp_path):
    payload = {
        "ldhName": "EVIL.EXAMPLE",
        "events": [
            {"eventAction": "registration", "eventDate": "2024-03-01T12:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-03-01T12:00:00Z"},
        ],
        "nameservers": [{"ldhName": "NS1.BULLETPROOF.EXAMPLE"}],
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Registrar Inc"]]]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [
                ["fn", {}, "text", "Fraudster"],
                ["email", {}, "text", "owner@evil.example"]]]},
        ],
    }
    run = await run_provider(tmp_path, RdapProvider, "evil.example", route({"rdap.org": payload}))
    assert "ns1.bulletproof.example" in run.values("nameserver")
    assert "owner@evil.example" in run.values("email")
    kinds = {event.kind for event in run.result.events}
    assert {"domain-registered", "domain-expires"} <= kinds


async def test_dns_intel_resolves_records_and_txt_analytics(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        qtype = request.url.params.get("type")
        answers = {
            "A": [{"name": "evil.example", "type": 1, "data": "203.0.113.55"}],
            "NS": [{"name": "evil.example", "type": 2, "data": "ns1.bulletproof.example."}],
            "MX": [{"name": "evil.example", "type": 15, "data": "10 mail.other.example."}],
            "TXT": [{"name": "evil.example", "type": 16,
                     "data": '"v=spf1 include:spf.attacker.example -all UA-424242-7"'}],
            "CNAME": [],
        }
        return json_response({"Status": 0, "Answer": answers.get(qtype, [])})

    run = await run_provider(tmp_path, DnsIntelProvider, "evil.example", handler)
    assert "203.0.113.55" in run.values("ip")
    assert "ns1.bulletproof.example" in run.values("nameserver")
    assert "mail.other.example" in run.values("domain")
    assert "spf.attacker.example" in run.values("domain")
    assert "UA-424242-7" in run.values("analytics_id")
    assert len(run.requests) == 5


async def test_hackertarget_parses_csv(tmp_path):
    body = "mail.evil.example,203.0.113.7\nvpn.evil.example,203.0.113.8\nunrelated.example,198.51.100.1\n"
    run = await run_provider(tmp_path, HackerTargetProvider, "evil.example", route({"hackertarget": body}))
    assert {"mail.evil.example", "vpn.evil.example"} <= run.values("domain")
    assert "203.0.113.7" in run.values("ip")
    assert "unrelated.example" not in run.values("domain")


async def test_threatminer_passive_dns_for_ip(tmp_path):
    payload = {"status_code": "200", "results": [{"domain": "evil.example"}, {"domain": "login.evil.example"}]}
    run = await run_provider(tmp_path, ThreatMinerProvider, "203.0.113.9",
                             route({"threatminer": payload}))
    assert {"evil.example", "login.evil.example"} == run.values("domain")


# --------------------------------------------------------------------------- #
# Archives and scanners
# --------------------------------------------------------------------------- #

async def test_wayback_cdx_earliest_snapshot_and_urls(tmp_path):
    payload = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20240101000000", "https://evil.example/login", "200", "text/html"],
        ["20230101000000", "https://evil.example/", "200", "text/html"],
        ["20240505000000", "https://evil.example/login", "200", "text/html"],
    ]
    run = await run_provider(tmp_path, WaybackProvider, "evil.example", route({"cdx": payload}))
    assert run.result.events and run.result.events[0].kind == "archive-snapshot"
    assert run.result.events[0].occurred_at.year == 2023
    urls = run.values("url")
    assert "https://evil.example/login" in urls


async def test_memento_earliest_capture(tmp_path):
    body = (
        '<http://web.archive.org/web/2019/https://evil.example/>; rel="memento"; '
        'datetime="2019-06-01T00:00:00Z"\n'
        '<https://arquivo.pt/wayback/2021/https://evil.example/>; rel="memento"; '
        'datetime="2021-06-01T00:00:00Z"\n'
    )
    run = await run_provider(tmp_path, MementoProvider, "https://evil.example/",
                             route({"timetravel": body}))
    assert run.result.events and run.result.events[0].occurred_at.year == 2019


async def test_urlscan_parses_pages_and_asn(tmp_path):
    payload = {"results": [{
        "task": {"time": "2025-04-04T10:00:00Z"},
        "_id": "scan-1",
        "page": {"url": "https://evil.example/login", "domain": "evil.example",
                 "ip": "203.0.113.20", "asn": "AS13335", "asnname": "CLOUDFLARENET",
                 "country": "US"},
        "stats": {"malicious": 2},
    }]}
    run = await run_provider(tmp_path, UrlscanProvider, "evil.example", route({"urlscan.io/api": payload}))
    assert "203.0.113.20" in run.values("ip")
    assert "AS13335" in run.values("asn")
    assert "https://evil.example/login" in run.values("url")
    assert run.result.events and run.result.events[0].kind == "url-scan"


# --------------------------------------------------------------------------- #
# Feeds
# --------------------------------------------------------------------------- #

async def test_urlhaus_host_listing(tmp_path):
    payload = {"query_status": "ok", "urls": [{
        "url": "http://evil.example/payload.exe", "date_added": "2025-01-05 10:00:00",
        "threat": "malware_download", "tags": ["exe", "emotet"],
        "urlhaus_link": "https://urlhaus.abuse.ch/url/1/",
    }]}
    run = await run_provider(tmp_path, UrlhausProvider, "evil.example", route({"urlhaus-api": payload}))
    assert "http://evil.example/payload.exe" in run.values("url")
    assert run.result.events[0].kind == "feed-submission"


async def test_threatfox_classifies_ioc(tmp_path):
    payload = {"query_status": "ok", "data": [{
        "ioc": "evil.example", "ioc_type": "domain", "threat_type": "payload_delivery",
        "malware_printable": "AgentTesla", "first_seen": "2024-12-01 08:00:00",
        "confidence_level": 90, "tags": ["stealer"],
    }]}
    run = await run_provider(tmp_path, ThreatFoxProvider, "evil.example", route({"threatfox": payload}))
    assert "evil.example" in run.values("domain")
    assert any("AgentTesla" in (event.detail or "") for event in run.result.events)


async def test_openphish_matches_only_seed_domain(tmp_path):
    body = "\n".join([
        "https://evil.example/login",
        "https://evil.example/verify",
        "https://unrelated.example/login",
    ])
    run = await run_provider(tmp_path, OpenPhishProvider, "evil.example", route({"openphish": body}))
    assert run.values("url") == {
        "https://evil.example/login", "https://evil.example/verify",
    }


async def test_phishing_database_feed(tmp_path):
    body = "https://evil.example/a\nhttps://another.example/b\n"
    run = await run_provider(tmp_path, PhishingDatabaseProvider, "evil.example",
                             route({"phishing-links-ACTIVE": body}))
    assert run.values("url") == {"https://evil.example/a"}


async def test_phishtank_verifies_with_key(tmp_path):
    payload = {"results": {"in_database": True, "verified": True, "valid": True,
                           "url": "http://evil.example/", "phish_id": "123",
                           "submission_time": "2025-01-01T00:00:00Z",
                           "verified_at": "2025-01-02T00:00:00Z",
                           "phish_detail_page": "https://phishtank.org/phish_detail.php?phish_id=123"}}
    run = await run_provider(tmp_path, PhishTankProvider, "evil.example",
                             route({"checkurl": payload}), env={"PHISHTANK_API_KEY": "test-key"})
    obs = run.observations("url")
    assert obs and obs[0].strength == "strong"
    assert "verified" in obs[0].tags


async def test_phishstats_url_and_ip(tmp_path):
    payload = [{"url": "https://evil.example/x", "ip": "203.0.113.77",
                "date": "2025-02-02 12:00:00", "score": 42, "country": "NL", "asn": "AS1"}]
    run = await run_provider(tmp_path, PhishStatsProvider, "evil.example", route({"phishstats": payload}))
    assert "https://evil.example/x" in run.values("url")
    assert "203.0.113.77" in run.values("ip")


# --------------------------------------------------------------------------- #
# Hosting / exposure / lookalikes
# --------------------------------------------------------------------------- #

async def test_shodan_internetdb_hostnames(tmp_path):
    payload = {"ip": "203.0.113.5", "ports": [80, 443],
               "hostnames": ["evil.example", "cdn.evil.example"],
               "vulns": ["CVE-2021-44228"], "tags": ["eol-os"]}
    run = await run_provider(tmp_path, ShodanInternetDbProvider, "203.0.113.5",
                             route({"internetdb": payload}))
    assert {"evil.example", "cdn.evil.example"} == run.values("domain")
    assert any("CVE-2021-44228" in note for note in run.result.notes)


async def test_ipinfo_asn(tmp_path):
    payload = {"ip": "203.0.113.5", "hostname": "evil.example", "country": "US",
               "org": "AS13335 Cloudflare, Inc.", "asn": {"asn": "AS13335", "name": "CLOUDFLARENET"}}
    run = await run_provider(tmp_path, IpinfoProvider, "203.0.113.5", route({"ipinfo.io": payload}))
    assert "AS13335" in run.values("asn")
    assert "evil.example" in run.values("domain")


async def test_hudsonrock_is_aggregate_only(tmp_path):
    payload = {"stealers": [
        {"stealerFamily": "RedLine", "date_compromised": "2024-05-01T00:00:00Z",
         "computerName": "VICTIM-PC", "topPasswords": ["hunter2"], "ip": "198.51.100.4"},
        {"stealerFamily": "RedLine", "date_compromised": "2024-06-01T00:00:00Z",
         "computerName": "OTHER-PC", "topPasswords": ["letmein"]},
    ]}
    run = await run_provider(tmp_path, HudsonRockProvider, "victim@evil.example",
                             route({"hudsonrock": payload}))
    blob = run.result.model_dump_json() + run.ctx.http.recorder.__class__.__name__
    assert "VICTIM-PC" not in blob and "hunter2" not in blob
    assert run.result.events and run.result.events[0].kind == "infostealer-exposure"
    assert "RedLine" in run.result.events[0].detail


async def test_typosquat_generates_candidates_without_network(tmp_path):
    run = await run_provider(tmp_path, TyposquatProvider, "example.com", route({}))
    values = run.values("domain")
    assert "examp1e.com" in values or "exarnple.com" in values
    assert all(obs.strength == "weak" for obs in run.observations("domain"))
    assert run.requests == []


# --------------------------------------------------------------------------- #
# Social sightings
# --------------------------------------------------------------------------- #

async def test_telegram_public_parses_posts(tmp_path):
    body = (
        '<div class="tgme_widget_message" data-post="scam_channel/17">'
        '<div class="tgme_widget_message_text js-message_text">'
        'Login at https://evil.example/login before it is taken down</div>'
        '<time datetime="2025-03-04T10:20:30+00:00"></time></div>'
        '<div class="tgme_widget_message" data-post="scam_channel/18">'
        '<div class="tgme_widget_message_text js-message_text">unrelated post</div>'
        '<time datetime="2025-03-05T10:20:30+00:00"></time></div>'
    )
    run = await run_sightings(tmp_path, TelegramPublicProvider, "@scam_channel",
                              route({"t.me/s/": body}))
    assert len(run.result.sightings) == 2
    first = run.result.sightings[0]
    assert first.platform == "telegram"
    assert first.post_url == "https://t.me/scam_channel/17"
    assert first.posted_at is not None and first.posted_at.year == 2025
    assert "evil.example" in first.text


async def test_bluesky_search_filters_non_matching_posts(tmp_path):
    payload = {"posts": [
        {"uri": "at://did:plc:1/app.bsky.feed.post/abc",
         "author": {"handle": "bad.actor", "createdAt": "2024-01-01T00:00:00Z"},
         "record": {"text": "fresh phish https://evil.example/login",
                    "createdAt": "2025-02-02T00:00:00Z"}},
        {"uri": "at://did:plc:2/app.bsky.feed.post/def",
         "author": {"handle": "someone.else"},
         "record": {"text": "nothing to see here", "createdAt": "2025-02-02T00:00:00Z"}},
    ]}
    run = await run_sightings(tmp_path, BlueskyProvider, "https://evil.example/login",
                              route({"public.api.bsky.app": payload}))
    assert len(run.result.sightings) == 1
    assert run.result.sightings[0].post_url == "https://bsky.app/profile/bad.actor/post/abc"


async def test_reddit_public_json(tmp_path):
    payload = {"data": {"children": [{"data": {
        "title": "New phish evil.example", "selftext": "see https://evil.example/login",
        "url": "https://evil.example/login", "permalink": "/r/phishing/comments/abc/x/",
        "author": "scammer", "author_fullname": "t2_x", "author_created_utc": 1600000000,
        "created_utc": 1700000000, "subreddit": "phishing", "score": 5, "id": "abc",
    }}]}}
    run = await run_sightings(tmp_path, RedditProvider, "evil.example", route({"reddit.com": payload}))
    assert len(run.result.sightings) == 1
    sighting = run.result.sightings[0]
    assert sighting.post_url == "https://www.reddit.com/r/phishing/comments/abc/x/"
    assert sighting.author_created_at and sighting.author_created_at.year == 2020


async def test_mastodon_requires_token(tmp_path):
    run = await run_sightings(tmp_path, MastodonProvider, "evil.example", route({}))
    assert run.result.sightings == []
    assert any("MASTODON_TOKEN" in note for note in run.result.notes)


# --------------------------------------------------------------------------- #
# Registry coverage
# --------------------------------------------------------------------------- #

def test_registry_reports_keyless_providers_enabled_and_keyed_skipped(tmp_config):
    registry = Registry(tmp_config)
    names = {status.name for status in registry.statuses()}
    for expected in {
        "crt_sh", "rdap", "dns_intel", "wayback", "memento", "urlscan", "urlhaus",
        "threatfox", "openphish", "phishing_database", "certspotter", "hackertarget",
        "threatminer", "phishstats", "shodan_internetdb", "ipinfo", "hudsonrock",
        "typosquat", "telegram_public", "bluesky", "reddit",
    }:
        assert expected in names, f"{expected} was not discovered"
    assert registry.status("crt_sh").status == "enabled"
    assert registry.status("phishtank").status == "skipped"
    assert "PHISHTANK_API_KEY" in registry.status("phishtank").reason
    assert registry.status("mastodon").status == "skipped"
    assert not registry.load_errors
