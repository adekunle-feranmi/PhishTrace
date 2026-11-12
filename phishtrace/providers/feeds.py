"""Threat feeds: abuse.ch (URLhaus, ThreatFox), OpenPhish, Phishing.Database,
PhishTank and PhishStats.

The bulk feeds (OpenPhish, Phishing.Database) are downloaded once per cache
window and matched locally against the seed's host, which keeps the request
budget tiny even for large investigations.
"""

from __future__ import annotations

from urllib.parse import quote

from phishtrace.models import SelectorStrength
from phishtrace.normalizer import extract_indicators
from phishtrace.providers._util import (
    as_int, as_list, first, host_matches, indicator_host, indicator_url, iterate_dicts,
    iter_lines, parse_date, result_error, safe_domain, safe_ip, text, url_host,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta

ABUSE_CH_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
ABUSE_CH_URLHAUS = "https://urlhaus-api.abuse.ch/v1/"


def _abusech_headers(ctx) -> dict | None:
    """abuse.ch APIs now require a free Auth-Key; omit the header when absent
    so the registry can report the provider as skipped instead of failing 401."""
    key = ctx.config.api_key("ABUSECH_AUTH_KEY")
    return {"Auth-Key": key} if key else None


def _seed_domain(ctx) -> str:
    indicator = ctx.indicator
    if indicator.type == "domain":
        return indicator.normalized
    if indicator.type == "url":
        host = indicator_host(indicator)
        return host
    return ""


class _BulkFeedProvider(BaseProvider):
    """Download a plain-text feed and keep only rows relevant to the seed."""

    feed_url = ""
    feed_label = ""

    async def _download(self, ctx):
        return await ctx.http.get_text(
            self.feed_url, timeout=90.0, max_bytes=16_000_000,
            cache_key=f"feed:{self.meta.name}", cache_ttl=self.meta.cache_ttl or 900.0,
        )

    async def run(self, ctx):
        domain = _seed_domain(ctx)
        if not domain:
            ctx.partial(f"{self.meta.name} requires a domain or URL seed")
            return ctx.result
        res = await self._download(ctx)
        if not res.ok:
            ctx.partial(f"{self.feed_label} unavailable: {result_error(res)}")
            return ctx.result
        seed_url = indicator_url(ctx.indicator)
        matches = 0
        for line in iter_lines(res.text, limit=200_000):
            host = url_host(line)
            if not host or not host_matches(host, domain):
                continue
            matches += 1
            ctx.emit(
                "url", line, "feed-listing", SelectorStrength.STRONG,
                evidence_id=res.evidence_id, tags=["feed", self.meta.name],
            )
            if matches >= 100:
                break
        if seed_url and not matches:
            # The exact page may appear under a slightly different canonical form.
            for line in iter_lines(res.text, limit=200_000):
                if seed_url.rstrip("/") in line:
                    ctx.emit("url", line.strip(), "feed-listing", SelectorStrength.STRONG,
                             evidence_id=res.evidence_id, tags=["feed", self.meta.name])
                    break
        if not matches:
            ctx.result.notes.append(f"{self.feed_label}: seed not present in current feed")
        return ctx.result


class OpenPhishProvider(_BulkFeedProvider):
    feed_url = "https://openphish.com/feed.txt"
    feed_label = "OpenPhish"
    meta = ProviderMeta(
        name="openphish",
        accepts=("url", "domain"),
        emits=("url",),
        rate_limit=0.2,
        timeout=90.0,
        reliability=0.82,
        category="feeds",
        description="OpenPhish public feed of active phishing URLs (keyless, current snapshot)",
        homepage="https://openphish.com/",
        cache_ttl=900.0,
    )


class PhishingDatabaseProvider(_BulkFeedProvider):
    feed_url = (
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
        "master/phishing-links-ACTIVE.txt"
    )
    feed_label = "Phishing.Database"
    meta = ProviderMeta(
        name="phishing_database",
        accepts=("url", "domain"),
        emits=("url",),
        rate_limit=0.2,
        timeout=90.0,
        reliability=0.8,
        category="feeds",
        description="Phishing.Database active phishing links (community feed, keyless)",
        homepage="https://github.com/Phishing-Database/Phishing.Database",
        cache_ttl=1800.0,
    )


class UrlhausProvider(BaseProvider):
    meta = ProviderMeta(
        name="urlhaus",
        accepts=("url", "domain", "file_hash"),
        emits=("url", "domain", "file_hash"),
        api_keys=("ABUSECH_AUTH_KEY",),
        rate_limit=0.6,
        timeout=30.0,
        reliability=0.9,
        category="feeds",
        description="URLhaus malware URL/payload database (requires a free abuse.ch Auth-Key)",
        homepage="https://urlhaus.abuse.ch/",
        cache_ttl=1800.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        if indicator.type == "domain":
            endpoint, payload = "host/", {"host": indicator.normalized}
        elif indicator.type == "url":
            endpoint, payload = "url/", {"url": indicator.normalized}
        elif indicator.type == "file_hash":
            endpoint, payload = "payload/", {"sha256_hash": indicator.normalized}
        else:
            ctx.partial("urlhaus supports URL, domain and file hash seeds")
            return ctx.result
        res = await ctx.http.request(
            "POST", ABUSE_CH_URLHAUS + endpoint, data=payload, expect_json=True,
            headers=_abusech_headers(ctx), timeout=30.0,
            cache_key=f"urlhaus:{indicator.type}:{indicator.normalized}", cache_ttl=1800.0,
        )
        if not res.ok:
            ctx.partial(f"urlhaus unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        status = text(data.get("query_status")).lower()
        if status not in {"ok", "no_results"}:
            ctx.partial(f"urlhaus query status: {status or 'unknown'}")
            return ctx.result
        if status == "no_results":
            ctx.result.notes.append("urlhaus: no records for this indicator")
            return ctx.result

        for row in iterate_dicts(first(data, "urls", default=[]), max_items=100):
            row_url = text(first(row, "url"))
            added = parse_date(first(row, "date_added"))
            tags = [text(tag).lower() for tag in as_list(first(row, "tags", default=[])) if text(tag)]
            threat = text(first(row, "threat"))
            if row_url:
                ctx.emit(
                    "url", row_url, "urlhaus-listing", SelectorStrength.STRONG,
                    evidence_id=res.evidence_id, observed_at=added,
                    tags=["feed", "urlhaus", *tags],
                    meta={"threat": threat, "urlhaus_link": text(first(row, "urlhaus_link")),
                          "reporter": text(first(row, "reporter"))},
                )
            if added:
                ctx.event(
                    added, kind="feed-submission",
                    label=f"URLhaus first listed {row_url or indicator.normalized}",
                    detail=threat or None,
                    url=text(first(row, "urlhaus_link")) or None,
                    evidence_id=res.evidence_id, indicator_value=indicator.normalized,
                )
        for row in iterate_dicts(first(data, "payloads", default=[]), max_items=50):
            sha = text(first(row, "sha256_hash", "sha256")).lower()
            first_seen = parse_date(first(row, "firstseen", "first_seen"))
            if sha:
                ctx.emit(
                    "file_hash", sha, "urlhaus-payload", SelectorStrength.STRONG,
                    evidence_id=res.evidence_id, observed_at=first_seen,
                    tags=["feed", "urlhaus", "malware-payload"],
                    meta={"signature": text(first(row, "signature")),
                          "file_type": text(first(row, "file_type"))},
                )
        return ctx.result


class ThreatFoxProvider(BaseProvider):
    meta = ProviderMeta(
        name="threatfox",
        accepts=("domain", "ip", "url", "file_hash"),
        emits=("domain", "ip", "url", "file_hash"),
        api_keys=("ABUSECH_AUTH_KEY",),
        rate_limit=0.5,
        timeout=30.0,
        reliability=0.88,
        category="threat-intel",
        description="abuse.ch ThreatFox IOC database (requires a free abuse.ch Auth-Key)",
        homepage="https://threatfox.abuse.ch/",
        cache_ttl=1800.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        value = indicator.normalized
        if indicator.type == "file_hash":
            query_term = value
        else:
            query_term = value
        res = await ctx.http.post_json(
            ABUSE_CH_THREATFOX,
            json_body={"query": "search_ioc", "search_term": query_term},
            headers=_abusech_headers(ctx), timeout=30.0,
            cache_key=f"threatfox:{indicator.type}:{value}", cache_ttl=1800.0,
        )
        if not res.ok:
            ctx.partial(f"threatfox unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        status = text(data.get("query_status")).lower()
        if status not in {"ok", "no_result", "no_results"}:
            ctx.partial(f"threatfox query status: {status or 'unknown'}")
            return ctx.result
        rows = as_list(data.get("data"))
        if not rows:
            ctx.result.notes.append("threatfox: no records for this indicator")
            return ctx.result
        for row in rows[:100]:
            if not isinstance(row, dict):
                continue
            ioc = text(first(row, "ioc"))
            ioc_type = text(first(row, "ioc_type")).lower()
            first_seen = parse_date(first(row, "first_seen"))
            last_seen = parse_date(first(row, "last_seen"))
            malware = text(first(row, "malware_printable", "malware"))
            threat_type = text(first(row, "threat_type"))
            confidence = as_int(first(row, "confidence_level"), 0)
            tags = [text(tag) for tag in as_list(first(row, "tags", default=[])) if text(tag)]
            kind, normalized = _classify_ioc(ioc, ioc_type)
            if not kind:
                continue
            ctx.emit(
                kind, normalized, "threatfox-ioc", SelectorStrength.STRONG,
                evidence_id=res.evidence_id, observed_at=first_seen,
                tags=["threat-intel", "threatfox", *tags],
                meta={"malware": malware, "threat_type": threat_type,
                      "confidence": confidence,
                      "last_seen": last_seen.isoformat() if last_seen else None,
                      "reference": text(first(row, "reference"))},
            )
            if first_seen:
                ctx.event(
                    first_seen, kind="threat-ioc-first-seen",
                    label=f"ThreatFox first observed {normalized}",
                    detail=" / ".join(part for part in (malware, threat_type) if part) or None,
                    evidence_id=res.evidence_id, indicator_value=normalized,
                )
        return ctx.result


def _classify_ioc(ioc: str, ioc_type: str) -> tuple[str, str]:
    lowered = ioc_type.lower()
    if lowered in {"domain", "hostname"}:
        domain = safe_domain(ioc)
        return ("domain", domain) if domain else ("", "")
    if lowered in {"url", "uri"}:
        return ("url", ioc) if ioc.startswith(("http://", "https://")) else ("", "")
    if lowered in {"ip", "ip:port"}:
        ip = safe_ip(ioc.split(":")[0])
        return ("ip", ip) if ip else ("", "")
    if "md5" in lowered or "sha1" in lowered or "sha256" in lowered:
        for found in extract_indicators(ioc, limit=1, include_url_parts=False):
            if found.type in {"file_hash", "cert_sha256"}:
                return (found.type, found.normalized)
    return ("", "")


class PhishTankProvider(BaseProvider):
    meta = ProviderMeta(
        name="phishtank",
        accepts=("url", "domain"),
        emits=("url",),
        api_keys=("PHISHTANK_API_KEY",),
        rate_limit=0.3,
        timeout=30.0,
        reliability=0.85,
        category="feeds",
        description="PhishTank verified phishing URL lookup (requires PHISHTANK_API_KEY)",
        homepage="https://www.phishtank.com/",
        cache_ttl=1800.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        if indicator.type == "url":
            candidate = indicator.normalized
        else:
            domain = indicator_host(indicator)
            candidate = f"http://{domain}/" if domain else ""
        if not candidate:
            ctx.partial("phishtank requires a URL or domain seed")
            return ctx.result
        app_key = ctx.config.api_key("PHISHTANK_API_KEY") or ""
        res = await ctx.http.post_json(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": candidate, "format": "json", "app_key": app_key},
            timeout=30.0, cache_key=f"phishtank:{candidate}", cache_ttl=1800.0,
        )
        if not res.ok:
            ctx.partial(f"phishtank unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        results = first(data, "results", default={})
        if not isinstance(results, dict) or not results.get("in_database"):
            ctx.result.notes.append("phishtank: URL not present in database")
            return ctx.result
        verified = bool(results.get("verified"))
        submitted = parse_date(first(results, "submission_time"))
        verified_at = parse_date(first(results, "verified_at"))
        ctx.emit(
            "url", text(first(results, "url", default=candidate)), "phishtank-verified",
            SelectorStrength.STRONG if verified else SelectorStrength.MEDIUM,
            evidence_id=res.evidence_id, observed_at=verified_at or submitted,
            tags=["feed", "phishtank"] + (["verified"] if verified else ["unverified"]),
            meta={"phish_id": text(first(results, "phish_id")),
                  "detail_page": text(first(results, "phish_detail_page"))},
        )
        if submitted:
            ctx.event(
                submitted, kind="feed-submission",
                label=f"PhishTank submission for {candidate}",
                url=text(first(results, "phish_detail_page")) or None,
                evidence_id=res.evidence_id, indicator_value=candidate,
            )
        return ctx.result


class PhishStatsProvider(BaseProvider):
    meta = ProviderMeta(
        name="phishstats",
        accepts=("url", "domain", "ip"),
        emits=("url", "ip", "domain"),
        rate_limit=0.3,
        timeout=30.0,
        reliability=0.7,
        category="feeds",
        description="PhishStats search API (keyless); URLs, hosting IPs and geolocation",
        homepage="https://phishstats.info/",
        cache_ttl=1800.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        if indicator.type == "ip":
            where = f"(ip,eq,{indicator.normalized})"
        elif indicator.type == "url":
            where = f"(url,like,~{quote(indicator_host(indicator))})"
        else:
            where = f"(url,like,~{quote(indicator.normalized)})"
        res = await ctx.http.get_json(
            "https://phishstats.info:2096/api/phishing",
            params={"_where": where, "_size": 100, "_sort": "-date"},
            timeout=30.0, max_bytes=4_000_000,
            cache_key=f"phishstats:{where}", cache_ttl=1800.0,
        )
        if not res.ok:
            ctx.partial(f"phishstats unavailable: {result_error(res)}")
            return ctx.result
        rows = res.data if isinstance(res.data, list) else []
        if not rows:
            ctx.result.notes.append("phishstats: no records for this indicator")
            return ctx.result
        for row in iterate_dicts(rows, max_items=100):
            url = text(first(row, "url"))
            ip = safe_ip(first(row, "ip"))
            observed = parse_date(first(row, "date"))
            score = as_int(first(row, "score"), 0)
            if url:
                ctx.emit(
                    "url", url, "phishstats-listing", SelectorStrength.MEDIUM,
                    evidence_id=res.evidence_id, observed_at=observed,
                    tags=["feed", "phishstats"],
                    meta={"score": score, "country": text(first(row, "country")),
                          "asn": text(first(row, "asn"))},
                )
            if ip:
                ctx.emit("ip", ip, "hosting-ip", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, observed_at=observed,
                         tags=["feed", "phishstats"])
            if observed:
                ctx.event(
                    observed, kind="feed-submission",
                    label=f"PhishStats observed {url or indicator.normalized}",
                    detail=f"score={score}" if score else None,
                    evidence_id=res.evidence_id, indicator_value=url or indicator.normalized,
                )
        return ctx.result
