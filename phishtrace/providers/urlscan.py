"""urlscan.io public search API (keyless).

The search endpoint exposes historical scans: the final URL, resolved IP, ASN,
country and the scanner's malicious verdict.  That is a ready-made pivot set
with timestamps.
"""

from __future__ import annotations

from urllib.parse import quote

from phishtrace.models import SelectorStrength
from phishtrace.providers._util import (
    as_int, as_list, first, indicator_host, parse_date, result_error, safe_domain, safe_ip, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta


class UrlscanProvider(BaseProvider):
    meta = ProviderMeta(
        name="urlscan",
        accepts=("url", "domain", "ip"),
        emits=("url", "domain", "ip", "asn"),
        rate_limit=0.25,
        timeout=45.0,
        reliability=0.85,
        category="scanners",
        description="Historical URL/DOM scans from urlscan.io (keyless search API)",
        homepage="https://urlscan.io/",
        cache_ttl=1800.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        if indicator.type == "ip":
            query = f"page.ip:{indicator.normalized}"
        elif indicator.type == "url":
            query = f'page.url:"{indicator.normalized}"'
        else:
            host = indicator_host(indicator)
            if not host:
                ctx.partial("urlscan requires a URL, domain or IP seed")
                return ctx.result
            query = f"domain:{host}"
        res = await ctx.http.get_json(
            "https://urlscan.io/api/v1/search/",
            params={"q": query, "size": 100},
            headers={"Accept": "application/json"},
            timeout=45.0, max_bytes=6_000_000,
            cache_key=f"urlscan:{query}", cache_ttl=1800.0,
        )
        if not res.ok:
            ctx.partial(f"urlscan unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        if text(data.get("message", "")).lower().startswith("error"):
            ctx.partial(f"urlscan error: {text(data.get('message'))[:160]}")
            return ctx.result
        results = as_list(data.get("results"))
        if not results:
            ctx.partial("urlscan returned no scans")
            return ctx.result

        seen_urls: set[str] = set()
        seen_ips: set[str] = set()
        for row in results[:100]:
            if not isinstance(row, dict):
                continue
            page = first(row, "page", default={})
            task = first(row, "task", default={})
            if not isinstance(page, dict):
                page = {}
            when = parse_date(first(task, "time") or first(row, "task_time"))
            scan_id = text(first(row, "_id", "uuid"))
            scan_url = f"https://urlscan.io/result/{scan_id}/" if scan_id else None
            final_url = text(first(page, "url"))
            if final_url and final_url not in seen_urls and len(seen_urls) < 60:
                seen_urls.add(final_url)
                ctx.emit(
                    "url", final_url, "scanned-url", SelectorStrength.MEDIUM,
                    evidence_id=res.evidence_id, observed_at=when,
                    tags=["urlscan"], meta={"scan": scan_url},
                )
            ip = safe_ip(first(page, "ip"))
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                ctx.emit(
                    "ip", ip, "resolved-by-scanner", SelectorStrength.MEDIUM,
                    evidence_id=res.evidence_id, observed_at=when, tags=["urlscan"],
                )
            asn = text(first(page, "asn"))
            if asn:
                digits = "".join(ch for ch in asn if ch.isdigit())
                if digits:
                    ctx.emit(
                        "asn", f"AS{digits}", "hosted-on", SelectorStrength.MEDIUM,
                        evidence_id=res.evidence_id,
                        tags=["urlscan"],
                        meta={"asn_name": text(first(page, "asnname")),
                              "country": text(first(page, "country"))},
                    )
            stats = first(row, "stats", default={})
            malicious = as_int(first(stats, "malicious"), 0) if isinstance(stats, dict) else 0
            if when:
                ctx.event(
                    when, kind="url-scan",
                    label=f"urlscan.io scan of {final_url or indicator.normalized}",
                    detail=f"malicious_score={malicious}",
                    url=scan_url, evidence_id=res.evidence_id,
                    indicator_value=indicator.normalized,
                    meta={"malicious": malicious, "country": text(first(page, "country"))},
                )
        return ctx.result
