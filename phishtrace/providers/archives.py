"""Web archive providers: Wayback Machine CDX and Memento TimeTravel.

Archives answer the question every phishing investigation starts with: *when
did this page first exist?*  Both providers here are keyless.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from phishtrace.models import SelectorStrength
from phishtrace.providers._util import (
    as_list, first, indicator_host, indicator_url, parse_date, result_error, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta

MEMENTO_LINE = re.compile(r'<(?P<url>[^>]+)>\s*;\s*rel="(?P<rel>[^"]+)"(?:.*?datetime="(?P<dt>[^"]+)")?')


class WaybackProvider(BaseProvider):
    meta = ProviderMeta(
        name="wayback",
        accepts=("url", "domain"),
        emits=("url",),
        rate_limit=0.4,
        timeout=60.0,
        reliability=0.85,
        category="archives",
        description="Wayback Machine CDX index (keyless): earliest snapshots and archived URLs",
        homepage="https://web.archive.org/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        if indicator.type == "url":
            target = indicator.normalized
            params = [
                ("url", target), ("output", "json"), ("limit", "50"),
                ("fl", "timestamp,original,statuscode,mimetype"),
            ]
        else:
            domain = indicator_host(indicator)
            if not domain:
                ctx.partial("wayback requires a URL or domain seed")
                return ctx.result
            target = domain
            params = [
                ("url", f"{domain}/*"), ("output", "json"), ("limit", "200"),
                ("fl", "timestamp,original,statuscode,mimetype"),
                ("filter", "statuscode:200"), ("collapse", "urlkey"),
            ]
        res = await ctx.http.get_json(
            "https://web.archive.org/cdx/search/cdx", params=params, timeout=60.0,
            max_bytes=6_000_000, cache_key=f"wayback:{target}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"wayback unavailable: {result_error(res)}")
            return ctx.result
        rows = res.data if isinstance(res.data, list) else []
        if not rows or not isinstance(rows[0], list):
            ctx.partial("wayback returned no captures")
            return ctx.result
        header = [text(col).lower() for col in rows[0]]
        index = {name: position for position, name in enumerate(header)}
        earliest = None
        earliest_url = ""
        emitted = 0
        for row in rows[1:]:
            if not isinstance(row, list):
                continue
            timestamp = text(row[index.get("timestamp", 0)])
            original = text(row[index.get("original", 1)]) if len(row) > 1 else ""
            if not original:
                continue
            captured = parse_date(timestamp)
            if captured and (earliest is None or captured < earliest):
                earliest, earliest_url = captured, original
            if emitted < 100 and original != target:
                emitted += 1
                ctx.emit(
                    "url", original, "archived-url", SelectorStrength.WEAK,
                    evidence_id=res.evidence_id, observed_at=captured,
                    tags=["archive", "wayback"],
                    meta={"timestamp": timestamp,
                          "snapshot": f"https://web.archive.org/web/{timestamp}/{original}"},
                )
        if earliest:
            snapshot = f"https://web.archive.org/web/{earliest.strftime('%Y%m%d%H%M%S')}/{earliest_url}"
            ctx.event(
                earliest, kind="archive-snapshot",
                label=f"Earliest Wayback capture of {target}",
                detail=earliest_url, url=snapshot,
                evidence_id=res.evidence_id, indicator_value=target,
            )
        return ctx.result


class MementoProvider(BaseProvider):
    meta = ProviderMeta(
        name="memento",
        accepts=("url",),
        emits=(),
        rate_limit=0.3,
        timeout=40.0,
        reliability=0.7,
        category="archives",
        description="Memento TimeTravel aggregator timemap (keyless); multi-archive earliest capture",
        homepage="http://timetravel.mementoweb.org/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        url = indicator_url(ctx.indicator)
        if not url:
            ctx.partial("memento requires a URL seed")
            return ctx.result
        res = await ctx.http.get_text(
            "http://timetravel.mementoweb.org/timemap/link/" + url,
            timeout=40.0, max_bytes=3_000_000,
            cache_key=f"memento:{url}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"memento unavailable: {result_error(res)}")
            return ctx.result
        earliest = None
        earliest_url = ""
        count = 0
        for match in MEMENTO_LINE.finditer(res.text[:500_000]):
            rel = match.group("rel") or ""
            if "memento" not in rel and "first" not in rel:
                continue
            when = parse_date(match.group("dt"))
            if not when:
                continue
            count += 1
            if earliest is None or when < earliest:
                earliest, earliest_url = when, match.group("url")
        if earliest:
            ctx.event(
                earliest, kind="archive-snapshot",
                label="Earliest memento capture across archives",
                detail=earliest_url, url=earliest_url,
                evidence_id=res.evidence_id, indicator_value=url,
                meta={"mementos": count},
            )
        else:
            ctx.partial("no mementos found")
        return ctx.result
