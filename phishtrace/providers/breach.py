"""Breach-data providers (Phase B, gated).

DeHashed and IntelX were tracked as "require legal review before any code
lands" in docs/PROVIDERS.md.  The code is now provided, but both providers are
inert on three levels:

1. ``enabled: false`` in config.yaml - the operator must switch it on;
2. ``legal_acknowledged`` must be set to ``true`` in the provider options
   (``can_run`` refuses to run while the acknowledgement is missing);
3. both keys must be present in ``.env``.

When they do run, attribution output is deliberately conservative: breach
records become *context-only* observations (they never drive expansion) plus
timeline events.  Everything degrades to ``ctx.partial`` on API errors.
"""

from __future__ import annotations

import asyncio
import base64

from phishtrace.models import SelectorStrength
from phishtrace.providers._util import (
    as_int, as_list, first, parse_date, result_error, safe_domain, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta
from phishtrace.providers.keyed import _KeyedProvider

MAX_ENTRIES = 40


# --------------------------------------------------------------------------- #
# DeHashed
# --------------------------------------------------------------------------- #
class DeHashedProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="dehashed",
        phase="B",
        accepts=("email", "username", "domain", "phone"),
        emits=("email", "username"),
        api_keys=("DEHASHED_API_KEY",),
        rate_limit=0.5,
        timeout=45.0,
        reliability=0.7,
        category="breach-data",
        description="DeHashed breach search: exposure records for emails, usernames, domains and phones",
        legal_note="Breach datasets contain third-party personal data; confirm your lawful basis before enabling",
        homepage="https://www.dehashed.com/",
        cache_ttl=86400.0,
    )

    def missing_keys(self, config) -> list[str]:
        missing = super().missing_keys(config)
        if not (self.options.get("username") or config.has_key("DEHASHED_EMAIL")):
            missing.append("DEHASHED_EMAIL")
        return missing

    def _query(self, indicator) -> str | None:
        if indicator.type == "email":
            return f"email:{indicator.normalized}"
        if indicator.type == "username":
            return f"username:{indicator.normalized}"
        if indicator.type == "domain":
            return f"domain:{indicator.normalized}"
        if indicator.type == "phone":
            digits = "".join(character for character in indicator.normalized if character.isdigit())
            return f"phone:{digits}" if digits else None
        return None

    async def run(self, ctx):
        key = self.key(ctx.config)
        username = self.options.get("username") or ctx.config.api_key("DEHASHED_EMAIL")
        if not key or not username:
            ctx.partial("dehashed: DEHASHED_API_KEY / DEHASHED_EMAIL not configured")
            return ctx.result
        query = self._query(ctx.indicator)
        if not query:
            ctx.partial(f"dehashed does not accept {ctx.indicator.type} indicators")
            return ctx.result
        token = base64.b64encode(f"{username}:{key}".encode()).decode()
        res = await ctx.http.get_json(
            "https://api.dehashed.com/search",
            params={"query": query, "size": 100, "page": 1},
            headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
            timeout=45.0, max_bytes=8_000_000,
            cache_key=f"dehashed:{query}", cache_ttl=86400.0,
        )
        if not res.ok:
            ctx.partial(f"dehashed unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        if data.get("success") is False:
            ctx.partial(f"dehashed rejected the query: {text(data.get('message')) or 'unknown error'}")
            return ctx.result
        entries = as_list(first(data, "entries", "records", default=[]))
        total = as_int(first(data, "count", "total"), len(entries))
        if not entries:
            ctx.result.notes.append(f"dehashed: no breach records for {query}")
            return ctx.result
        databases: list[str] = []
        emails = 0
        usernames = 0
        for entry in entries[:MAX_ENTRIES]:
            if not isinstance(entry, dict):
                continue
            database = text(first(entry, "database", "breach", "source"))
            if database and database not in databases and len(databases) < 10:
                databases.append(database)
            email = text(first(entry, "email")).lower()
            if "@" in email and 0 < len(email) < 320 and emails < MAX_ENTRIES:
                emails += 1
                ctx.emit(
                    "email", email, "breach-exposure", SelectorStrength.WEAK,
                    evidence_id=res.evidence_id, tags=["dehashed", "breach"],
                    context_only=True, meta={"database": database},
                    note="Address found in breach data; verify before contacting",
                )
            username_value = text(first(entry, "username", "login"))
            if username_value and len(username_value) < 200 and usernames < MAX_ENTRIES:
                usernames += 1
                ctx.emit(
                    "username", username_value, "breach-exposure", SelectorStrength.WEAK,
                    evidence_id=res.evidence_id, tags=["dehashed", "breach"],
                    context_only=True, meta={"database": database},
                    note="Username found in breach data",
                )
        for database in databases:
            ctx.event(
                ctx.now(), kind="breach-records",
                label=f"DeHashed: records in '{database}' for {query}",
                detail=f"total={total}",
                evidence_id=res.evidence_id, precision="day",
                indicator_value=ctx.indicator.normalized,
                meta={"database": database, "total": total},
            )
        return ctx.result


# --------------------------------------------------------------------------- #
# Intelligence X
# --------------------------------------------------------------------------- #
class IntelXProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="intelx",
        phase="B",
        accepts=("email", "domain", "url", "file_hash", "phone", "username"),
        emits=(),
        api_keys=("INTELX_API_KEY",),
        rate_limit=0.5,
        timeout=60.0,
        reliability=0.7,
        category="breach-data",
        description="Intelligence X selector search: leaked/archived documents matching the indicator",
        legal_note="Intelligence X indexes leaked and archived documents; enable only after legal review",
        homepage="https://intelx.io/",
        cache_ttl=3600.0,
    )

    def _base(self) -> str:
        return str(self.options.get("api_base") or "https://free.intelx.io").rstrip("/")

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("INTELX_API_KEY not configured")
            return ctx.result
        term = ctx.indicator.normalized
        if ctx.indicator.type == "phone":
            digits = "".join(character for character in term if character.isdigit())
            if not digits:
                ctx.partial("intelx: unusable phone number")
                return ctx.result
            term = f"+{digits}"
        headers = {"x-key": key, "Content-Type": "application/json"}
        search = await ctx.http.post_json(
            f"{self._base()}/intelligent/search",
            json_body={"term": term, "maxresults": 25, "media": 0, "sort": 4, "terminate": []},
            headers=headers, timeout=45.0, max_bytes=2_000_000,
            cache_key=f"intelx:start:{term}", cache_ttl=3600.0,
        )
        if not search.ok:
            ctx.partial(f"intelx search rejected: {result_error(search)}")
            return ctx.result
        data = search.data if isinstance(search.data, dict) else {}
        search_id = text(first(data, "id"))
        if not search_id:
            ctx.partial(f"intelx returned no search id (status={text(data.get('status')) or '?'})")
            return ctx.result
        records: list[dict] = []
        final_status = None
        poll_evidence_id = search.evidence_id
        for attempt in range(4):
            result = await ctx.http.get_json(
                f"{self._base()}/intelligent/search/result",
                params={"id": search_id, "limit": 25, "previewlines": 0, "statistics": 0},
                headers={"x-key": key, "Accept": "application/json"},
                timeout=45.0, max_bytes=4_000_000,
                cache_key=f"intelx:poll:{search_id}:{attempt}", cache_ttl=60.0,
            )
            if not result.ok:
                ctx.partial(f"intelx result fetch failed: {result_error(result)}")
                return ctx.result
            payload = result.data if isinstance(result.data, dict) else {}
            poll_evidence_id = result.evidence_id or poll_evidence_id
            final_status = as_int(payload.get("status"), -1)
            if final_status == 3:
                # "no results available but keep trying" - short backoff, re-poll.
                await asyncio.sleep(1.0)
                continue
            if final_status == 0:
                records = [row for row in as_list(payload.get("records")) if isinstance(row, dict)]
            break
        if final_status == 3:
            ctx.partial("intelx: search still processing after 4 polls; retry later")
            return ctx.result
        if not records:
            ctx.result.notes.append(f"intelx: no records for {term}")
            return ctx.result
        for record in records[:25]:
            system_id = text(first(record, "systemid"))
            name = text(first(record, "name"))
            if not name:
                continue
            ctx.event(
                parse_date(first(record, "date", "added")), kind="intelx-result",
                label=f"IntelX: {name[:180]}",
                detail=f"bucket={text(record.get('bucket'))} type={text(record.get('type'))}",
                url=f"https://intelx.io/?did={system_id}" if system_id else None,
                evidence_id=poll_evidence_id,
                precision="day", indicator_value=term,
                meta={"systemid": system_id, "bucket": text(record.get("bucket")),
                      "storageid": text(record.get("storageid"))},
            )
        ctx.event(
            ctx.now(), kind="intelx-summary",
            label=f"IntelX: {len(records)} records for {term}",
            detail=f"records={len(records)}",
            evidence_id=search.evidence_id, precision="day", indicator_value=term,
            meta={"records": len(records)},
        )
        return ctx.result
