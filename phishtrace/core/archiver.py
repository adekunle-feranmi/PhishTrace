"""Archiving of posts and pages so evidence survives the campaign.

Phishing pages and the social posts that distribute them disappear quickly.
This module preserves what can be preserved, in two independent ways:

1. **Existing snapshots** — the Internet Archive availability API is queried for
   an already-existing capture. This is passive, free and always safe.
2. **Local snapshots** — when the isolated fetcher is enabled, a page may be
   fetched through it and stored gzip-compressed with a SHA-256 sidecar in
   ``data_dir/archive``. This is the only path that contacts infrastructure and
   it is therefore gated behind ``fetcher.active_fetch``.

``save_page_now`` exists but is off by default: it asks the Internet Archive to
fetch the page on our behalf and is heavily rate-limited upstream. When enabled
and rejected, the failure is recorded as a reason, never as a silent success.

Nothing here invents a snapshot URL: a result is only marked ``archived`` when
a URL or a local file actually exists.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import quote

from phishtrace.config import Config
from phishtrace.core.http import EvidenceRecorder, ProviderHTTP, TTLCache, make_client
from phishtrace.core.limits import Budget, RateLimiter
from phishtrace.models import iso, utcnow


@dataclass
class ArchiveResult:
    url: str
    status: str = "unavailable"  # archived | existing | unavailable | denied | error | disabled
    snapshot_url: str | None = None
    local_path: str | None = None
    sha256: str | None = None
    source: str = "none"  # wayback-lookup | wayback-save | local-fetch
    reason: str | None = None
    evidence_id: str | None = None
    retrieved_at: str | None = None
    size_bytes: int = 0

    @property
    def ok(self) -> bool:
        return bool(self.snapshot_url or self.local_path)

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "snapshot_url": self.snapshot_url,
            "local_path": self.local_path,
            "sha256": self.sha256,
            "source": self.source,
            "reason": self.reason,
            "evidence_id": self.evidence_id,
            "retrieved_at": self.retrieved_at,
            "size_bytes": self.size_bytes,
        }


class Archiver:
    """Best-effort, evidence-recording archiver for one investigation."""

    def __init__(
        self,
        config: Config,
        repo,
        investigation_id: str,
        *,
        transport=None,
        fetcher=None,
        logger: Callable[[str], None] | None = None,
    ):
        self.config = config
        self.repo = repo
        self.investigation_id = investigation_id
        self.transport = transport
        self.fetcher = fetcher
        self.log = logger or (lambda message: None)
        self.settings = config.archiver
        self._client = None
        self._http: ProviderHTTP | None = None
        self.saved = 0

    # ------------------------------------------------------------------ lifecycle
    async def _ensure_http(self) -> ProviderHTTP:
        if self._http is not None:
            return self._http
        self._client = make_client(self.config, transport=self.transport)
        store = getattr(self.repo, "evidence_store", None)
        recorder = EvidenceRecorder(store, self.repo, self.investigation_id) if store else None
        self._http = ProviderHTTP(
            provider="archiver",
            client=self._client,
            limiter=RateLimiter(1.0, burst=1),
            budget=Budget(
                global_limit=max(10, int(self.config.limits.global_request_budget) // 10),
                per_provider_limit=8,
            ),
            recorder=recorder,
            config=self.config,
            cache=TTLCache(max_items=64),
        )
        return self._http

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None
                self._http = None

    # ------------------------------------------------------------------- lookups
    async def lookup(self, url: str) -> ArchiveResult:
        """Return the closest *existing* Internet Archive capture, if any."""
        result = ArchiveResult(url=url, source="wayback-lookup")
        if not self.settings.enabled or not self.settings.lookup_existing:
            result.status = "disabled"
            result.reason = "archiver disabled in config"
            return result
        http = await self._ensure_http()
        endpoint = (
            "https://archive.org/wayback/available?url="
            + quote(url, safe="")
            + "&timestamp="
            + utcnow().strftime("%Y%m%d")
        )
        try:
            res = await http.get_json(
                endpoint,
                timeout=self.settings.timeout,
                cache_key="wayback-available:" + url,
                cache_ttl=3600.0,
            )
        except Exception as exc:  # noqa: BLE001 - archiving must never break a run
            result.status = "error"
            result.reason = f"{type(exc).__name__}: {exc}"[:300]
            return result
        result.evidence_id = res.evidence_id
        result.retrieved_at = iso(utcnow())
        if not res.ok:
            result.status = "error"
            result.reason = (res.error or f"HTTP {res.status}")[:300]
            return result
        data = res.data if isinstance(res.data, dict) else {}
        snapshots = data.get("archived_snapshots") or {}
        closest = snapshots.get("closest") if isinstance(snapshots, dict) else None
        if isinstance(closest, dict) and closest.get("url"):
            if str(closest.get("status", "200")) == "200":
                result.snapshot_url = str(closest["url"])
                result.status = "existing"
                return result
            result.reason = f"closest capture has status {closest.get('status')}"
            result.status = "unavailable"
            return result
        result.status = "unavailable"
        result.reason = "no existing capture"
        return result

    async def save_page_now(self, url: str) -> ArchiveResult:
        """Ask the Internet Archive to capture the page (opt-in, rate-limited)."""
        result = ArchiveResult(url=url, source="wayback-save")
        if not self.settings.save_page_now:
            result.status = "disabled"
            result.reason = "archiver.save_page_now is disabled (opt-in)"
            return result
        if self.saved >= int(self.settings.max_snapshots):
            result.status = "denied"
            result.reason = f"max_snapshots={self.settings.max_snapshots} reached"
            return result
        http = await self._ensure_http()
        endpoint = "https://web.archive.org/save/" + quote(url, safe=":/?&=%#")
        try:
            res = await http.request("GET", endpoint, timeout=max(30.0, self.settings.timeout))
        except Exception as exc:  # noqa: BLE001
            result.status = "error"
            result.reason = f"{type(exc).__name__}: {exc}"[:300]
            return result
        result.evidence_id = res.evidence_id
        result.retrieved_at = iso(utcnow())
        if res.status in {200, 201, 302}:
            location = (res.headers or {}).get("content-location") or (res.headers or {}).get("location")
            if location:
                result.snapshot_url = (
                    location if location.startswith("http") else "https://web.archive.org" + location
                )
                result.status = "archived"
                self.saved += 1
            else:
                result.status = "unavailable"
                result.reason = "save accepted but no capture URL returned"
        elif res.status == 429:
            result.status = "denied"
            result.reason = "Internet Archive rate limit (429)"
        else:
            result.status = "error"
            result.reason = f"save returned HTTP {res.status}"
        return result

    # ------------------------------------------------------------ local snapshot
    def _archive_path(self, sha256: str) -> Path:
        return Path(self.config.archive_dir) / sha256[:2] / f"{sha256}.html.gz"

    async def local_snapshot(self, url: str) -> ArchiveResult:
        """Fetch a page through the isolated fetcher and gzip it to disk."""
        result = ArchiveResult(url=url, source="local-fetch")
        if not self.settings.enabled or not self.settings.local_snapshot:
            result.status = "disabled"
            result.reason = "local snapshot disabled in config"
            return result
        if self.fetcher is None or not getattr(self.config.fetcher, "active_fetch", False):
            result.status = "denied"
            result.reason = "fetcher.active_fetch is disabled; refusing to contact the page"
            return result
        try:
            page = await self.fetcher.fetch(url, provider="archiver", note="local archive snapshot")
        except Exception as exc:  # noqa: BLE001
            result.status = "error"
            result.reason = f"{type(exc).__name__}: {exc}"[:300]
            return result
        if page is None:
            result.status = "error"
            result.reason = "fetcher returned no page"
            return result

        if isinstance(page, dict):
            body = page.get("content") or page.get("body") or b""
            status_code = page.get("status_code") or page.get("status")
            content_type = page.get("content_type")
            evidence_id = page.get("evidence_id")
            final_url = page.get("url", url)
        else:
            body = getattr(page, "content", None) or getattr(page, "body", b"") or b""
            status_code = getattr(page, "status_code", None)
            content_type = getattr(page, "content_type", None)
            evidence_id = getattr(page, "evidence_id", None)
            final_url = getattr(page, "url", url)
        if isinstance(body, str):
            body = body.encode("utf-8", "replace")
        if not body:
            result.status = "error"
            result.reason = "empty response body"
            return result

        digest = hashlib.sha256(body).hexdigest()
        path = self._archive_path(digest)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # mtime=0 keeps the gzip deterministic, so the same page always hashes
            # to the same file and re-archiving is idempotent.
            with gzip.GzipFile(filename=str(path), mode="wb", mtime=0) as handle:
                handle.write(body)
            sidecar = path.with_suffix(".json")
            sidecar.write_text(
                json.dumps(
                    {
                        "url": url,
                        "final_url": final_url,
                        "sha256": digest,
                        "size_bytes": len(body),
                        "status_code": status_code,
                        "content_type": content_type,
                        "evidence_id": evidence_id,
                        "retrieved_at": iso(utcnow()),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            result.status = "error"
            result.reason = f"cannot write archive file: {exc}"[:300]
            return result
        result.local_path = str(path)
        result.sha256 = digest
        result.size_bytes = len(body)
        result.evidence_id = evidence_id
        result.status = "archived"
        result.retrieved_at = iso(utcnow())
        return result

    # ------------------------------------------------------------------ public API
    async def archive(self, url: str, *, local: bool = True) -> ArchiveResult:
        """Lookup first, then optionally capture locally. Lookup wins on ties."""
        existing = await self.lookup(url)
        if existing.ok:
            return existing
        if local and self.fetcher is not None and getattr(self.config.fetcher, "active_fetch", False):
            local_result = await self.local_snapshot(url)
            if local_result.ok:
                return local_result
            if local_result.reason and not existing.reason:
                existing.reason = local_result.reason
        if self.settings.save_page_now:
            saved = await self.save_page_now(url)
            if saved.ok:
                return saved
            if saved.reason and not existing.reason:
                existing.reason = saved.reason
        return existing

    async def archive_sightings(
        self,
        sightings: Iterable[dict],
        *,
        limit: int | None = None,
        local: bool = True,
    ) -> dict[str, Any]:
        """Attach snapshot URLs/paths to stored sightings. Never raises."""
        started = time.monotonic()
        cap = int(limit if limit is not None else self.settings.max_snapshots)
        summary: dict[str, Any] = {
            "requested": 0,
            "archived": 0,
            "existing": 0,
            "unavailable": 0,
            "errors": 0,
            "skipped": 0,
            "results": [],
            "warnings": [],
            "duration_ms": 0,
        }
        if not self.settings.enabled:
            summary["warnings"].append("archiver disabled in config")
            return summary
        for sighting in list(sightings)[:cap]:
            url = sighting.get("post_url")
            if not url:
                summary["skipped"] += 1
                continue
            if sighting.get("archive_snapshot_url") or sighting.get("local_archive_path"):
                summary["skipped"] += 1
                continue
            summary["requested"] += 1
            result = await self.archive(url, local=local)
            summary["results"].append(result.as_dict())
            if result.ok:
                summary["archived" if result.status == "archived" else "existing"] += 1
                self.repo.update_sighting_archive(sighting["id"], result.snapshot_url, result.local_path)
            elif result.status == "error":
                summary["errors"] += 1
                if result.reason and result.reason not in summary["warnings"]:
                    summary["warnings"].append(f"{url}: {result.reason}"[:300])
            else:
                summary["unavailable"] += 1
        summary["duration_ms"] = int((time.monotonic() - started) * 1000)
        await self.close()
        return summary

    async def archive_urls(
        self,
        urls: Iterable[tuple[str, str | None]],
        *,
        limit: int | None = None,
    ) -> dict[str, Any]:
        """Archive a handful of important URLs (seed URL, kit URLs).

        ``urls`` is an iterable of ``(url, label)`` pairs.
        """
        started = time.monotonic()
        cap = int(limit if limit is not None else self.settings.max_snapshots)
        results = []
        for url, label in list(urls)[:cap]:
            if not url:
                continue
            result = await self.archive(url)
            item = result.as_dict()
            item["label"] = label
            results.append(item)
        await self.close()
        return {
            "results": results,
            "archived": sum(1 for r in results if r["status"] == "archived"),
            "existing": sum(1 for r in results if r["status"] == "existing"),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
