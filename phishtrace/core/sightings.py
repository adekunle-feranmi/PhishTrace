"""Sightings engine: the human side of a campaign.

Pivot providers answer "what infrastructure is connected?". Sighting providers
answer "who talked about it, when, and in what role?". They are separated
because they are slow, rate-limited, and often the most legally sensitive part
of an investigation: they read public posts, nothing else.

Guarantees
----------
* Only providers that declare ``supports_sightings`` and are enabled are run.
* Each provider is isolated: its own timeout, its own request budget slice, its
  own evidence recorder. One dead platform never blocks the rest.
* The configured ``max_sightings`` cap is applied to the **earliest** posts, so
  a flood of recent chatter can never bury the first mention.
* Roles are assigned per author cluster across everything collected, then
  stored on each sighting with the signals that produced them.
* Re-running the same investigation does not duplicate sightings: the store's
  unique ``dedupe_key`` (platform + post identity) absorbs repeats.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from phishtrace.config import Config
from phishtrace.core.http import EvidenceRecorder, ProviderHTTP, TTLCache, make_client
from phishtrace.core.limits import Budget, RateLimiter
from phishtrace.core.registry import Registry
from phishtrace.core.roles import RoleAssessment, classify_sightings, summarize_roles
from phishtrace.models import NormalizedIndicator, SightingDraft, iso, utcnow
from phishtrace.providers.context import ProviderContext


@dataclass
class SightingsSummary:
    collected: int = 0
    stored: int = 0
    suppressed: int = 0
    providers_ran: list[str] = field(default_factory=list)
    providers_skipped: list[dict] = field(default_factory=list)
    providers_failed: list[dict] = field(default_factory=list)
    platforms: dict[str, int] = field(default_factory=dict)
    roles: dict[str, int] = field(default_factory=dict)
    earliest_observed: str | None = None
    earliest_by_platform: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    duration_ms: int = 0
    capped: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "collected": self.collected,
            "stored": self.stored,
            "suppressed_by_cap": self.suppressed,
            "capped": self.capped,
            "providers_ran": list(self.providers_ran),
            "providers_skipped": list(self.providers_skipped),
            "providers_failed": list(self.providers_failed),
            "platforms": dict(self.platforms),
            "roles": dict(self.roles),
            "earliest_observed": self.earliest_observed,
            "earliest_by_platform": dict(self.earliest_by_platform),
            "warnings": list(self.warnings),
            "duration_ms": self.duration_ms,
        }


def _sort_key(draft: SightingDraft) -> tuple:
    """Earliest first; undated posts last but still deterministic."""
    posted = draft.posted_at
    return (
        posted is None,
        posted.timestamp() if posted else float("inf"),
        draft.platform or "",
        draft.post_url or "",
    )


class SightingsEngine:
    """Collect, classify, cap and persist public social sightings."""

    def __init__(
        self,
        config: Config,
        registry: Registry,
        repo,
        investigation_id: str,
        *,
        transport=None,
        logger: Callable[[str], None] | None = None,
        max_concurrency: int = 3,
        budget: Budget | None = None,
    ):
        self.config = config
        self.registry = registry
        self.repo = repo
        self.investigation_id = investigation_id
        self.transport = transport
        self.log = logger or (lambda message: None)
        self.max_concurrency = max(1, int(max_concurrency))
        # Sightings get a slice of the global budget so they can never starve
        # the pivot stage that runs before them.
        self.budget = budget or Budget(
            max(20, int(config.limits.global_request_budget) // 4),
            min(10, max(2, int(config.limits.per_provider_budget))),
        )
        self._client = None
        self._limiters: dict[str, RateLimiter] = {}
        self._caches: dict[str, TTLCache] = {}

    # --------------------------------------------------------------------- public
    async def collect(
        self,
        indicator: NormalizedIndicator,
        *,
        variants: Iterable[dict] | None = None,
        limit: int | None = None,
    ) -> SightingsSummary:
        started = time.monotonic()
        summary = SightingsSummary()
        cap = int(limit if limit is not None else self.config.limits.max_sightings)
        cap = max(0, cap)

        candidates = []
        for provider in self.registry.all_providers():
            if not provider.meta.supports_sightings:
                continue
            status = self.registry.status(provider.meta.name)
            if status and status.status == "skipped":
                summary.providers_skipped.append({"provider": provider.meta.name, "reason": status.reason})
                continue
            if status and status.status == "failed":
                summary.providers_failed.append({"provider": provider.meta.name, "reason": status.error})
                continue
            candidates.append(provider)

        if not candidates:
            summary.duration_ms = int((time.monotonic() - started) * 1000)
            summary.warnings.append("no enabled sighting-capable provider")
            return summary

        self._client = make_client(self.config, transport=self.transport)
        semaphore = asyncio.Semaphore(self.max_concurrency)
        variant_list = list(variants if variants is not None else indicator.variants)

        async def guarded(provider):
            async with semaphore:
                return await self._run_provider(provider, indicator, variant_list, summary)

        results = await asyncio.gather(*(guarded(p) for p in candidates), return_exceptions=True)
        drafts: list[SightingDraft] = []
        for provider, result in zip(candidates, results):
            if isinstance(result, BaseException):
                summary.providers_failed.append(
                    {"provider": provider.meta.name, "reason": f"{type(result).__name__}: {result}"[:300]}
                )
                continue
            if result:
                drafts.extend(result)

        summary.collected = len(drafts)
        if not drafts:
            summary.duration_ms = int((time.monotonic() - started) * 1000)
            await self._close()
            return summary

        # Classify across all collected posts before capping: role evidence is
        # stronger with the full author history in view.
        classify_sightings(drafts)

        ordered = sorted(drafts, key=_sort_key)
        selected = ordered[:cap] if cap else []
        summary.roles = summarize_roles(_assessments_for(selected))
        summary.suppressed = max(0, len(ordered) - len(selected))
        summary.capped = summary.suppressed > 0
        if summary.capped:
            summary.warnings.append(
                f"max_sightings={cap} applied to the earliest posts; {summary.suppressed} later sighting(s) not stored"
            )

        node_index = self._indicator_index()
        earliest: dict[str, str] = {}
        for draft in selected:
            payload = self._payload(draft, node_index)
            try:
                _sighting_id, created = self.repo.add_sighting(self.investigation_id, payload)
            except Exception as exc:  # noqa: BLE001 - one bad post must not stop storage
                summary.warnings.append(f"could not store sighting {draft.post_url}: {type(exc).__name__}: {exc}"[:300])
                continue
            if created:
                summary.stored += 1
            platform = draft.platform or "unknown"
            summary.platforms[platform] = summary.platforms.get(platform, 0) + 1
            posted = iso(draft.posted_at) if draft.posted_at else None
            if posted:
                if platform not in earliest or posted < earliest[platform]:
                    earliest[platform] = posted

        summary.earliest_by_platform = dict(sorted(earliest.items()))
        summary.earliest_observed = min(earliest.values()) if earliest else None
        summary.duration_ms = int((time.monotonic() - started) * 1000)
        await self._close()
        return summary

    # ------------------------------------------------------------------ internals
    async def _close(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            finally:
                self._client = None

    def _indicator_index(self) -> dict[str, str]:
        """Map every stored indicator form to its node id for attribution."""
        index: dict[str, str] = {}
        try:
            graph = self.repo.graph(self.investigation_id)
        except Exception:  # noqa: BLE001
            return index
        for node in graph.get("nodes", []):
            for form in (node.get("normalized_value"), node.get("value")):
                if form:
                    index[str(form).strip().lower()] = node["id"]
            for variant in (node.get("meta") or {}).get("variants") or []:
                value = variant.get("value") if isinstance(variant, dict) else None
                if value:
                    index[str(value).strip().lower()] = node["id"]
        return index

    def _payload(self, draft: SightingDraft, node_index: dict[str, str]) -> dict:
        form = (draft.indicator_form_matched or "").strip()
        return {
            "indicator_id": node_index.get(form.lower()) if form else None,
            "indicator_form_matched": form,
            "platform": draft.platform,
            "post_url": draft.post_url,
            "post_id": draft.post_id,
            "author_handle": draft.author_handle,
            "author_id": draft.author_id,
            "author_created_at": draft.author_created_at,
            "posted_at": draft.posted_at,
            "retrieved_at": utcnow(),
            "text_excerpt": (draft.text or "")[:600],
            "role": draft.role,
            "archive_snapshot_url": draft.archive_snapshot_url,
            "local_archive_path": draft.local_archive_path,
            "evidence_id": draft.evidence_id,
            "meta": {
                **(draft.meta or {}),
                "adapter": draft.adapter,
                "collected_by": "sightings_engine",
            },
        }

    async def _run_provider(
        self,
        provider,
        indicator: NormalizedIndicator,
        variants: list[dict],
        summary: SightingsSummary,
    ) -> list[SightingDraft]:
        name = provider.meta.name
        limiter = self._limiters.setdefault(name, RateLimiter(provider.effective_rate_limit(), burst=1))
        cache = self._caches.setdefault(name, TTLCache(max_items=64))
        store = getattr(self.repo, "evidence_store", None)
        recorder = EvidenceRecorder(store, self.repo, self.investigation_id) if store else None
        http = ProviderHTTP(
            provider=name,
            client=self._client,
            limiter=limiter,
            budget=self.budget,
            recorder=recorder,
            config=self.config,
            cache=cache,
        )
        ctx = ProviderContext(
            provider=provider,
            config=self.config,
            http=http,
            indicator=indicator,
            variants=variants,
            investigation_id=self.investigation_id,
            options=provider.options,
            logger=self.log,
        )
        started = time.monotonic()
        error: str | None = None
        try:
            await asyncio.wait_for(provider.sightings(ctx, variants), timeout=provider.effective_timeout())
        except asyncio.TimeoutError:
            error = f"timeout after {provider.effective_timeout():.0f}s"
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a platform failure is data, not a crash
            error = f"{type(exc).__name__}: {exc}"[:300]
        duration_ms = int((time.monotonic() - started) * 1000)

        for note in list(ctx.result.notes) + list(ctx.result.errors):
            entry = f"{name}: {note}"
            if entry not in summary.warnings:
                summary.warnings.append(entry[:300])
        if error:
            summary.providers_failed.append({"provider": name, "reason": error})
        else:
            summary.providers_ran.append(name)

        try:
            self.repo.record_provider_run(
                self.investigation_id,
                provider=name,
                status="failed" if error else "ran",
                reason=error,
                category=provider.meta.category,
                requests=http.requests,
                observations=0,
                sightings=len(ctx.result.sightings),
                errors=[error] if error else list(ctx.result.errors),
                duration_ms=duration_ms,
                extra={
                    "stage": "sightings",
                    "partial": ctx.result.partial,
                    "notes": list(ctx.result.notes),
                },
            )
        except Exception as exc:  # noqa: BLE001
            summary.warnings.append(f"could not record provider run for {name}: {exc}"[:200])
        try:
            self.registry.mark_ran(
                name,
                requests=http.requests,
                observations=0,
                sightings=len(ctx.result.sightings),
                duration_ms=duration_ms,
                error=error,
            )
        except Exception:  # noqa: BLE001
            pass
        return list(ctx.result.sightings)


def _assessments_for(drafts: Iterable[SightingDraft]) -> list[RoleAssessment]:
    """One lightweight assessment per post, carrying its assigned role."""
    return [RoleAssessment(role=d.role or "unknown", confidence=0.0) for d in drafts]


def role_breakdown(assessments: Iterable[RoleAssessment]) -> dict[str, int]:
    """Convenience wrapper used by reports and the UI."""
    return summarize_roles(assessments)
