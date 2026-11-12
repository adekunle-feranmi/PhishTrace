"""Investigation orchestration: normalize, run, persist, report readiness.

The runner is the single entry point used by the CLI and the web API. It owns
the investigation lifecycle (create -> run -> finalize), enforces seed-level
deduplication, and builds the coverage block that every report must show.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable

from phishtrace.config import Config
from phishtrace.core.http import ProviderHTTP, make_client
from phishtrace.core.limits import Budget, RateLimiter
from phishtrace.core.pivot import PivotEngine
from phishtrace.core.registry import Registry
from phishtrace.core.stoplist import StopList
from phishtrace.models import NormalizedIndicator, iso, utcnow
from phishtrace.normalizer import normalize_indicator
from phishtrace.providers.context import ProviderContext

REUSE_STATUSES = {"completed", "partial"}


def _error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:500]


class InvestigationRunner:
    """Run one seed end-to-end and persist the result."""

    def __init__(
        self,
        config: Config,
        repo,
        registry: Registry | None = None,
        *,
        transport=None,
        fetcher=None,
        progress: Callable[[dict], None] | None = None,
        logger: Callable[[str], None] | None = None,
        max_provider_concurrency: int = 4,
    ):
        self.config = config
        self.repo = repo
        self.registry = registry or Registry(config)
        self.transport = transport
        self.fetcher = fetcher
        self.progress = progress
        self.logger = logger
        self.max_provider_concurrency = max_provider_concurrency

    # --------------------------------------------------------------------- public
    async def run_seed(
        self,
        raw_seed: str,
        *,
        kind: str | None = None,
        reuse: bool = True,
        owner: str = "cli",
        run_sightings: bool = True,
    ) -> dict:
        """Normalize ``raw_seed`` and run a full investigation.

        When ``reuse`` is true and the same normalized seed already has a
        completed (or partially completed) investigation, that investigation
        is returned untouched. This is what makes re-running a seed
        idempotent for nodes, edges, sightings and evidence.
        """
        seed = normalize_indicator(
            raw_seed,
            kind=kind,
            default_region=getattr(self.config, "default_region", None) or "US",
        )
        if reuse:
            existing = self.repo.latest_for_seed(seed.normalized)
            if existing and existing.get("status") in REUSE_STATUSES:
                return self._result(existing, reused=True)
        investigation = self.repo.create_investigation(
            seed=str(raw_seed),
            seed_type=seed.type,
            seed_normalized=seed.normalized,
            config_snapshot=self.config.redacted(),
            owner=owner,
        )
        engine = PivotEngine(
            self.config,
            self.registry,
            self.repo,
            investigation["id"],
            transport=self.transport,
            fetcher=self.fetcher,
            stoplist=StopList.from_config(self.config),
            progress=self.progress,
            logger=self.logger,
            max_provider_concurrency=self.max_provider_concurrency,
            run_sightings=run_sightings,
        )
        started = time.monotonic()
        try:
            stats = await engine.run(seed)
        except Exception as exc:  # noqa: BLE001 - persist the failure, then surface it
            self.repo.finalize(
                investigation["id"],
                status="failed",
                coverage=engine.coverage(),
                stats=engine.stats.as_dict(),
                summary={"seed": self._seed_summary(seed), "error": _error_text(exc)},
                error=_error_text(exc),
            )
            raise
        counts = self.repo.counts(investigation["id"])
        coverage = engine.coverage()
        summary = self._summary(seed, counts, engine, coverage, int((time.monotonic() - started) * 1000))
        status = "partial" if stats.truncated else "completed"
        self.repo.finalize(
            investigation["id"],
            status=status,
            coverage=coverage,
            stats=stats.as_dict(),
            summary=summary,
        )
        current = self.repo.get_investigation(investigation["id"]) or investigation
        return self._result(current, reused=False, counts=counts, coverage=coverage, warnings=engine.warnings)

    def run_seed_sync(self, raw_seed: str, **kwargs) -> dict:
        """Small convenience wrapper for scripts and tests."""
        return asyncio.run(self.run_seed(raw_seed, **kwargs))

    # -------------------------------------------------------------------- helpers
    @staticmethod
    def _seed_summary(seed: NormalizedIndicator) -> dict:
        return {
            "value": seed.value,
            "type": seed.type,
            "normalized": seed.normalized,
            "display": seed.display,
        }

    def _summary(
        self,
        seed: NormalizedIndicator,
        counts: dict,
        engine: PivotEngine,
        coverage: dict,
        duration_ms: int,
    ) -> dict:
        return {
            "seed": self._seed_summary(seed),
            "headline": (
                f"{counts['indicators']} indicator(s), {counts['edges']} edge(s), "
                f"{counts['sightings']} sighting(s) from {len(coverage.get('ran', []))} provider(s)"
            ),
            "counts": counts,
            "providers_ran": coverage.get("ran", []),
            "providers_skipped": coverage.get("skipped", []),
            "providers_failed": coverage.get("failed", []),
            "stoplist_hits": engine.stats.stoplist_hits,
            "truncated": engine.stats.truncated,
            "budget": engine.budget.snapshot(),
            "duration_ms": duration_ms,
            "warnings": engine.warnings[:50],
            "generated_at": iso(utcnow()),
            "wording": {
                "timeline": "earliest observed",
                "note": "Timestamps are the earliest observation PhishTrace could verify; absence is not proof of non-existence.",
            },
        }

    def _result(
        self,
        investigation: dict,
        *,
        reused: bool,
        counts: dict | None = None,
        coverage: dict | None = None,
        warnings: list[str] | None = None,
    ) -> dict:
        counts = counts or self.repo.counts(investigation["id"])
        coverage = coverage or investigation.get("coverage") or {}
        stats = investigation.get("stats") or {}
        return {
            "investigation": investigation,
            "investigation_id": investigation["id"],
            "status": investigation.get("status"),
            "reused": reused,
            "counts": counts,
            "stats": stats,
            "coverage": coverage,
            "skipped": coverage.get("skipped", []),
            "failed": coverage.get("failed", []),
            "warnings": list(warnings or (investigation.get("summary") or {}).get("warnings") or []),
        }


async def validate_provider_keys(config: Config, registry: Registry) -> dict[str, tuple[bool, str]]:
    """Harmless, per-provider key check used by ``phishtrace doctor --validate``.

    Only providers that declare an API key are checked. Providers that have no
    remote healthcheck yet report their key presence honestly instead of
    pretending the key was verified.
    """
    results: dict[str, tuple[bool, str]] = {}
    client = make_client(config)
    try:
        for provider in registry.all_providers():
            name = provider.meta.name
            if not provider.meta.api_keys:
                continue
            status = registry.status(name)
            if status and status.status == "skipped":
                results[name] = (False, status.reason or "provider skipped")
                continue
            if status and status.status == "failed":
                results[name] = (False, status.error or "provider failed")
                continue
            http = ProviderHTTP(
                provider=name,
                client=client,
                limiter=RateLimiter(provider.effective_rate_limit()),
                budget=Budget(global_limit=100, per_provider_limit=4),
                recorder=None,
                config=config,
            )
            ctx = ProviderContext(provider=provider, config=config, http=http, options=provider.options)
            try:
                ok, message = await asyncio.wait_for(
                    provider.healthcheck(ctx),
                    timeout=min(20.0, provider.effective_timeout()),
                )
            except asyncio.TimeoutError:
                ok, message = False, "healthcheck timed out"
            except Exception as exc:  # noqa: BLE001 - doctor must report, not crash
                ok, message = False, _error_text(exc)
            results[name] = (bool(ok), str(message)[:300])
    finally:
        await client.aclose()
    return results
