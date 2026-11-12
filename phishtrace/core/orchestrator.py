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
from phishtrace.core.archiver import Archiver
from phishtrace.core.http import ProviderHTTP, make_client
from phishtrace.core.limits import Budget, RateLimiter
from phishtrace.core.pivot import PivotEngine
from phishtrace.core.registry import Registry
from phishtrace.core.sightings import SightingsEngine
from phishtrace.core.stoplist import StopList
from phishtrace.core.timeline import TimelineMerger, derive_events_from_sightings
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
        return await self.run_existing(seed, investigation, run_sightings=run_sightings)

    async def run_existing(
        self,
        seed: NormalizedIndicator,
        investigation: dict,
        *,
        run_sightings: bool = True,
    ) -> dict:
        """Run the pivot and post-processing stages for an existing investigation.

        Used by the web console, which creates the investigation row first so the
        browser can subscribe to live progress before the slow work starts.
        """
        self._emit("run.start", investigation_id=investigation["id"], seed=seed.normalized)
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
            self._emit("run.failed", investigation_id=investigation["id"], error=_error_text(exc))
            raise
        self._emit("stage.pivot", investigation_id=investigation["id"],
                   indicators=self.repo.counts(investigation["id"])["indicators"])
        sightings_summary = None
        archive_summary = None
        if run_sightings:
            self._emit("stage.sightings", investigation_id=investigation["id"])
            sightings_summary, archive_summary = await self._post_stages(engine, seed)
            self._emit("stage.archive", investigation_id=investigation["id"],
                       archived=(archive_summary or {}).get("archived", 0))
        counts = self.repo.counts(investigation["id"])
        coverage = engine.coverage()
        timeline = TimelineMerger(self.repo, investigation["id"]).build()
        coverage["timeline"] = timeline.coverage
        summary = self._summary(seed, counts, engine, coverage, int((time.monotonic() - started) * 1000))
        summary["timeline"] = {
            "earliest_observed": (timeline.earliest_observed or {}).get("occurred_at"),
            "earliest_label": (timeline.earliest_observed or {}).get("label"),
            "earliest_stage": (timeline.earliest_observed or {}).get("stage"),
            "stages": {stage: bucket.get("earliest_observed") for stage, bucket in timeline.stages.items()},
            "event_count": len(timeline.rows),
            "precision": timeline.precision,
            "gaps": timeline.gaps[:10],
            "wording": timeline.wording,
        }
        if sightings_summary is not None:
            summary["sightings"] = sightings_summary.as_dict()
        if archive_summary is not None:
            summary["archive"] = {
                "requested": archive_summary.get("requested", 0),
                "archived": archive_summary.get("archived", 0),
                "existing": archive_summary.get("existing", 0),
                "unavailable": archive_summary.get("unavailable", 0),
                "errors": archive_summary.get("errors", 0),
            }
        warnings = list(engine.warnings)
        for extra in ((sightings_summary.warnings if sightings_summary else []) +
                      (archive_summary.get("warnings", []) if archive_summary else [])):
            if extra not in warnings:
                warnings.append(extra)
        summary["warnings"] = warnings[:50]
        status = "partial" if stats.truncated else "completed"
        self.repo.finalize(
            investigation["id"],
            status=status,
            coverage=coverage,
            stats=stats.as_dict(),
            summary=summary,
        )
        self._emit("run.finalized", investigation_id=investigation["id"], status=status)
        current = self.repo.get_investigation(investigation["id"]) or investigation
        return self._result(current, reused=False, counts=counts, coverage=coverage, warnings=warnings)

    async def _post_stages(self, engine: PivotEngine, seed: NormalizedIndicator):
        """Run the stages that depend on a finished pivot: sightings, archive, roles."""
        sightings_engine = SightingsEngine(
            self.config,
            self.registry,
            self.repo,
            engine.investigation_id,
            transport=self.transport,
            logger=self.logger,
            max_concurrency=self.max_provider_concurrency,
        )
        sightings = await sightings_engine.collect(seed, variants=seed.variants)
        for name in sightings.providers_ran:
            status = self.registry.status(name)
            engine.note_external_run(
                name,
                requests=int(getattr(status, "requests", 0) or 0),
                stage="sightings",
            )
        for item in sightings.providers_failed:
            engine.note_external_run(
                item["provider"], error=item.get("reason") or "sighting provider failed", stage="sightings"
            )

        stored = self.repo.list_sightings(engine.investigation_id)
        for event in derive_events_from_sightings(stored):
            try:
                self.repo.add_event(engine.investigation_id, event)
            except Exception:  # noqa: BLE001 - timeline enrichment must not fail a run
                pass

        archive_summary = None
        if self.config.archiver.enabled and getattr(self.config.limits, "archive_sightings", True) and stored:
            archiver = Archiver(
                self.config,
                self.repo,
                engine.investigation_id,
                transport=self.transport,
                fetcher=self.fetcher,
                logger=self.logger,
            )
            try:
                archive_summary = await archiver.archive_sightings(
                    stored, limit=min(len(stored), int(self.config.archiver.max_snapshots))
                )
            except Exception as exc:  # noqa: BLE001
                archive_summary = {"warnings": [f"archiver failed: {type(exc).__name__}: {exc}"[:300]]}
        return sightings, archive_summary

    def run_seed_sync(self, raw_seed: str, **kwargs) -> dict:
        """Small convenience wrapper for scripts and tests."""
        return asyncio.run(self.run_seed(raw_seed, **kwargs))

    # -------------------------------------------------------------------- helpers
    def _emit(self, event: str, **payload) -> None:
        """Publish a lifecycle event without letting a UI callback break the run."""
        if not self.progress:
            return
        try:
            self.progress({"event": event, "at": iso(utcnow()), **payload})
        except Exception:  # noqa: BLE001 - progress reporting is best effort
            pass

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
