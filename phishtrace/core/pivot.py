"""Bounded breadth-first pivot engine.

The engine turns one normalized seed selector into an evidence-backed graph.
Design rules, in order of importance:

1. **Never invent data.** Nodes and edges exist only because a provider
   returned an observation that normalized successfully.
2. **Stay bounded.** Depth, children per node, total nodes, global requests,
   per-provider requests and wall-clock time all have hard caps. Hitting a cap
   is recorded as a truncation reason, never hidden.
3. **Isolate failures.** A provider that raises, times out or exhausts its
   budget is recorded and skipped; the investigation continues. Three
   consecutive failures open a circuit breaker for that provider for the rest
   of the run.
4. **Do not mass-pivot on shared infrastructure.** Every discovered node is
   classified by :mod:`phishtrace.core.stoplist`. Stop-listed nodes are kept
   as context and never expanded. A stop-listed *seed* is still queried once
   (the analyst asked about it) but none of its children are expanded.
5. **Deduplicate.** All persistence goes through the repository's upserts, so
   re-running the same seed against the same investigation adds no duplicate
   nodes, edges or events.
"""

from __future__ import annotations

import asyncio
import heapq
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable

from phishtrace.config import Config
from phishtrace.core.http import EvidenceRecorder, ProviderHTTP, TTLCache, make_client
from phishtrace.core.limits import Budget, RateLimiter
from phishtrace.core.registry import Registry
from phishtrace.core.scoring import (
    DEFAULT_PATH_FLOOR, edge_confidence, path_confidence, should_expand, strength_rank,
)
from phishtrace.core.stoplist import StopDecision, StopList
from phishtrace.models import NormalizedIndicator, Observation, ProviderResult, iso, utcnow
from phishtrace.core.intake import plan_intake
from phishtrace.normalizer import normalize_indicator
from phishtrace.providers.base import BaseProvider
from phishtrace.providers.context import ProviderContext

# Expansion order: cheap, high-signal selectors first so a truncated run still
# produces the most useful graph.
TYPE_PRIORITY: dict[str, int] = {
    "url": 0,
    "domain": 1,
    "cert_sha256": 2,
    "analytics_id": 3,
    "telegram": 4,
    "email": 5,
    "phone": 6,
    "btc_address": 6,
    "file_hash": 7,
    "ip": 8,
    "nameserver": 9,
    "ja3": 10,
    "asn": 11,
    "username": 12,
    "unknown": 20,
}

SIGHTING_ONLY = "sighting-only"
SCHEMA_VERSION = 1


@dataclass
class EngineStats:
    nodes: int = 0
    edges: int = 0
    expanded: int = 0
    provider_runs: int = 0
    provider_failures: int = 0
    observations: int = 0
    duplicate_observations: int = 0
    invalid_observations: int = 0
    context_only: int = 0
    stoplist_hits: int = 0
    events: int = 0
    nodes_capped: int = 0
    children_capped: int = 0
    truncated: str | None = None
    duration_ms: int = 0
    budget: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "expanded": self.expanded,
            "provider_runs": self.provider_runs,
            "provider_failures": self.provider_failures,
            "observations": self.observations,
            "duplicate_observations": self.duplicate_observations,
            "invalid_observations": self.invalid_observations,
            "context_only": self.context_only,
            "stoplist_hits": self.stoplist_hits,
            "events": self.events,
            "nodes_capped": self.nodes_capped,
            "children_capped": self.children_capped,
            "truncated": self.truncated,
            "duration_ms": self.duration_ms,
            "budget": self.budget,
            "schema_version": SCHEMA_VERSION,
        }


@dataclass
class ProviderOutcome:
    provider: str
    status: str
    result: ProviderResult
    error: str | None = None
    duration_ms: int = 0
    requests: int = 0


@dataclass
class _Candidate:
    child: NormalizedIndicator
    observations: list[tuple[str, Observation]]
    decision: StopDecision
    context_only: bool
    confidence: float
    path: float
    strength: str


class PivotEngine:
    """One bounded pivot run over one investigation."""

    def __init__(
        self,
        config: Config,
        registry: Registry,
        repo,
        investigation_id: str,
        *,
        transport=None,
        fetcher=None,
        stoplist: StopList | None = None,
        progress: Callable[[dict], None] | None = None,
        logger: Callable[[str], None] | None = None,
        max_provider_concurrency: int = 4,
        run_sightings: bool = True,
    ):
        self.config = config
        self.registry = registry
        self.repo = repo
        self.investigation_id = investigation_id
        self.transport = transport
        self.fetcher = fetcher
        self.stoplist = stoplist or StopList.from_config(config)
        self.progress = progress
        self.log = logger or (lambda message: None)
        self.max_provider_concurrency = max(1, int(max_provider_concurrency))
        self.run_sightings = run_sightings

        self.budget = Budget(
            config.limits.global_request_budget,
            config.limits.per_provider_budget,
        )
        self.stats = EngineStats()
        self.warnings: list[str] = []
        self.activity: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"requests": 0, "observations": 0, "errors": [], "status": "pending", "duration_ms": 0}
        )

        self._client = None
        self._queue: list[tuple] = []
        self._seq = 0
        self._known: set[tuple[str, str]] = set()
        self._rows: dict[tuple[str, str], dict] = {}
        self._enqueued: set[tuple[str, str]] = set()
        self._expanded: set[tuple[str, str]] = set()
        self._limiters: dict[str, RateLimiter] = {}
        self._caches: dict[str, TTLCache] = {}
        self._failures: dict[str, int] = defaultdict(int)
        self._dead: set[str] = set()
        self._deadline = 0.0

    # ------------------------------------------------------------------ lifecycle
    async def run(self, seed: NormalizedIndicator) -> EngineStats:
        started = time.monotonic()
        self._deadline = started + max(30.0, float(self.config.limits.investigation_timeout_seconds))
        self._client = make_client(self.config, transport=self.transport)
        try:
            seed_row, created = self.repo.ensure_indicator(
                self.investigation_id,
                type=seed.type,
                value=seed.value,
                normalized_value=seed.normalized,
                depth=0,
                path_confidence=1.0,
                tags=list(seed.tags) + ["seed"],
                meta={
                    "seed": True,
                    "display": seed.display,
                    "variants": seed.variants[:12],
                },
            )
            if created:
                self.stats.nodes += 1
            self._known.add(seed.key())
            self._rows[seed.key()] = seed_row
            decision = self.stoplist.classify(seed.type, seed.normalized, is_seed=True)
            self._report("seed", {
                "investigation_id": self.investigation_id,
                "type": seed.type,
                "value": seed.value,
                "normalized": seed.normalized,
                "role": decision.role,
                "expand": decision.expand,
            })
            if not decision.expand:
                self.stats.stoplist_hits += 1
                self._report("stoplist", {"indicator": seed.value, **decision.as_dict()})

            self._enqueue(seed_row, depth=0, path=1.0, priority=0)
            if decision.expand:
                await self._queue_derived(seed, seed_row, depth=0)

            while self._queue:
                if time.monotonic() >= self._deadline:
                    self._truncate("investigation timeout")
                    break
                if self.budget.global_used >= self.budget.global_limit:
                    self._truncate(f"global request budget exhausted ({self.budget.global_limit})")
                    break
                _, _, _, _, node, depth, node_path, node_decision = heapq.heappop(self._queue)
                key = (node["type"], node["normalized_value"])
                if key in self._expanded:
                    continue
                self._expanded.add(key)
                await self._expand_node(node, depth, node_path, node_decision)

            self.stats.duration_ms = int((time.monotonic() - started) * 1000)
            self.stats.budget = self.budget.snapshot()
            self._report("run.complete", {"stats": self.stats.as_dict()})
            return self.stats
        finally:
            if self._client is not None:
                await self._client.aclose()
                self._client = None

    # -------------------------------------------------------------------- queue
    def _enqueue(self, node: dict, *, depth: int, path: float, priority: int) -> None:
        key = (node["type"], node["normalized_value"])
        if key in self._enqueued or key in self._expanded:
            return
        self._enqueued.add(key)
        self._seq += 1
        heapq.heappush(
            self._queue,
            (depth, TYPE_PRIORITY.get(node["type"], 15), priority, self._seq, node, depth, path, self._decision_for(node)),
        )

    def _decision_for(self, node: dict) -> StopDecision:
        return self.stoplist.classify(node["type"], node["normalized_value"])

    @staticmethod
    def _queue_tuple_sort(item: tuple) -> tuple:
        return (item[0], item[1], item[2], item[3])

    async def _queue_derived(self, seed: NormalizedIndicator, seed_row: dict, *, depth: int) -> None:
        """Derive the selectors contained inside the submitted link or address.

        Intake is deterministic and bounded: a URL yields at most a handful of
        selectors, each with the relation and reason that produced it.  Without
        this a URL seed would only reach providers that accept URLs, which is a
        small minority of the catalogue.
        """
        plan = plan_intake(seed.value, kind=seed.type)
        for note in plan.notes:
            self.warnings.append(note)

        for item in plan.derived:
            try:
                child = normalize_indicator(item.value, kind=item.type)
            except ValueError:
                self.warnings.append(f"could not derive {item.relation} selector from {seed.normalized}")
                continue
            if child.key() == seed.key():
                continue
            decision = self.stoplist.classify(child.type, child.normalized)
            row, derived_created = self._ensure_child(
                parent=seed_row,
                parent_path=1.0,
                child=child,
                raw_value=item.value,
                provider="normalizer",
                relation=item.relation,
                strength=item.strength,
                confidence=item.confidence,
                decision=decision,
                context_only=item.context_only or not decision.expand,
                depth=depth + 1,
                tags=list(item.tags) or ["derived"],
                note=item.reason,
            )
            if derived_created:
                self.stats.nodes += 1
            if not decision.expand:
                self.stats.stoplist_hits += 1
                self.stats.context_only += 1
                continue
            path = min(1.0, float(item.confidence))
            ok, _reason = should_expand(
                strength=item.strength,
                path=path,
                depth=depth + 1,
                context_only=False,
                stop_expand=True,
                max_depth=self.config.limits.max_depth,
                expand_weak=self.config.limits.expand_weak,
                expand_medium=self.config.limits.expand_medium,
                path_floor=float(getattr(self.config.limits, "path_confidence_floor", DEFAULT_PATH_FLOOR)),
            )
            if ok:
                self._enqueue(row, depth=depth + 1, path=path, priority=-1000 + item.priority)

    def _find_node(self, type_name: str, normalized: str) -> dict | None:
        return self._rows.get((type_name, normalized))

    # ------------------------------------------------------------------ expansion
    async def _expand_node(self, node: dict, depth: int, node_path: float, decision: StopDecision) -> None:
        providers = [
            provider
            for provider in self.registry.for_indicator(node["type"])
            if not (provider.meta.supports_sightings and not provider.meta.emits)
        ]
        # Sighting-only plugins are executed by the sightings engine, not here.
        self.stats.expanded += 1
        if not providers:
            self._report("node.skipped", {
                "type": node["type"], "value": node["value"], "depth": depth,
                "reason": "no enabled provider accepts this selector",
            })
            return
        providers = sorted(providers, key=lambda p: p.meta.name)
        self._report("node.start", {
            "type": node["type"],
            "value": node["value"],
            "depth": depth,
            "path_confidence": round(node_path, 4),
            "providers": [p.meta.name for p in providers],
        })

        semaphore = asyncio.Semaphore(self.max_provider_concurrency)

        async def guarded(provider: BaseProvider) -> ProviderOutcome | None:
            async with semaphore:
                return await self._run_provider(provider, node, depth)

        results = await asyncio.gather(*(guarded(p) for p in providers), return_exceptions=True)
        observations: list[tuple[str, Observation]] = []
        for outcome in results:
            if isinstance(outcome, BaseException):
                self.warnings.append(f"provider task crashed: {type(outcome).__name__}: {outcome}")
                self.stats.provider_failures += 1
                continue
            if outcome is None:
                continue
            observations.extend((outcome.provider, obs) for obs in outcome.result.observations)
            self._persist_events(outcome)
            for note in outcome.result.notes:
                if note not in self.warnings:
                    self.warnings.append(f"{outcome.provider}: {note}")
            for error in outcome.result.errors:
                if error not in self.warnings:
                    self.warnings.append(f"{outcome.provider}: {error}")

        allow_children = decision.expand
        candidates = self._materialize(node, depth, node_path, observations, allow_children)
        self._enqueue_candidates(node, depth, candidates, allow_children)
        self._report("node.done", {
            "type": node["type"],
            "value": node["value"],
            "depth": depth,
            "children": len(candidates),
            "expand": allow_children,
        })

    async def _run_provider(self, provider: BaseProvider, node: dict, depth: int) -> ProviderOutcome | None:
        name = provider.meta.name
        if name in self._dead:
            return None
        activity = self.activity[name]
        started = time.monotonic()
        activity["status"] = "running"
        limiter = self._limiters.setdefault(name, RateLimiter(provider.effective_rate_limit(), burst=1))
        cache = self._caches.setdefault(name, TTLCache(max_items=128))
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
        indicator = self._indicator_model(node)
        ctx = ProviderContext(
            provider=provider,
            config=self.config,
            http=http,
            indicator=indicator,
            variants=indicator.variants,
            investigation_id=self.investigation_id,
            options=provider.options,
            logger=self.log,
            fetcher=self.fetcher,
        )
        timeout = provider.effective_timeout()
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            self._truncate("investigation timeout")
            return None
        timeout = max(1.0, min(timeout, remaining))
        error: str | None = None
        self.stats.provider_runs += 1
        try:
            await asyncio.wait_for(provider.run(ctx), timeout=timeout)
        except asyncio.TimeoutError:
            error = f"timeout after {timeout:.0f}s"
            ctx.fail(error)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - one provider must never abort a run
            error = f"{type(exc).__name__}: {exc}"[:400]
            ctx.fail(error)
        if any("budget exhausted" in item.lower() for item in http.errors):
            ctx.partial("request budget exhausted during provider run")
        duration_ms = int((time.monotonic() - started) * 1000)
        status = "failed" if error or (ctx.result.errors and not ctx.result.observations) else "ran"

        activity["requests"] += http.requests
        activity["observations"] += len(ctx.result.observations)
        activity["duration_ms"] += duration_ms
        activity["status"] = status
        if error:
            activity["errors"].append(error)
        for item in ctx.result.errors:
            if item not in activity["errors"]:
                activity["errors"].append(item)

        try:
            self.repo.record_provider_run(
                self.investigation_id,
                provider=name,
                status=status,
                reason=error,
                category=provider.meta.category,
                requests=http.requests,
                observations=len(ctx.result.observations),
                sightings=len(ctx.result.sightings),
                errors=([error] if error else []) + list(ctx.result.errors),
                started_at=None,
                duration_ms=duration_ms,
                extra={
                    "partial": ctx.result.partial,
                    "notes": list(ctx.result.notes),
                    "selector": node.get("normalized_value"),
                    "selector_type": node.get("type"),
                    "depth": depth,
                },
            )
        except Exception as exc:  # noqa: BLE001 - persistence failure must not abort the run
            self.warnings.append(f"could not record provider run for {name}: {exc}")

        try:
            self.registry.mark_ran(
                name,
                requests=http.requests,
                observations=len(ctx.result.observations),
                sightings=len(ctx.result.sightings),
                duration_ms=duration_ms,
                error=error,
            )
        except Exception:  # noqa: BLE001
            pass

        if error:
            self.stats.provider_failures += 1
            self._failures[name] += 1
            if self._failures[name] >= 3 and name not in self._dead:
                self._dead.add(name)
                self.warnings.append(f"{name}: circuit breaker opened after 3 consecutive failures")
        else:
            self._failures[name] = 0

        self._report("provider.done", {
            "provider": name,
            "selector": node.get("normalized_value"),
            "status": status,
            "requests": http.requests,
            "observations": len(ctx.result.observations),
            "sightings": len(ctx.result.sightings),
            "duration_ms": duration_ms,
            "error": error,
        })
        return ProviderOutcome(
            provider=name,
            status=status,
            result=ctx.result,
            error=error,
            duration_ms=duration_ms,
            requests=http.requests,
        )

    # --------------------------------------------------------------- persistence
    def _indicator_model(self, node: dict) -> NormalizedIndicator:
        meta = node.get("meta") or {}
        variants = meta.get("variants") or [{"form": "text", "value": node.get("value", "")}]
        return NormalizedIndicator(
            type=node["type"],
            value=node.get("value") or node["normalized_value"],
            normalized=node["normalized_value"],
            variants=[v for v in variants if isinstance(v, dict)],
            tags=list(node.get("tags") or []),
            display=node.get("value"),
        )

    def _materialize(
        self,
        node: dict,
        depth: int,
        node_path: float,
        observations: list[tuple[str, Observation]],
        parent_expandable: bool = True,
    ) -> list[_Candidate]:
        groups: dict[tuple[str, str], list[tuple[str, Observation, NormalizedIndicator]]] = defaultdict(list)
        for provider_name, observation in observations:
            try:
                child = self._normalize_observation(observation)
            except ValueError:
                self.stats.invalid_observations += 1
                self._report("observation.invalid", {
                    "provider": provider_name,
                    "type": observation.type,
                    "value": observation.value[:300],
                })
                continue
            if child.key() == (node["type"], node["normalized_value"]):
                continue
            self.stats.observations += 1
            groups[child.key()].append((provider_name, observation, child))

        candidates: list[_Candidate] = []
        for key, items in groups.items():
            if len(items) > 1:
                self.stats.duplicate_observations += len(items) - 1
            child = items[0][2]
            decision = self.stoplist.classify(child.type, child.normalized)
            # Children of a stop-listed parent inherit context-only status: a
            # Cloudflare edge address must not pull in third-party identifiers.
            context_only = (
                not parent_expandable
                or not decision.expand
                or all(obs.context_only for _, obs, _ in items)
            )
            corroborations = len({provider for provider, _, _ in items})
            best_strength = max((obs.strength for _, obs, _ in items), key=strength_rank)
            best_conf = max(
                edge_confidence(
                    obs.strength,
                    self._provider_weight(provider_name),
                    corroborations=corroborations,
                    hint=obs.confidence_hint,
                )
                for provider_name, obs, _ in items
            )
            child_path = path_confidence(node_path, best_conf)

            exists = key in self._known
            if not exists and self.stats.nodes >= self.config.limits.max_nodes:
                self.stats.nodes_capped += 1
                self._report("node.capped", {"type": child.type, "value": child.value,
                                             "reason": f"max_nodes={self.config.limits.max_nodes}"})
                continue
            tags = sorted({tag for _, obs, _ in items for tag in obs.tags} | set(child.tags))
            note = next((obs.note for _, obs, _ in items if obs.note), None)
            child_meta = {
                "role": decision.role,
                "stop_reason": decision.reason,
                "variants": child.variants[:12],
                "display": child.display,
            }
            child_row, created = self._ensure_child(
                parent=node,
                parent_path=node_path,
                child=child,
                raw_value=items[0][1].value,
                provider=items[0][0],
                relation=items[0][1].relation,
                strength=best_strength,
                confidence=best_conf,
                decision=decision,
                context_only=context_only,
                depth=depth + 1,
                tags=tags,
                note=note,
                meta=child_meta,
            )
            if created:
                self.stats.nodes += 1
            if context_only:
                self.stats.context_only += 1
                if not decision.expand:
                    self.stats.stoplist_hits += 1
            for provider_name, obs, _ in items:
                confidence = edge_confidence(
                    obs.strength,
                    self._provider_weight(provider_name),
                    corroborations=corroborations,
                    hint=obs.confidence_hint,
                )
                _, edge_created = self.repo.add_edge(
                    self.investigation_id,
                    src_id=node["id"],
                    dst_id=child_row["id"],
                    relation=obs.relation or "related-to",
                    provider=provider_name,
                    confidence=confidence,
                    selector_strength=obs.strength,
                    evidence_id=obs.evidence_id,
                    observed_at=obs.observed_at,
                    meta={
                        "role": decision.role,
                        "stop_reason": decision.reason,
                        "note": obs.note,
                        "tags": obs.tags,
                    },
                )
                if edge_created:
                    self.stats.edges += 1
            candidates.append(_Candidate(
                child=child,
                observations=[(provider_name, obs) for provider_name, obs, _ in items],
                decision=decision,
                context_only=context_only,
                confidence=best_conf,
                path=child_path,
                strength=best_strength,
            ))
        return candidates

    def _ensure_child(
        self,
        *,
        parent: dict,
        parent_path: float,
        child: NormalizedIndicator,
        raw_value: str,
        provider: str,
        relation: str,
        strength: str,
        confidence: float,
        decision: StopDecision,
        context_only: bool,
        depth: int,
        tags: list[str] | None = None,
        note: str | None = None,
        meta: dict | None = None,
    ) -> tuple[dict, bool]:
        child_meta = {
            "role": decision.role,
            "stop_reason": decision.reason,
            "variants": child.variants[:12],
            "display": child.display,
            **(meta or {}),
        }
        row, created = self.repo.ensure_indicator(
            self.investigation_id,
            type=child.type,
            value=raw_value or child.value,
            normalized_value=child.normalized,
            depth=depth,
            path_confidence=path_confidence(parent_path, confidence),
            tags=list(tags or []),
            context_only=context_only,
            parent_id=parent["id"],
            meta=child_meta,
        )
        self._known.add(child.key())
        self._rows[child.key()] = row
        if created:
            self.repo.add_edge(
                self.investigation_id,
                src_id=parent["id"],
                dst_id=row["id"],
                relation=relation,
                provider=provider,
                confidence=confidence,
                selector_strength=strength,
                evidence_id=None,
                observed_at=None,
                meta={"role": decision.role, "stop_reason": decision.reason, "note": note},
            )
            self.stats.edges += 1
        return row, created

    def _enqueue_candidates(self, node: dict, depth: int, candidates: list[_Candidate], allow_children: bool) -> None:
        if not candidates or not allow_children:
            return
        candidates.sort(key=lambda item: (-item.path, TYPE_PRIORITY.get(item.child.type, 15), item.child.normalized))
        limit = max(0, int(self.config.limits.max_children_per_node))
        selected = candidates[:limit]
        self.stats.children_capped += max(0, len(candidates) - len(selected))
        if len(candidates) > len(selected):
            self._report("children.capped", {
                "value": node["value"], "observed": len(candidates), "expanded": len(selected),
                "reason": f"max_children_per_node={limit}",
            })
        for candidate in selected:
            if candidate.context_only:
                continue
            ok, reason = should_expand(
                strength=candidate.strength,
                path=candidate.path,
                depth=depth + 1,
                context_only=candidate.context_only,
                stop_expand=candidate.decision.expand,
                max_depth=self.config.limits.max_depth,
                expand_weak=self.config.limits.expand_weak,
                expand_medium=self.config.limits.expand_medium,
                path_floor=float(getattr(self.config.limits, "path_confidence_floor", DEFAULT_PATH_FLOOR)),
            )
            if not ok:
                if reason and "weak selector" not in reason:
                    self._report("node.not-expanded", {
                        "type": candidate.child.type, "value": candidate.child.value, "reason": reason,
                    })
                continue
            row = self._find_node(candidate.child.type, candidate.child.normalized)
            if row:
                self._enqueue(row, depth=depth + 1, path=candidate.path, priority=-int(candidate.path * 1000))

    def _persist_events(self, outcome: ProviderOutcome) -> None:
        for event in outcome.result.events:
            payload = event.model_dump()
            payload["occurred_at"] = event.occurred_at
            try:
                _, created = self.repo.add_event(self.investigation_id, payload)
            except Exception as exc:  # noqa: BLE001
                self.warnings.append(f"could not persist event from {outcome.provider}: {exc}")
                continue
            if created:
                self.stats.events += 1
        if outcome.result.sightings:
            # Sightings are persisted by the Phase 4 sightings engine so that
            # archive capture and role classification happen in one place.
            self.warnings.append(
                f"{outcome.provider}: returned {len(outcome.result.sightings)} sighting(s) during pivot; "
                "they will be collected by the sightings stage"
            )

    # ------------------------------------------------------------------- helpers
    def _normalize_observation(self, observation: Observation) -> NormalizedIndicator:
        region = getattr(self.config, "default_region", None) or "US"
        try:
            child = normalize_indicator(observation.value, kind=observation.type, default_region=region)
        except ValueError:
            child = normalize_indicator(observation.value, default_region=region)
        if not child.value:
            child.value = observation.value
        return child

    def _provider_weight(self, name: str) -> float:
        provider = self.registry.get(name)
        return provider.effective_weight() if provider else 0.5

    def _truncate(self, reason: str) -> None:
        if not self.stats.truncated:
            self.stats.truncated = reason
            self.warnings.append(f"run truncated: {reason}")

    def _report(self, event: str, payload: dict) -> None:
        if not self.progress:
            return
        try:
            self.progress({"event": event, "at": iso(utcnow()), **payload})
        except Exception:  # noqa: BLE001 - UI callbacks must never break a run
            pass

    # ------------------------------------------------------------------- coverage
    def note_external_run(
        self,
        provider: str,
        *,
        requests: int = 0,
        observations: int = 0,
        duration_ms: int = 0,
        error: str | None = None,
        stage: str = "sightings",
    ) -> None:
        """Register work done outside the pivot loop (sightings, archiving).

        Without this, a social provider that ran during the sightings stage
        would be reported as "not applicable" simply because the pivot engine
        never called it. Coverage must reflect what actually ran.
        """
        activity = self.activity[provider]
        activity["requests"] += int(requests)
        activity["observations"] += int(observations)
        activity["duration_ms"] += int(duration_ms)
        activity["status"] = "failed" if error else "ran"
        activity["stage"] = stage
        if error and error not in activity["errors"]:
            activity["errors"].append(error)

    def coverage(self) -> dict:
        """Coverage for *this run*, merged with static availability."""
        providers: list[dict] = []
        ran: list[str] = []
        skipped: list[dict] = []
        failed: list[dict] = []
        for status in self.registry.statuses():
            entry = status.model_dump()
            activity = self.activity.get(status.name)
            if activity:
                entry.update({
                    "requests": activity["requests"],
                    "observations": activity["observations"],
                    "duration_ms": activity["duration_ms"],
                    "status": "failed" if activity["status"] == "failed" else "enabled",
                })
                if activity["errors"]:
                    entry["error"] = activity["errors"][0]
                if activity.get("stage"):
                    entry["stage"] = activity["stage"]
            if entry["status"] == "failed":
                failed.append({"provider": status.name, "reason": entry.get("error") or status.reason})
            elif entry["status"] == "skipped":
                skipped.append({"provider": status.name, "reason": status.reason})
            elif activity and activity["status"] == "failed":
                failed.append({"provider": status.name, "reason": activity["errors"][0] if activity["errors"] else "provider failed"})
            elif activity and (activity["requests"] or activity["observations"]):
                ran.append(status.name)
            else:
                entry["status"] = "skipped"
                entry["reason"] = entry.get("reason") or "not applicable to any selector in this run"
                skipped.append({"provider": status.name, "reason": entry["reason"]})
            providers.append(entry)
        return {
            "providers": providers,
            "ran": sorted(ran),
            "skipped": skipped,
            "failed": failed,
            "load_errors": [{"module": e.module, "error": e.error} for e in self.registry.load_errors],
            "circuit_breakers": sorted(self._dead),
            "stoplist": {
                "networks": len(self.stoplist.networks),
                "domains": len(self.stoplist.domains),
                "warnings": list(self.stoplist.warnings),
            },
        }
