"""Background execution of web-triggered investigations.

The web console must show progress for a run before the first network request
happens, so a run is created in two steps: the API writes the investigation row,
then this manager starts a daemon thread that owns a private asyncio loop. Each
run gets its own registry instance so provider request counters and coverage
cannot leak between concurrent investigations.

Only a bounded ring buffer of progress events is kept in memory; durable state
always lives in the repository. The API therefore stays correct after a restart
even though live event history is lost.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from typing import Any, Callable

from phishtrace.core.orchestrator import InvestigationRunner
from phishtrace.core.registry import Registry

TERMINAL_STATUSES = {"completed", "partial", "failed", "cancelled"}

#: Progress events that move the console's coarse stage indicator forward.
_STAGE_BY_EVENT = {
    "run.start": "starting",
    "seed": "pivot",
    "node.start": "pivot",
    "node.done": "pivot",
    "provider.done": "pivot",
    "stage.pivot": "sightings",
    "stage.sightings": "sightings",
    "stage.archive": "archive",
    "run.finalized": "done",
    "run.failed": "failed",
}


class RunError(RuntimeError):
    """Raised when a run cannot be started (unknown investigation, overload)."""


class _RunRecord:
    __slots__ = (
        "investigation_id", "seed", "events", "seq", "state", "error", "stage",
        "started", "finished", "thread", "run_sightings",
    )

    def __init__(self, investigation_id: str, seed: str, run_sightings: bool):
        self.investigation_id = investigation_id
        self.seed = seed
        self.events: deque[dict] = deque(maxlen=500)
        self.seq = 0
        self.state = "starting"
        self.error: str | None = None
        self.stage = "starting"
        self.started = time.monotonic()
        self.finished: float | None = None
        self.thread: threading.Thread | None = None
        self.run_sightings = run_sightings

    def push(self, event: dict) -> None:
        self.seq += 1
        item = {"seq": self.seq, **event}
        self.events.append(item)
        name = str(event.get("event") or "")
        if name in _STAGE_BY_EVENT:
            self.stage = _STAGE_BY_EVENT[name]
        if name == "run.failed":
            self.stage = "failed"
            self.error = str(event.get("error") or "run failed")[:500]


class RunManager:
    """Start investigations in daemon threads and expose bounded live progress."""

    def __init__(
        self,
        config,
        repo,
        registry: Registry,
        *,
        max_concurrent: int = 2,
        max_provider_concurrency: int = 4,
    ):
        self.config = config
        self.repo = repo
        self.registry = registry
        self.max_concurrent = max(1, int(max_concurrent))
        self.max_provider_concurrency = max(1, int(max_provider_concurrency))
        self._lock = threading.RLock()
        self._runs: dict[str, _RunRecord] = {}

    # ------------------------------------------------------------------ lifecycle
    def start(self, investigation: dict, seed, *, run_sightings: bool = True) -> dict:
        """Start ``investigation`` in the background and return a small snapshot."""
        investigation_id = investigation["id"]
        with self._lock:
            existing = self._runs.get(investigation_id)
            if existing and existing.thread and existing.thread.is_alive():
                raise RunError("investigation is already running")
            if self._active_locked() >= self.max_concurrent:
                raise RunError(
                    f"too many concurrent investigations (limit {self.max_concurrent}); retry shortly"
                )
            record = _RunRecord(investigation_id, str(seed.normalized), run_sightings)
            self._runs[investigation_id] = record
            thread = threading.Thread(
                target=self._execute,
                args=(record, seed),
                name=f"phishtrace-run-{investigation_id[:8]}",
                daemon=True,
            )
            record.thread = thread
            thread.start()
        return self.snapshot(investigation_id) or {}

    def _active_locked(self) -> int:
        return sum(1 for r in self._runs.values() if r.thread and r.thread.is_alive())

    def _execute(self, record: _RunRecord, seed) -> None:
        runner = InvestigationRunner(
            self.config,
            self.repo,
            self._fresh_registry(),
            progress=record.push,
            max_provider_concurrency=self.max_provider_concurrency,
        )
        try:
            asyncio.run(runner.run_existing(
                seed,
                self.repo.get_investigation(record.investigation_id) or {"id": record.investigation_id},
                run_sightings=record.run_sightings,
            ))
        except Exception as exc:  # noqa: BLE001 - persisted by the runner, surfaced here
            record.error = f"{type(exc).__name__}: {exc}"[:500]
            record.state = "failed"
            record.stage = "failed"
            record.push({"event": "run.error", "error": record.error})
        else:
            record.state = "finished"
        finally:
            record.finished = time.monotonic()
            with self._lock:
                self._prune_locked()

    def _fresh_registry(self) -> Registry:
        """Clone provider classes so per-run request counters start at zero."""
        try:
            classes = [type(p) for p in self.registry.all_providers()]
            return Registry(self.config, provider_classes=classes) if classes else self.registry
        except Exception:  # noqa: BLE001 - a clone failure must not kill the run
            return self.registry

    def _prune_locked(self, keep: int = 40) -> None:
        if len(self._runs) <= keep:
            return
        finished = sorted(
            (r for r in self._runs.values() if r.finished is not None),
            key=lambda r: r.finished or 0.0,
        )
        for record in finished[: max(0, len(self._runs) - keep)]:
            self._runs.pop(record.investigation_id, None)

    # -------------------------------------------------------------------- reading
    def snapshot(self, investigation_id: str, *, after: int = 0) -> dict | None:
        with self._lock:
            record = self._runs.get(investigation_id)
            if record is None:
                return None
            events = [dict(e) for e in record.events if int(e.get("seq", 0)) > after]
            first_seq = record.events[0]["seq"] if record.events else 0
            running = bool(record.thread and record.thread.is_alive())
            elapsed_ms = int(((record.finished or time.monotonic()) - record.started) * 1000)
            return {
                "investigation_id": investigation_id,
                "state": record.state,
                "stage": record.stage,
                "error": record.error,
                "running": running,
                "elapsed_ms": max(0, elapsed_ms),
                "events": events,
                "cursor": record.seq,
                "dropped": max(0, after + 1 - first_seq) if after and first_seq > after + 1 else 0,
                "run_sightings": record.run_sightings,
            }

    def wait(self, investigation_id: str, timeout: float = 30.0) -> dict | None:
        """Block until the run's thread exits (used by tests and CLI helpers)."""
        with self._lock:
            record = self._runs.get(investigation_id)
        if record and record.thread:
            record.thread.join(max(0.0, float(timeout)))
        return self.snapshot(investigation_id)

    def active(self) -> list[str]:
        with self._lock:
            return sorted(
                r.investigation_id for r in self._runs.values()
                if r.thread and r.thread.is_alive()
            )

    def discard(self, investigation_id: str) -> None:
        """Forget a run record (used when an investigation is deleted)."""
        with self._lock:
            self._runs.pop(investigation_id, None)


def progress_callback(record: _RunRecord) -> Callable[[dict[str, Any]], None]:
    """Compatibility helper for callers that only need the push function."""
    return record.push
