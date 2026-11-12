"""Per-run provider context: HTTP, evidence, emission helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from phishtrace.config import Config
from phishtrace.models import (
    NormalizedIndicator, Observation, ProviderResult, SelectorStrength, SightingDraft,
    TimelineEventDraft, parse_timestamp, utcnow,
)


@dataclass
class ProviderContext:
    provider: Any
    config: Config
    http: Any
    indicator: NormalizedIndicator | None = None
    variants: list[dict] = field(default_factory=list)
    investigation_id: str | None = None
    options: dict = field(default_factory=dict)
    logger: Callable[[str], None] | None = None
    fetcher: Any | None = None
    result: ProviderResult = field(default_factory=ProviderResult)

    # ------------------------------------------------------------------ logging
    def log(self, message: str) -> None:
        if self.logger:
            self.logger(f"[{self.provider.meta.name}] {message}")

    # ----------------------------------------------------------------- emission
    def emit(
        self,
        type: str,
        value: str,
        relation: str,
        strength: str | SelectorStrength = SelectorStrength.WEAK,
        *,
        evidence_id: str | None = None,
        observed_at: datetime | str | None = None,
        tags: list[str] | None = None,
        meta: dict | None = None,
        context_only: bool = False,
        confidence_hint: float | None = None,
        note: str | None = None,
    ) -> Observation:
        if not value:
            raise ValueError("observation value must not be empty")
        obs = Observation(
            type=type,
            value=str(value).strip(),
            relation=relation,
            strength=strength.value if isinstance(strength, SelectorStrength) else str(strength),
            evidence_id=evidence_id,
            observed_at=parse_timestamp(observed_at) if not isinstance(observed_at, datetime) else observed_at,
            tags=list(tags or []),
            meta=meta or {},
            context_only=context_only,
            confidence_hint=confidence_hint,
            note=note,
        )
        self.result.observations.append(obs)
        return obs

    def event(
        self,
        occurred_at: datetime | str | None,
        *,
        source: str | None = None,
        kind: str,
        label: str,
        detail: str | None = None,
        url: str | None = None,
        evidence_id: str | None = None,
        indicator_value: str | None = None,
        precision: str = "exact",
        meta: dict | None = None,
    ) -> TimelineEventDraft | None:
        parsed = parse_timestamp(occurred_at) if not isinstance(occurred_at, datetime) else occurred_at
        if not parsed:
            return None
        ev = TimelineEventDraft(
            occurred_at=parsed,
            source=source or self.provider.meta.name,
            kind=kind,
            label=label,
            detail=detail,
            url=url,
            evidence_id=evidence_id,
            indicator_value=indicator_value,
            precision=precision,
            meta=meta or {},
        )
        self.result.events.append(ev)
        return ev

    def sighting(
        self,
        *,
        platform: str,
        post_url: str,
        post_id: str | None = None,
        author_handle: str | None = None,
        author_id: str | None = None,
        author_created_at: datetime | str | None = None,
        posted_at: datetime | str | None = None,
        text: str = "",
        role: str = "unknown",
        indicator_form_matched: str | None = None,
        evidence_id: str | None = None,
        archive_snapshot_url: str | None = None,
        meta: dict | None = None,
    ) -> SightingDraft:
        draft = SightingDraft(
            platform=platform,
            post_url=post_url,
            post_id=post_id,
            author_handle=author_handle,
            author_id=author_id,
            author_created_at=parse_timestamp(author_created_at) if not isinstance(author_created_at, datetime) else author_created_at,
            posted_at=parse_timestamp(posted_at) if not isinstance(posted_at, datetime) else posted_at,
            text=text or "",
            role=role,
            indicator_form_matched=indicator_form_matched,
            evidence_id=evidence_id,
            archive_snapshot_url=archive_snapshot_url,
            meta=meta or {},
        )
        self.result.sightings.append(draft)
        return draft

    # ------------------------------------------------------------- active fetch
    @property
    def active_fetch_allowed(self) -> bool:
        return bool(self.config.fetcher.active_fetch and self.fetcher is not None)

    async def fetch_page(self, url: str, *, note: str = "") -> Any | None:
        """Fetch through the isolated, SSRF-protected fetcher (active mode only)."""
        if not self.active_fetch_allowed:
            self.log("active_fetch disabled; refusing direct contact with infrastructure")
            return None
        return await self.fetcher.fetch(url, provider=self.provider.meta.name, note=note)

    # -------------------------------------------------------------------- flags
    def partial(self, reason: str) -> None:
        self.result.partial = True
        self.result.notes.append(reason)

    def fail(self, message: str) -> None:
        self.result.errors.append(message)

    def now(self) -> datetime:
        return utcnow()
