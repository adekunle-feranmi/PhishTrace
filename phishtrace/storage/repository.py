"""Persistence facade.

All writes are idempotent: re-running the same seed reuses an existing
investigation and upserts indicators, edges, sightings, timeline events and
evidence rows rather than duplicating them.
"""

from __future__ import annotations

import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Iterable

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from phishtrace.models import STRENGTH_RANK, as_utc, iso, stable_key, utcnow
from phishtrace.storage.db import (
    AuditLog, Edge, Entity, EntityLink, EntityMember, Evidence, Indicator, Investigation,
    KitAnalysis, ProviderRun, Sighting, TimelineEvent, User,
)
from phishtrace.storage.evidence import EvidenceRecord, EvidenceStore
from phishtrace.utils import to_jsonable


class Repository:
    def __init__(self, session_factory: sessionmaker, evidence_store: EvidenceStore | None = None):
        self.sessions = session_factory
        self.evidence_store = evidence_store
        self._write_lock = threading.RLock()

    @contextmanager
    def session(self) -> Iterable[Session]:
        session = self.sessions()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------ investigations
    def create_investigation(
        self,
        *,
        seed: str,
        seed_type: str,
        seed_normalized: str,
        config_snapshot: dict,
        owner: str = "cli",
    ) -> dict:
        with self._write_lock, self.session() as db:
            inv = Investigation(
                id=uuid.uuid4().hex,
                seed=seed,
                seed_type=seed_type,
                seed_normalized=seed_normalized,
                config_snapshot=to_jsonable(config_snapshot),
                owner=owner,
                status="running",
                started_at=utcnow(),
            )
            db.add(inv)
            db.flush()
            return self._inv_dict(inv)

    def latest_for_seed(self, seed_normalized: str) -> dict | None:
        with self.session() as db:
            row = db.scalars(
                select(Investigation)
                .where(Investigation.seed_normalized == seed_normalized)
                .order_by(Investigation.started_at.desc())
                .limit(1)
            ).first()
            return self._inv_dict(row) if row else None

    def get_investigation(self, investigation_id: str) -> dict | None:
        with self.session() as db:
            row = db.get(Investigation, investigation_id)
            return self._inv_dict(row) if row else None

    def list_investigations(self, limit: int = 100, owner: str | None = None) -> list[dict]:
        with self.session() as db:
            stmt = select(Investigation).order_by(Investigation.started_at.desc()).limit(limit)
            if owner:
                stmt = stmt.where(Investigation.owner == owner)
            rows = db.scalars(stmt).all()
            return [self._inv_dict(row) for row in rows]

    def mark_running(self, investigation_id: str) -> None:
        with self._write_lock, self.session() as db:
            inv = db.get(Investigation, investigation_id)
            if inv:
                inv.status = "running"
                inv.error = None
                inv.finished_at = None

    def finalize(
        self,
        investigation_id: str,
        *,
        status: str,
        coverage: dict,
        stats: dict,
        summary: dict,
        error: str | None = None,
    ) -> None:
        with self._write_lock, self.session() as db:
            inv = db.get(Investigation, investigation_id)
            if not inv:
                return
            inv.status = status
            inv.coverage = to_jsonable(coverage)
            inv.stats = to_jsonable(stats)
            inv.summary = to_jsonable(summary)
            inv.finished_at = utcnow()
            inv.error = error

    def delete_investigation(self, investigation_id: str) -> list[str]:
        """Delete an investigation and return now-orphaned evidence file paths."""
        with self._write_lock, self.session() as db:
            inv = db.get(Investigation, investigation_id)
            if not inv:
                return []
            paths = [row.raw_response_path for row in db.scalars(
                select(Evidence).where(Evidence.investigation_id == investigation_id)
            ).all()]
            db.execute(delete(Investigation).where(Investigation.id == investigation_id))
        return [path for path in paths if not self._evidence_path_referenced(path)]

    def _evidence_path_referenced(self, path: str) -> bool:
        with self.session() as db:
            return db.scalar(select(func.count()).select_from(Evidence).where(Evidence.raw_response_path == path)) > 0

    # ---------------------------------------------------------------- indicators
    def ensure_indicator(
        self,
        investigation_id: str,
        *,
        type: str,
        value: str,
        normalized_value: str,
        depth: int = 0,
        path_confidence: float = 1.0,
        tags: list[str] | None = None,
        context_only: bool = False,
        parent_id: str | None = None,
        meta: dict | None = None,
    ) -> tuple[dict, bool]:
        with self._write_lock, self.session() as db:
            row = db.scalars(
                select(Indicator).where(
                    Indicator.investigation_id == investigation_id,
                    Indicator.type == type,
                    Indicator.normalized_value == normalized_value,
                )
            ).first()
            if row:
                merged_tags = list(dict.fromkeys((row.tags or []) + (tags or [])))
                row.tags = merged_tags
                row.depth = min(row.depth, depth)
                row.path_confidence = max(row.path_confidence, path_confidence)
                if not context_only:
                    row.context_only = False
                if parent_id and not row.parent_id:
                    row.parent_id = parent_id
                if meta:
                    row.meta = {**(row.meta or {}), **to_jsonable(meta)}
                db.flush()
                return row.to_dict(), False
            obj = Indicator(
                id=uuid.uuid4().hex,
                investigation_id=investigation_id,
                type=type,
                value=value,
                normalized_value=normalized_value,
                depth=depth,
                path_confidence=path_confidence,
                tags=list(dict.fromkeys(tags or [])),
                context_only=context_only,
                parent_id=parent_id,
                meta=to_jsonable(meta or {}),
                first_seen_in_run=utcnow(),
            )
            db.add(obj)
            db.flush()
            return obj.to_dict(), True

    def get_indicator(self, investigation_id: str, indicator_id: str) -> dict | None:
        with self.session() as db:
            row = db.get(Indicator, indicator_id)
            if not row or row.investigation_id != investigation_id:
                return None
            return row.to_dict()

    # --------------------------------------------------------------------- edges
    def add_edge(
        self,
        investigation_id: str,
        *,
        src_id: str,
        dst_id: str,
        relation: str,
        provider: str,
        confidence: float,
        selector_strength: str,
        evidence_id: str | None = None,
        observed_at: datetime | None = None,
        meta: dict | None = None,
    ) -> tuple[dict, bool]:
        with self._write_lock, self.session() as db:
            row = db.scalars(
                select(Edge).where(
                    Edge.investigation_id == investigation_id,
                    Edge.src_id == src_id,
                    Edge.dst_id == dst_id,
                    Edge.relation == relation,
                    Edge.provider == provider,
                )
            ).first()
            if row:
                row.confidence = max(row.confidence, confidence)
                if STRENGTH_RANK.get(selector_strength, 0) > STRENGTH_RANK.get(row.selector_strength, 0):
                    row.selector_strength = selector_strength
                if evidence_id and not row.evidence_id:
                    row.evidence_id = evidence_id
                existing_meta = dict(row.meta or {})
                if evidence_id:
                    ids = list(existing_meta.get("evidence_ids") or [])
                    if evidence_id not in ids:
                        ids.append(evidence_id)
                    existing_meta["evidence_ids"] = ids
                existing_meta.update(to_jsonable(meta or {}))
                row.meta = existing_meta
                if observed_at and (row.observed_at is None or as_utc(observed_at) < as_utc(row.observed_at)):
                    row.observed_at = observed_at
                db.flush()
                return row.to_dict(), False
            obj = Edge(
                id=uuid.uuid4().hex,
                investigation_id=investigation_id,
                src_id=src_id,
                dst_id=dst_id,
                relation=relation,
                provider=provider,
                confidence=confidence,
                selector_strength=selector_strength,
                evidence_id=evidence_id,
                observed_at=observed_at,
                meta=to_jsonable({"evidence_ids": [evidence_id] if evidence_id else [], **(meta or {})}),
            )
            db.add(obj)
            db.flush()
            return obj.to_dict(), True

    # ------------------------------------------------------------------ evidence
    def add_evidence(self, investigation_id: str, record: EvidenceRecord) -> tuple[str, bool]:
        with self._write_lock, self.session() as db:
            existing = db.scalars(
                select(Evidence).where(
                    Evidence.investigation_id == investigation_id,
                    Evidence.dedupe_key == record.dedupe_key,
                )
            ).first()
            if existing:
                return existing.id, False
            obj = Evidence(
                id=record.id,
                investigation_id=investigation_id,
                provider=record.provider,
                request=to_jsonable(record.request),
                raw_response_path=record.raw_response_path,
                sha256=record.sha256,
                retrieved_at=record.retrieved_at,
                url=record.url,
                status_code=record.status_code,
                content_type=record.content_type,
                size_bytes=record.size_bytes,
                dedupe_key=record.dedupe_key,
            )
            db.add(obj)
            db.flush()
            return obj.id, True

    # ----------------------------------------------------------------- timeline
    def add_event(self, investigation_id: str, event: dict) -> tuple[str, bool]:
        occurred = event.get("occurred_at")
        if not occurred:
            return "", False
        dedupe = stable_key("event", event.get("source"), event.get("kind"), event.get("label"), iso(occurred))
        with self._write_lock, self.session() as db:
            existing = db.scalars(
                select(TimelineEvent).where(
                    TimelineEvent.investigation_id == investigation_id,
                    TimelineEvent.dedupe_key == dedupe,
                )
            ).first()
            if existing:
                return existing.id, False
            obj = TimelineEvent(
                id=uuid.uuid4().hex,
                investigation_id=investigation_id,
                occurred_at=occurred,
                source=event.get("source", "unknown"),
                kind=event.get("kind", "event"),
                label=event.get("label", ""),
                detail=event.get("detail"),
                url=event.get("url"),
                evidence_id=event.get("evidence_id"),
                indicator_value=event.get("indicator_value"),
                precision=event.get("precision", "exact"),
                dedupe_key=dedupe,
                meta=to_jsonable(event.get("meta") or {}),
            )
            db.add(obj)
            db.flush()
            return obj.id, True

    # ----------------------------------------------------------------- sightings
    def add_sighting(self, investigation_id: str, sighting: dict) -> tuple[str, bool]:
        identity = sighting.get("post_id") or sighting.get("post_url")
        dedupe = stable_key("sighting", sighting.get("platform"), identity)
        with self._write_lock, self.session() as db:
            existing = db.scalars(
                select(Sighting).where(
                    Sighting.investigation_id == investigation_id,
                    Sighting.dedupe_key == dedupe,
                )
            ).first()
            if existing:
                forms = list((existing.meta or {}).get("matched_forms") or [])
                form = sighting.get("indicator_form_matched")
                if form and form not in forms:
                    forms.append(form)
                    existing.meta = {**(existing.meta or {}), "matched_forms": forms}
                if sighting.get("archive_snapshot_url") and not existing.archive_snapshot_url:
                    existing.archive_snapshot_url = sighting["archive_snapshot_url"]
                if sighting.get("local_archive_path") and not existing.local_archive_path:
                    existing.local_archive_path = sighting["local_archive_path"]
                db.flush()
                return existing.id, False
            obj = Sighting(
                id=uuid.uuid4().hex,
                investigation_id=investigation_id,
                indicator_id=sighting.get("indicator_id"),
                indicator_form_matched=sighting.get("indicator_form_matched") or "",
                platform=sighting.get("platform", "unknown"),
                post_url=sighting.get("post_url") or "",
                post_id=sighting.get("post_id"),
                author_handle=sighting.get("author_handle"),
                author_id=sighting.get("author_id"),
                author_created_at=sighting.get("author_created_at"),
                posted_at=sighting.get("posted_at"),
                retrieved_at=sighting.get("retrieved_at") or utcnow(),
                text_excerpt=sighting.get("text_excerpt") or "",
                text_sha256=sighting.get("text_sha256") or "",
                role=sighting.get("role") or "unknown",
                archive_snapshot_url=sighting.get("archive_snapshot_url"),
                local_archive_path=sighting.get("local_archive_path"),
                evidence_id=sighting.get("evidence_id"),
                dedupe_key=dedupe,
                meta=to_jsonable({
                    **(sighting.get("meta") or {}),
                    "matched_forms": [sighting.get("indicator_form_matched")]
                    if sighting.get("indicator_form_matched") else [],
                }),
            )
            db.add(obj)
            db.flush()
            return obj.id, True

    def update_sighting_archive(self, sighting_id: str, url: str | None, local_path: str | None) -> None:
        with self._write_lock, self.session() as db:
            row = db.get(Sighting, sighting_id)
            if row:
                if url:
                    row.archive_snapshot_url = url
                if local_path:
                    row.local_archive_path = local_path
                db.flush()

    # -------------------------------------------------------------- provider runs
    def record_provider_run(
        self,
        investigation_id: str,
        *,
        provider: str,
        status: str,
        reason: str | None = None,
        category: str = "",
        requests: int = 0,
        observations: int = 0,
        sightings: int = 0,
        errors: list[str] | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        duration_ms: int = 0,
        extra: dict | None = None,
    ) -> None:
        with self._write_lock, self.session() as db:
            row = db.scalars(
                select(ProviderRun).where(
                    ProviderRun.investigation_id == investigation_id,
                    ProviderRun.provider == provider,
                )
            ).first()
            if row:
                row.requests += requests
                row.observations += observations
                row.sightings += sightings
                if errors:
                    row.errors = list(dict.fromkeys((row.errors or []) + errors))[:20]
                if status == "failed" and row.status != "ran":
                    row.status = "failed"
                    row.reason = reason or row.reason
                elif status == "ran":
                    row.status = "ran"
                    if reason:
                        row.reason = reason
                row.finished_at = finished_at or utcnow()
                row.duration_ms += duration_ms
                row.extra = {**(row.extra or {}), **to_jsonable(extra or {})}
                db.flush()
                return
            obj = ProviderRun(
                id=uuid.uuid4().hex,
                investigation_id=investigation_id,
                provider=provider,
                category=category,
                status=status,
                reason=reason,
                requests=requests,
                observations=observations,
                sightings=sightings,
                errors=to_jsonable(errors or []),
                started_at=started_at or utcnow(),
                finished_at=finished_at or utcnow(),
                duration_ms=duration_ms,
                extra=to_jsonable(extra or {}),
            )
            db.add(obj)
            db.flush()

    # -------------------------------------------------------------------- kits
    def add_kit(self, investigation_id: str, kit: dict) -> str:
        with self._write_lock, self.session() as db:
            obj = KitAnalysis(
                id=uuid.uuid4().hex,
                investigation_id=investigation_id,
                indicator_id=kit.get("indicator_id"),
                url=kit.get("url", ""),
                kit_sha256=kit.get("kit_sha256"),
                file_tree_hash=kit.get("file_tree_hash"),
                ssdeep=kit.get("ssdeep"),
                tlsh=kit.get("tlsh"),
                exfil_emails=to_jsonable(kit.get("exfil_emails") or []),
                telegram_bots=to_jsonable(kit.get("telegram_bots") or []),
                webhooks=to_jsonable(kit.get("webhooks") or []),
                analytics_ids=to_jsonable(kit.get("analytics_ids") or []),
                author_strings=to_jsonable(kit.get("author_strings") or []),
                brand=kit.get("brand"),
                form_fields=to_jsonable(kit.get("form_fields") or []),
                files=to_jsonable(kit.get("files") or []),
                exposed_paths=to_jsonable(kit.get("exposed_paths") or []),
                credential_exposure_count=int(kit.get("credential_exposure_count") or 0),
                credential_exposure_types=to_jsonable(kit.get("credential_exposure_types") or []),
                notes=kit.get("notes"),
            )
            db.add(obj)
            db.flush()
            return obj.id

    # ---------------------------------------------------------------- read APIs
    def graph(self, investigation_id: str) -> dict:
        with self.session() as db:
            nodes = db.scalars(select(Indicator).where(Indicator.investigation_id == investigation_id)).all()
            edges = db.scalars(select(Edge).where(Edge.investigation_id == investigation_id)).all()
            node_map = {n.id: n.to_dict() for n in nodes}
            out_edges = []
            for edge in edges:
                item = edge.to_dict()
                item["src_value"] = node_map.get(edge.src_id, {}).get("value")
                item["dst_value"] = node_map.get(edge.dst_id, {}).get("value")
                item["src_type"] = node_map.get(edge.src_id, {}).get("type")
                item["dst_type"] = node_map.get(edge.dst_id, {}).get("type")
                out_edges.append(item)
            return {"nodes": [n.to_dict() for n in nodes], "edges": out_edges}

    def list_sightings(self, investigation_id: str, limit: int | None = None) -> list[dict]:
        with self.session() as db:
            stmt = (
                select(Sighting)
                .where(Sighting.investigation_id == investigation_id)
                .order_by(Sighting.posted_at.is_(None), Sighting.posted_at.asc(), Sighting.retrieved_at.asc())
            )
            if limit:
                stmt = stmt.limit(limit)
            return [row.to_dict() for row in db.scalars(stmt).all()]

    def list_timeline(self, investigation_id: str) -> list[dict]:
        with self.session() as db:
            stmt = (
                select(TimelineEvent)
                .where(TimelineEvent.investigation_id == investigation_id)
                .order_by(TimelineEvent.occurred_at.asc())
            )
            return [row.to_dict() for row in db.scalars(stmt).all()]

    def list_evidence(self, investigation_id: str, limit: int = 1000) -> list[dict]:
        with self.session() as db:
            stmt = (
                select(Evidence)
                .where(Evidence.investigation_id == investigation_id)
                .order_by(Evidence.retrieved_at.desc())
                .limit(limit)
            )
            return [row.to_dict() for row in db.scalars(stmt).all()]

    def get_evidence(self, investigation_id: str, evidence_id: str) -> dict | None:
        with self.session() as db:
            row = db.get(Evidence, evidence_id)
            if not row or row.investigation_id != investigation_id:
                return None
            return row.to_dict()

    def list_provider_runs(self, investigation_id: str) -> list[dict]:
        with self.session() as db:
            rows = db.scalars(
                select(ProviderRun)
                .where(ProviderRun.investigation_id == investigation_id)
                .order_by(ProviderRun.provider.asc())
            ).all()
            return [row.to_dict() for row in rows]

    def list_kits(self, investigation_id: str) -> list[dict]:
        with self.session() as db:
            rows = db.scalars(
                select(KitAnalysis)
                .where(KitAnalysis.investigation_id == investigation_id)
                .order_by(KitAnalysis.created_at.asc())
            ).all()
            return [row.to_dict() for row in rows]

    def counts(self, investigation_id: str) -> dict:
        with self.session() as db:
            def count(model) -> int:
                return int(db.scalar(
                    select(func.count()).select_from(model).where(model.investigation_id == investigation_id)
                ) or 0)
            return {
                "indicators": count(Indicator),
                "edges": count(Edge),
                "sightings": count(Sighting),
                "events": count(TimelineEvent),
                "evidence": count(Evidence),
                "kits": count(KitAnalysis),
            }

    def full_export(self, investigation_id: str) -> dict | None:
        inv = self.get_investigation(investigation_id)
        if not inv:
            return None
        return {
            "investigation": inv,
            "graph": self.graph(investigation_id),
            "sightings": self.list_sightings(investigation_id),
            "timeline": self.list_timeline(investigation_id),
            "evidence": self.list_evidence(investigation_id),
            "provider_runs": self.list_provider_runs(investigation_id),
            "kits": self.list_kits(investigation_id),
            "counts": self.counts(investigation_id),
        }

    # ----------------------------------------------------------------- entities
    def upsert_entity(
        self,
        *,
        kind: str,
        key: str,
        label: str,
        confidence: float = 0.0,
        meta: dict | None = None,
    ) -> tuple[dict, bool]:
        """Return the entity for ``key``, creating it on first sight.

        ``key`` is globally unique, which is the whole point: an email seen in
        one investigation is the same row when it turns up in the next one.
        """
        with self._write_lock, self.session() as db:
            row = db.scalars(select(Entity).where(Entity.key == key)).first()
            if row:
                if label and label != row.label:
                    row.label = label
                row.confidence = max(row.confidence, float(confidence))
                row.meta = {**(row.meta or {}), **to_jsonable(meta or {})}
                db.flush()
                return row.to_dict(), False
            obj = Entity(
                id=uuid.uuid4().hex,
                kind=kind,
                key=key,
                label=label,
                confidence=float(confidence),
                meta=to_jsonable(meta or {}),
            )
            db.add(obj)
            db.flush()
            return obj.to_dict(), True

    def add_entity_member(
        self,
        entity_id: str,
        investigation_id: str,
        *,
        indicator_id: str | None,
        role: str,
        join_rule: str,
        strength: str = "weak",
        confidence: float = 0.0,
        evidence_id: str | None = None,
        reason: str = "",
        meta: dict | None = None,
    ) -> tuple[dict, bool]:
        with self._write_lock, self.session() as db:
            row = db.scalars(
                select(EntityMember).where(
                    EntityMember.entity_id == entity_id,
                    EntityMember.investigation_id == investigation_id,
                    EntityMember.indicator_id == indicator_id,
                    EntityMember.role == role,
                )
            ).first()
            if row:
                row.confidence = max(row.confidence, float(confidence))
                if STRENGTH_RANK.get(strength, 0) > STRENGTH_RANK.get(row.strength, 0):
                    row.strength = strength
                if evidence_id and not row.evidence_id:
                    row.evidence_id = evidence_id
                if reason:
                    row.reason = reason
                row.meta = {**(row.meta or {}), **to_jsonable(meta or {})}
                db.flush()
                return row.to_dict(), False
            obj = EntityMember(
                id=uuid.uuid4().hex,
                entity_id=entity_id,
                investigation_id=investigation_id,
                indicator_id=indicator_id,
                role=role,
                join_rule=join_rule,
                strength=strength,
                confidence=float(confidence),
                evidence_id=evidence_id,
                reason=reason,
                meta=to_jsonable(meta or {}),
            )
            db.add(obj)
            db.flush()
            return obj.to_dict(), True

    def refresh_entity(self, entity_id: str) -> dict:
        """Recompute member/investigation counts and the observed window."""
        with self._write_lock, self.session() as db:
            row = db.get(Entity, entity_id)
            if not row:
                return {}
            total = db.scalar(
                select(func.count()).select_from(EntityMember).where(EntityMember.entity_id == entity_id)
            ) or 0
            cases = db.scalar(
                select(func.count(func.distinct(EntityMember.investigation_id))).where(
                    EntityMember.entity_id == entity_id
                )
            ) or 0
            first = db.scalar(
                select(func.min(EntityMember.first_seen)).where(EntityMember.entity_id == entity_id)
            )
            last = db.scalar(
                select(func.max(EntityMember.first_seen)).where(EntityMember.entity_id == entity_id)
            )
            row.member_count = int(total)
            row.investigation_count = int(cases)
            if first:
                row.first_seen = as_utc(first)
            if last:
                row.last_seen = as_utc(last)
            db.flush()
            return row.to_dict()

    def set_entity_score(self, entity_id: str, score: float) -> None:
        with self._write_lock, self.session() as db:
            row = db.get(Entity, entity_id)
            if row:
                row.score = float(score)
                db.flush()

    def link_entities(
        self,
        src_id: str,
        dst_id: str,
        relation: str,
        *,
        strength: str = "weak",
        confidence: float = 0.0,
        shared: list | None = None,
        investigations: list | None = None,
    ) -> tuple[dict, bool]:
        if src_id == dst_id:
            return {}, False
        with self._write_lock, self.session() as db:
            row = db.scalars(
                select(EntityLink).where(
                    EntityLink.src_id == src_id,
                    EntityLink.dst_id == dst_id,
                    EntityLink.relation == relation,
                )
            ).first()
            if row:
                row.confidence = max(row.confidence, float(confidence))
                if STRENGTH_RANK.get(strength, 0) > STRENGTH_RANK.get(row.strength, 0):
                    row.strength = strength
                merged = list(dict.fromkeys(list(row.shared or []) + list(shared or [])))
                row.shared = merged[:50]
                seen = list(dict.fromkeys(list(row.investigations or []) + list(investigations or [])))
                row.investigations = seen[:50]
                db.flush()
                return row.to_dict(), False
            obj = EntityLink(
                id=uuid.uuid4().hex,
                src_id=src_id,
                dst_id=dst_id,
                relation=relation,
                strength=strength,
                confidence=float(confidence),
                shared=list(shared or [])[:50],
                investigations=list(investigations or [])[:50],
            )
            db.add(obj)
            db.flush()
            return obj.to_dict(), True

    def get_entity(self, entity_id: str) -> dict | None:
        with self.session() as db:
            row = db.get(Entity, entity_id)
            if not row:
                return None
            data = row.to_dict()
            data["members"] = [
                m.to_dict()
                for m in db.scalars(
                    select(EntityMember)
                    .where(EntityMember.entity_id == entity_id)
                    .order_by(EntityMember.first_seen.asc())
                ).all()
            ]
            data["links"] = [
                link.to_dict()
                for link in db.scalars(
                    select(EntityLink).where(
                        or_(EntityLink.src_id == entity_id, EntityLink.dst_id == entity_id)
                    )
                ).all()
            ]
            return data

    def get_entity_by_key(self, key: str) -> dict | None:
        with self.session() as db:
            row = db.scalars(select(Entity).where(Entity.key == key)).first()
            return row.to_dict() if row else None

    def list_entities(
        self,
        *,
        kind: str | None = None,
        limit: int = 100,
        min_investigations: int = 0,
    ) -> list[dict]:
        with self.session() as db:
            stmt = select(Entity)
            if kind:
                stmt = stmt.where(Entity.kind == kind)
            if min_investigations > 0:
                stmt = stmt.where(Entity.investigation_count >= min_investigations)
            stmt = stmt.order_by(
                Entity.investigation_count.desc(), Entity.score.desc(), Entity.last_seen.desc()
            ).limit(max(1, limit))
            return [row.to_dict() for row in db.scalars(stmt).all()]

    def entity_members(self, entity_id: str) -> list[dict]:
        with self.session() as db:
            return [
                m.to_dict()
                for m in db.scalars(
                    select(EntityMember).where(EntityMember.entity_id == entity_id)
                ).all()
            ]

    def entities_for_investigation(self, investigation_id: str) -> list[dict]:
        """Entities touched by one investigation, with their member roles."""
        with self.session() as db:
            pairs = db.execute(
                select(Entity, EntityMember)
                .join(EntityMember, EntityMember.entity_id == Entity.id)
                .where(EntityMember.investigation_id == investigation_id)
                .order_by(Entity.kind.asc(), Entity.score.desc())
            ).all()
            merged: dict[str, dict] = {}
            for entity, member in pairs:
                item = merged.get(entity.id)
                if item is None:
                    item = entity.to_dict()
                    item["roles"] = []
                    item["member_ids"] = []
                    item["evidence_ids"] = []
                    merged[entity.id] = item
                if member.role not in item["roles"]:
                    item["roles"].append(member.role)
                if member.id not in item["member_ids"]:
                    item["member_ids"].append(member.id)
                if member.evidence_id and member.evidence_id not in item["evidence_ids"]:
                    item["evidence_ids"].append(member.evidence_id)
            return list(merged.values())

    def entity_cases(self, entity_id: str) -> list[dict]:
        """Investigations in which this entity has a membership row."""
        with self.session() as db:
            rows = db.scalars(
                select(Investigation)
                .join(EntityMember, EntityMember.investigation_id == Investigation.id)
                .where(EntityMember.entity_id == entity_id)
                .distinct()
                .order_by(Investigation.started_at.desc())
            ).all()
            return [
                {
                    "id": row.id,
                    "seed": row.seed,
                    "seed_type": row.seed_type,
                    "seed_normalized": row.seed_normalized,
                    "status": row.status,
                    "owner": row.owner,
                    "started_at": iso(row.started_at),
                }
                for row in rows
            ]

    def delete_entities(self) -> int:
        """Drop the resolved layer (used by tests and re-resolution)."""
        with self._write_lock, self.session() as db:
            removed = db.execute(delete(Entity)).rowcount or 0
            db.flush()
            return int(removed)

    # -------------------------------------------------------------------- users
    def create_user(self, username: str, password_hash: str, is_admin: bool = True) -> dict:
        with self._write_lock, self.session() as db:
            existing = db.scalars(select(User).where(User.username == username)).first()
            if existing:
                existing.password_hash = password_hash
                db.flush()
                return {"id": existing.id, "username": existing.username, "created": False}
            obj = User(
                id=uuid.uuid4().hex,
                username=username,
                password_hash=password_hash,
                is_admin=is_admin,
            )
            db.add(obj)
            db.flush()
            return {"id": obj.id, "username": obj.username, "created": True}

    def get_user(self, username: str) -> dict | None:
        with self.session() as db:
            row = db.scalars(select(User).where(User.username == username)).first()
            if not row:
                return None
            return {
                "id": row.id,
                "username": row.username,
                "password_hash": row.password_hash,
                "is_admin": row.is_admin,
                "disabled": row.disabled,
                "created_at": row.created_at,
                "last_login_at": row.last_login_at,
            }

    def get_user_by_id(self, user_id: str) -> dict | None:
        with self.session() as db:
            row = db.get(User, user_id)
            if not row:
                return None
            return {
                "id": row.id,
                "username": row.username,
                "is_admin": row.is_admin,
                "disabled": row.disabled,
                "created_at": row.created_at,
                "last_login_at": row.last_login_at,
            }

    def count_users(self) -> int:
        with self.session() as db:
            return int(db.scalar(select(func.count()).select_from(User)) or 0)

    def touch_login(self, user_id: str) -> None:
        with self._write_lock, self.session() as db:
            row = db.get(User, user_id)
            if row:
                row.last_login_at = utcnow()
                db.flush()

    # -------------------------------------------------------------------- audit
    def audit(
        self,
        *,
        actor: str,
        action: str,
        investigation_id: str | None = None,
        seed: str | None = None,
        providers: list[str] | None = None,
        ip: str | None = None,
        detail: dict | None = None,
    ) -> None:
        with self._write_lock, self.session() as db:
            db.add(AuditLog(
                id=uuid.uuid4().hex,
                actor=actor,
                action=action,
                investigation_id=investigation_id,
                seed=seed,
                providers=list(providers or []),
                ip=ip,
                detail=to_jsonable(detail or {}),
            ))
            db.flush()

    def list_audit(self, limit: int = 200) -> list[dict]:
        with self.session() as db:
            rows = db.scalars(select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)).all()
            return [{
                "id": row.id,
                "ts": row.ts,
                "actor": row.actor,
                "action": row.action,
                "investigation_id": row.investigation_id,
                "seed": row.seed,
                "providers": row.providers or [],
                "ip": row.ip,
                "detail": row.detail or {},
            } for row in rows]

    # ------------------------------------------------------------- maintenance
    def purge_older_than(self, days: int) -> dict:
        cutoff = utcnow() - timedelta(days=max(0, days))
        with self.session() as db:
            rows = db.scalars(
                select(Investigation).where(
                    ((Investigation.finished_at.is_not(None)) & (Investigation.finished_at < cutoff))
                    | ((Investigation.finished_at.is_(None)) & (Investigation.started_at < cutoff))
                )
            ).all()
            ids = [row.id for row in rows]
        deleted = []
        for investigation_id in ids:
            self.delete_investigation(investigation_id)
            deleted.append(investigation_id)
        return {"deleted": deleted, "count": len(deleted), "cutoff": iso(cutoff)}

    @staticmethod
    def _inv_dict(row: Investigation) -> dict:
        return {
            "id": row.id,
            "seed": row.seed,
            "seed_type": row.seed_type,
            "seed_normalized": row.seed_normalized,
            "status": row.status,
            "owner": row.owner,
            "config_snapshot": row.config_snapshot or {},
            "coverage": row.coverage or {},
            "stats": row.stats or {},
            "summary": row.summary or {},
            "started_at": row.started_at,
            "finished_at": row.finished_at,
            "error": row.error,
        }

