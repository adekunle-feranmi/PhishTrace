"""SQLite/SQLAlchemy schema for PhishTrace."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint,
    create_engine, event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from phishtrace.models import utcnow


class Base(DeclarativeBase):
    pass


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    seed: Mapped[str] = mapped_column(Text)
    seed_type: Mapped[str] = mapped_column(String(32))
    seed_normalized: Mapped[str] = mapped_column(Text, index=True)
    status: Mapped[str] = mapped_column(String(24), default="running", index=True)
    owner: Mapped[str] = mapped_column(String(128), default="cli")
    config_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    coverage: Mapped[dict] = mapped_column(JSON, default=dict)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    indicators: Mapped[list["Indicator"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")
    edges: Mapped[list["Edge"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")


class Indicator(Base):
    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("investigation_id", "type", "normalized_value", name="uq_indicator"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(Text)
    normalized_value: Mapped[str] = mapped_column(Text)
    first_seen_in_run: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    path_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    context_only: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped[Investigation] = relationship(back_populates="indicators")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "depth": self.depth,
            "path_confidence": self.path_confidence,
            "tags": self.tags or [],
            "context_only": self.context_only,
            "first_seen_in_run": self.first_seen_in_run,
            "meta": self.meta or {},
        }


class Edge(Base):
    __tablename__ = "edges"
    __table_args__ = (
        UniqueConstraint("investigation_id", "src_id", "dst_id", "relation", "provider", name="uq_edge"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    src_id: Mapped[str] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[str] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    relation: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    selector_strength: Mapped[str] = mapped_column(String(16), default="weak")
    evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    investigation: Mapped[Investigation] = relationship(back_populates="edges")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "src": self.src_id,
            "dst": self.dst_id,
            "relation": self.relation,
            "provider": self.provider,
            "confidence": self.confidence,
            "selector_strength": self.selector_strength,
            "evidence_id": self.evidence_id,
            "observed_at": self.observed_at,
            "meta": self.meta or {},
        }


class Sighting(Base):
    __tablename__ = "sightings"
    __table_args__ = (UniqueConstraint("investigation_id", "dedupe_key", name="uq_sighting"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    indicator_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    indicator_form_matched: Mapped[str] = mapped_column(Text)
    platform: Mapped[str] = mapped_column(String(48), index=True)
    post_url: Mapped[str] = mapped_column(Text)
    post_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    author_handle: Mapped[str | None] = mapped_column(String(256), nullable=True)
    author_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    author_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    posted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    text_excerpt: Mapped[str] = mapped_column(Text, default="")
    text_sha256: Mapped[str] = mapped_column(String(64), default="")
    role: Mapped[str] = mapped_column(String(24), default="unknown")
    archive_snapshot_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    local_archive_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(64))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "indicator_id": self.indicator_id,
            "indicator_form_matched": self.indicator_form_matched,
            "platform": self.platform,
            "post_url": self.post_url,
            "post_id": self.post_id,
            "author_handle": self.author_handle,
            "author_id": self.author_id,
            "author_created_at": self.author_created_at,
            "posted_at": self.posted_at,
            "retrieved_at": self.retrieved_at,
            "text_excerpt": self.text_excerpt,
            "text_sha256": self.text_sha256,
            "role": self.role,
            "archive_snapshot_url": self.archive_snapshot_url,
            "local_archive_path": self.local_archive_path,
            "evidence_id": self.evidence_id,
            "meta": self.meta or {},
        }


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("investigation_id", "dedupe_key", name="uq_evidence"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(64), index=True)
    request: Mapped[dict] = mapped_column(JSON, default=dict)
    raw_response_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    dedupe_key: Mapped[str] = mapped_column(String(64))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider,
            "request": self.request or {},
            "raw_response_path": self.raw_response_path,
            "sha256": self.sha256,
            "retrieved_at": self.retrieved_at,
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
        }


class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    __table_args__ = (UniqueConstraint("investigation_id", "dedupe_key", name="uq_timeline"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(48))
    label: Mapped[str] = mapped_column(Text)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    indicator_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    precision: Mapped[str] = mapped_column(String(16), default="exact")
    dedupe_key: Mapped[str] = mapped_column(String(64))
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "occurred_at": self.occurred_at,
            "source": self.source,
            "kind": self.kind,
            "label": self.label,
            "detail": self.detail,
            "url": self.url,
            "evidence_id": self.evidence_id,
            "indicator_value": self.indicator_value,
            "precision": self.precision,
            "meta": self.meta or {},
        }


class ProviderRun(Base):
    __tablename__ = "provider_runs"
    __table_args__ = (UniqueConstraint("investigation_id", "provider", name="uq_provider_run"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(24), default="ran")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    requests: Mapped[int] = mapped_column(Integer, default=0)
    observations: Mapped[int] = mapped_column(Integer, default=0)
    sightings: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "category": self.category,
            "status": self.status,
            "reason": self.reason,
            "requests": self.requests,
            "observations": self.observations,
            "sightings": self.sightings,
            "errors": self.errors or [],
            "duration_ms": self.duration_ms,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "extra": self.extra or {},
        }


class KitAnalysis(Base):
    __tablename__ = "kit_analyses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    indicator_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    url: Mapped[str] = mapped_column(Text)
    kit_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_tree_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ssdeep: Mapped[str | None] = mapped_column(Text, nullable=True)
    tlsh: Mapped[str | None] = mapped_column(String(128), nullable=True)
    exfil_emails: Mapped[list] = mapped_column(JSON, default=list)
    telegram_bots: Mapped[list] = mapped_column(JSON, default=list)
    webhooks: Mapped[list] = mapped_column(JSON, default=list)
    analytics_ids: Mapped[list] = mapped_column(JSON, default=list)
    author_strings: Mapped[list] = mapped_column(JSON, default=list)
    brand: Mapped[str | None] = mapped_column(String(128), nullable=True)
    form_fields: Mapped[list] = mapped_column(JSON, default=list)
    files: Mapped[list] = mapped_column(JSON, default=list)
    exposed_paths: Mapped[list] = mapped_column(JSON, default=list)
    credential_exposure_count: Mapped[int] = mapped_column(Integer, default=0)
    credential_exposure_types: Mapped[list] = mapped_column(JSON, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "indicator_id": self.indicator_id,
            "url": self.url,
            "kit_sha256": self.kit_sha256,
            "file_tree_hash": self.file_tree_hash,
            "ssdeep": self.ssdeep,
            "tlsh": self.tlsh,
            "exfil_emails": self.exfil_emails or [],
            "telegram_bots": self.telegram_bots or [],
            "webhooks": self.webhooks or [],
            "analytics_ids": self.analytics_ids or [],
            "author_strings": self.author_strings or [],
            "brand": self.brand,
            "form_fields": self.form_fields or [],
            "files": self.files or [],
            "exposed_paths": self.exposed_paths or [],
            "credential_exposure_count": self.credential_exposure_count,
            "credential_exposure_types": self.credential_exposure_types or [],
            "notes": self.notes,
            "created_at": self.created_at,
        }


class Entity(Base):
    """A durable join key shared by indicators from one or more investigations.

    ``kind`` is ``identity`` (email, phone, handle, wallet, publisher ID),
    ``infrastructure`` (certificate, nameserver pair, provider desk) or
    ``case`` (one investigation).  ``key`` is the normalized join key and is
    globally unique: that uniqueness is what makes resolution work across
    investigations instead of only inside one.
    """

    __tablename__ = "entities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    key: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    label: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    member_count: Mapped[int] = mapped_column(Integer, default=0)
    investigation_count: Mapped[int] = mapped_column(Integer, default=0, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    members: Mapped[list["EntityMember"]] = relationship(
        back_populates="entity", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "key": self.key,
            "label": self.label,
            "confidence": self.confidence,
            "score": self.score,
            "member_count": self.member_count,
            "investigation_count": self.investigation_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "meta": self.meta or {},
        }


class EntityMember(Base):
    """Why one indicator belongs to one entity.  Every claim is traceable."""

    __tablename__ = "entity_members"
    __table_args__ = (
        UniqueConstraint("entity_id", "investigation_id", "indicator_id", "role",
                         name="uq_entity_member"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    entity_id: Mapped[str] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    indicator_id: Mapped[str | None] = mapped_column(
        ForeignKey("indicators.id", ondelete="CASCADE"), nullable=True, index=True)
    role: Mapped[str] = mapped_column(String(32), default="contact")
    join_rule: Mapped[str] = mapped_column(String(48))
    strength: Mapped[str] = mapped_column(String(16), default="weak")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    entity: Mapped[Entity] = relationship(back_populates="members")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "entity_id": self.entity_id,
            "investigation_id": self.investigation_id,
            "indicator_id": self.indicator_id,
            "role": self.role,
            "join_rule": self.join_rule,
            "strength": self.strength,
            "confidence": self.confidence,
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "first_seen": self.first_seen,
            "meta": self.meta or {},
        }


class EntityLink(Base):
    """An edge between two entities, e.g. identity -> case."""

    __tablename__ = "entity_links"
    __table_args__ = (
        UniqueConstraint("src_id", "dst_id", "relation", name="uq_entity_link"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    src_id: Mapped[str] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[str] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    relation: Mapped[str] = mapped_column(String(64))
    strength: Mapped[str] = mapped_column(String(16), default="weak")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    shared: Mapped[list] = mapped_column(JSON, default=list)
    investigations: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "src": self.src_id,
            "dst": self.dst_id,
            "relation": self.relation,
            "strength": self.strength,
            "confidence": self.confidence,
            "shared": self.shared or [],
            "investigations": self.investigations or [],
        }


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    action: Mapped[str] = mapped_column(String(64))
    investigation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    seed: Mapped[str | None] = mapped_column(Text, nullable=True)
    providers: Mapped[list] = mapped_column(JSON, default=list)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


def make_engine(url: str, *, echo: bool = False) -> Engine:
    kwargs: dict = {"echo": echo, "future": True, "pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _record):  # pragma: no cover - driver hook
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()
    return engine


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db(url: str, data_dir: Path) -> tuple[Engine, sessionmaker]:
    if url.startswith("sqlite"):
        data_dir.mkdir(parents=True, exist_ok=True)
    engine = make_engine(url)
    Base.metadata.create_all(engine)
    return engine, make_session_factory(engine)
