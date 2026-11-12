"""Domain models shared by the engine, providers and reporting layer."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from dateutil import parser as date_parser
from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def iso(value: datetime | str | None) -> str | None:
    """Normalize any timestamp to UTC ISO-8601 with a `Z` suffix."""
    if value is None:
        return None
    dt = parse_timestamp(value) if not isinstance(value, datetime) else value
    if dt is None:
        return None
    return as_utc(dt).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime | None:
    """Parse many timestamp shapes seen across threat-intel feeds into aware UTC.

    Handles epoch seconds/milliseconds/microseconds, ISO-8601, RFC-2822,
    Wayback's YYYYMMDDhhmmss, crt.sh's naive timestamps and date-only strings.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return as_utc(value)
    if isinstance(value, (int, float)):
        num = float(value)
        if num > 1e17:  # nanoseconds
            num /= 1e9
        elif num > 1e14:  # microseconds
            num /= 1e6
        elif num > 1e11:  # milliseconds
            num /= 1e3
        try:
            return datetime.fromtimestamp(num, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{14}", text):
        try:
            return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if re.fullmatch(r"\d{10}(\.\d+)?", text):
        return parse_timestamp(float(text))
    if re.fullmatch(r"\d{13}", text):
        return parse_timestamp(int(text) / 1000)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = date_parser.parse(text)
    except (ValueError, OverflowError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class IndicatorType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    PHONE = "phone"
    CERT_SHA256 = "cert_sha256"
    FILE_HASH = "file_hash"
    TELEGRAM = "telegram"
    ANALYTICS_ID = "analytics_id"
    NAMESERVER = "nameserver"
    ASN = "asn"
    JA3 = "ja3"
    USERNAME = "username"
    BTC_ADDRESS = "btc_address"
    UNKNOWN = "unknown"


class SelectorStrength(str, Enum):
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"


STRENGTH_RANK = {
    SelectorStrength.STRONG.value: 3,
    SelectorStrength.MEDIUM.value: 2,
    SelectorStrength.WEAK.value: 1,
}


class NormalizedIndicator(BaseModel):
    type: str
    value: str
    normalized: str
    variants: list[dict[str, str]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    display: str | None = None

    def key(self) -> tuple[str, str]:
        return (self.type, self.normalized)


class Observation(BaseModel):
    """A candidate pivot discovered by a provider."""

    type: str
    value: str
    relation: str
    strength: str = SelectorStrength.WEAK.value
    evidence_id: str | None = None
    observed_at: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
    context_only: bool = False
    confidence_hint: float | None = None
    note: str | None = None

    def normalized_key(self) -> tuple[str, str]:
        return (self.type, self.value.strip().lower())


class SightingDraft(BaseModel):
    platform: str
    post_url: str
    post_id: str | None = None
    author_handle: str | None = None
    author_id: str | None = None
    author_created_at: datetime | None = None
    posted_at: datetime | None = None
    text: str = ""
    role: str = "unknown"
    adapter: str | None = None
    indicator_form_matched: str | None = None
    archive_snapshot_url: str | None = None
    local_archive_path: str | None = None
    evidence_id: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class TimelineEventDraft(BaseModel):
    occurred_at: datetime
    source: str
    kind: str
    label: str
    detail: str | None = None
    url: str | None = None
    evidence_id: str | None = None
    indicator_value: str | None = None
    precision: str = "exact"  # exact | day | derived
    meta: dict[str, Any] = Field(default_factory=dict)


class ProviderResult(BaseModel):
    observations: list[Observation] = Field(default_factory=list)
    sightings: list[SightingDraft] = Field(default_factory=list)
    events: list[TimelineEventDraft] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    requests: int = 0
    partial: bool = False


class ProviderStatus(BaseModel):
    name: str
    category: str
    status: str  # enabled | skipped | failed
    reason: str | None = None
    requires_keys: list[str] = Field(default_factory=list)
    missing_keys: list[str] = Field(default_factory=list)
    accepts: list[str] = Field(default_factory=list)
    emits: list[str] = Field(default_factory=list)
    rate_limit: float = 1.0
    timeout: float = 30.0
    reliability: float = 0.8
    passive: bool = True
    phase: str = "A"
    requests: int = 0
    observations: int = 0
    sightings: int = 0
    duration_ms: int = 0
    error: str | None = None


def text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def stable_key(*parts: Any) -> str:
    joined = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()


def truncate(text: str | None, limit: int = 1200) -> str:
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[: max(0, limit - 1)] + "…" if len(text) > limit else text
