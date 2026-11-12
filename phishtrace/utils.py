"""Small shared helpers."""

from __future__ import annotations

import json
import math
import re
import unicodedata
from datetime import date, datetime
from enum import Enum
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from phishtrace.models import as_utc, iso


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def round_conf(value: float) -> float:
    return round(clamp(value), 3)


def json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return iso(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return str(value)


def to_jsonable(value: Any) -> Any:
    """Recursively convert ORM/datetime/enum structures into JSON-safe data."""
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, (datetime, date)):
        return iso(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if hasattr(value, "to_dict"):
        return to_jsonable(value.to_dict())
    return str(value)


def dumps(value: Any, **kwargs) -> str:
    return json.dumps(to_jsonable(value), ensure_ascii=False, default=json_default, **kwargs)


def slugify(value: str, max_len: int = 60) -> str:
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return (value or "item")[:max_len].strip("-") or "item"


def host_from_url(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def origin_from_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def truncate_middle(value: str, limit: int = 80) -> str:
    if len(value) <= limit:
        return value
    head = max(1, (limit - 1) // 2)
    tail = max(1, limit - head - 1)
    return f"{value[:head]}…{value[-tail:]}"


def parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def utc_iso(value: Any) -> str | None:
    return iso(as_utc(value)) if isinstance(value, datetime) else iso(value)
