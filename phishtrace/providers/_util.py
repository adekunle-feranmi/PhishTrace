"""Shared helpers for provider plugins.

Providers deal with a lot of half-structured data from public APIs.  These
helpers keep the parsing code short and, more importantly, keep a single bad
record from aborting an entire provider run.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit

from dateutil import parser as date_parser

from phishtrace.models import as_utc, parse_timestamp
from phishtrace.normalizer import clean_text, registrable_domain, refang


def text(value: Any) -> str:
    if value is None:
        return ""
    return clean_text(str(value)).strip()


def first(mapping: Any, *keys: str, default: Any = None) -> Any:
    """Return the first present, non-empty key from a mapping."""
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping and mapping[key] not in (None, "", [], {}):
            return mapping[key]
    return default


def as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str):
        return [value] if value.strip() else []
    return []


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def iterate_dicts(value: Any, *, max_items: int = 500) -> Iterator[dict]:
    count = 0
    for item in as_list(value):
        if count >= max_items:
            return
        if isinstance(item, dict):
            count += 1
            yield item
        elif isinstance(item, str) and item.strip():
            count += 1
            yield {"value": item.strip()}


def parse_date(value: Any):
    """Lenient date parser that never raises."""
    if value in (None, "", 0):
        return None
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            return parse_timestamp(raw)
        except Exception:  # noqa: BLE001
            pass
        try:
            dt = date_parser.parse(raw, fuzzy=True)
            return as_utc(dt)
        except (ValueError, OverflowError, TypeError):
            return None
    try:
        return parse_timestamp(value)
    except Exception:  # noqa: BLE001
        return None


def url_host(value: Any) -> str:
    raw = refang(text(value))
    if not raw:
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.IGNORECASE):
        raw = "http://" + raw
    try:
        return (urlsplit(raw).hostname or "").lower().strip(".")
    except ValueError:
        return ""


def host_matches(host: str, needle: str) -> bool:
    """True when ``host`` is ``needle`` or a subdomain of it."""
    host = (host or "").lower().strip(".")
    needle = (needle or "").lower().strip(".")
    if not host or not needle:
        return False
    return host == needle or host.endswith("." + needle)


def belongs_to_domain(url_or_host: Any, domain: str) -> bool:
    """True when the host is ``domain`` itself or a subdomain of it.

    Deliberately strict: an earlier version also accepted hosts whose registrable
    domain contained the target, which let ``stranger@elsewhere.example`` pass as
    in-scope when the public-suffix lookup collapsed both to ``example``.
    """
    host = url_host(url_or_host if "//" in str(url_or_host) else f"http://{url_or_host}")
    if not host:
        return False
    return host_matches(host, domain)


def safe_ip(value: Any) -> str | None:
    raw = text(value).strip("[]")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return None


def safe_domain(value: Any) -> str | None:
    raw = text(value).lower().strip(".")
    if raw.startswith("*."):
        raw = raw[2:]
    if not raw or " " in raw or "." not in raw:
        return None
    try:
        ascii_host = raw.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return None
    if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", ascii_host):
        return None
    if safe_ip(ascii_host):
        return None
    return ascii_host


def strip_tags(value: Any) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text(value))).strip()


def result_error(result: Any) -> str:
    return text(getattr(result, "error", "") or f"HTTP {getattr(result, 'status', '?')}")


def iter_lines(body: str, *, limit: int = 5000) -> Iterator[str]:
    for index, line in enumerate(body.splitlines()):
        if index >= limit:
            return
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def indicator_host(indicator: Any) -> str:
    """Host part of a URL/domain indicator, or the IP itself."""
    if indicator is None:
        return ""
    if indicator.type in {"domain", "ip"}:
        return indicator.normalized
    if indicator.type == "url":
        for variant in indicator.variants:
            if variant.get("kind") == "host":
                return variant.get("value", "")
        return url_host(indicator.normalized)
    return ""


def indicator_url(indicator: Any) -> str:
    if indicator is None:
        return ""
    if indicator.type == "url":
        return indicator.normalized
    return ""


def dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output
