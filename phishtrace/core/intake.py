"""Turn one submitted link into an ordered, explained seed set.

A URL is not an IOC.  It is a container: a host, often a deeper subdomain, a
registrable domain, and a path/query string that frequently carries the
operator's mailbox, Telegram handle, phone number, wallet or analytics ID.

This module decomposes a seed deterministically *before* any provider runs, so
the pivot engine expands the selectors that actually exist inside the link
instead of only asking the handful of providers that accept URLs.  Every derived
selector carries its provenance, so the graph can show why it was chased.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

from phishtrace.normalizer import normalize_indicator

#: Hard cap: intake must never turn one link into an unbounded crawl.
MAX_DERIVED = 12

TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "net.za", "gov.za",
    "co.ke", "co.il", "org.il", "co.jp", "ne.jp", "or.jp",
    "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co", "com.pe",
    "co.in", "net.in", "org.in", "co.id", "co.th", "com.sg", "com.my",
    "com.tr", "com.ua", "com.pl", "com.ru", "com.cn", "com.hk", "com.tw",
    "co.kr", "or.kr", "com.sa", "com.eg", "com.ng", "com.gh",
    "gov.in", "ac.in", "edu.in", "res.in",
})

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
TELEGRAM_PATH_RE = re.compile(r"^/(?:s/)?([A-Za-z][A-Za-z0-9_]{3,31})/?$")
ANALYTICS_PATTERNS = (
    ("UA", re.compile(r"\bUA-\d{4,12}-\d{1,4}\b", re.IGNORECASE)),
    ("GA4", re.compile(r"\bG-[A-Z0-9]{6,14}\b")),
    ("GTM", re.compile(r"\bGTM-[A-Z0-9]{4,12}\b")),
    ("ADS", re.compile(r"\bAW-\d{6,12}\b")),
)
WALLET_RE = re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")

PHONE_KEYS = frozenset({"phone", "tel", "telephone", "msisdn", "mobile", "whatsapp", "wa"})
TELEGRAM_KEYS = frozenset({"telegram", "tg", "telegram_id", "channel"})
WALLET_KEYS = frozenset({"btc", "btc_address", "wallet", "address", "crypto"})

TELEGRAM_HOSTS = frozenset({"t.me", "telegram.me", "telegram.dog", "tlgrm.eu"})
URL_SHORTENERS = frozenset({
    "bit.ly", "bitly.com", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "t.ly", "tiny.cc",
})

_PRIORITY = {
    "url-host": 0,
    "url-email": 1,
    "url-telegram": 1,
    "email-domain": 1,
    "url-phone": 2,
    "url-analytics": 2,
    "url-wallet": 2,
    "registrable-domain": 4,
    "parent-domain": 6,
}


@dataclass(frozen=True)
class DerivedSeed:
    """One selector found inside a seed, with the evidence for chasing it."""

    value: str
    type: str
    relation: str
    reason: str
    priority: int = 5
    strength: str = "strong"
    confidence: float = 0.95
    context_only: bool = False
    tags: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type,
            "relation": self.relation,
            "reason": self.reason,
            "priority": self.priority,
            "strength": self.strength,
            "confidence": self.confidence,
            "context_only": self.context_only,
            "tags": list(self.tags),
        }


@dataclass(frozen=True)
class IntakePlan:
    """Ordered decomposition of one seed. Pure data: no I/O, no network."""

    raw: str
    normalized: str
    seed_type: str
    derived: tuple[DerivedSeed, ...] = ()
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "seed": self.raw,
            "normalized": self.normalized,
            "seed_type": self.seed_type,
            "derived": [item.as_dict() for item in self.derived],
            "notes": list(self.notes),
            "count": len(self.derived),
        }


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without shipping a public-suffix list."""
    host = (host or "").strip().strip(".").lower()
    if not host or ":" in host:
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in TWO_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _normalized(raw: str, kind: str | None = None):
    try:
        return normalize_indicator(raw, kind=kind)
    except (TypeError, ValueError):
        return None


def _add(derived: list[DerivedSeed], seen: set[tuple[str, str]], item: DerivedSeed) -> None:
    key = (item.type, item.value.strip().lower())
    if key in seen:
        return
    seen.add(key)
    derived.append(item)


def _scan_tokens(tokens: list[tuple[str, str]], derived, seen) -> None:
    """Extract selectors from decoded path/query tokens, keyed by parameter name."""
    for name, token in tokens:
        value = token.strip()
        if not value:
            continue
        for match in EMAIL_RE.findall(value):
            selector = _normalized(match, "email")
            if selector:
                where = f"query parameter '{name}'" if name else "URL path"
                _add(derived, seen, DerivedSeed(
                    match, selector.type, "url-email",
                    f"mailbox found in {where} of the submitted link",
                    1, "strong", 0.9, False, ("intake", "url-email"),
                ))
        if name in TELEGRAM_KEYS or value.startswith("@"):
            handle = value.lstrip("@")
            selector = _normalized(handle, "telegram")
            if selector and not EMAIL_RE.search(value):
                _add(derived, seen, DerivedSeed(
                    handle, selector.type, "url-telegram",
                    f"Telegram handle found in query parameter '{name}'",
                    1, "strong", 0.8, False, ("intake",),
                ))
        if name in PHONE_KEYS:
            digits = re.sub(r"[^\d+]", "", value)
            if 9 <= len(digits.lstrip("+")) <= 15:
                selector = _normalized(digits, "phone")
                if selector:
                    _add(derived, seen, DerivedSeed(
                        digits, selector.type, "url-phone",
                        f"phone number found in query parameter '{name}'",
                        2, "strong", 0.85, False, ("intake",),
                    ))
        for label, pattern in ANALYTICS_PATTERNS:
            match = pattern.search(value)
            if match:
                selector = _normalized(match.group(0), "analytics_id")
                if selector:
                    _add(derived, seen, DerivedSeed(
                        match.group(0), selector.type, "url-analytics",
                        f"{label} tracking ID embedded in the submitted link",
                        2, "strong", 0.9, False, ("intake",),
                    ))
        if name in WALLET_KEYS or WALLET_RE.fullmatch(value):
            match = WALLET_RE.search(value)
            if match:
                selector = _normalized(match.group(0), "btc_address")
                if selector:
                    _add(derived, seen, DerivedSeed(
                        match.group(0), selector.type, "url-wallet",
                        "cryptocurrency address embedded in the submitted link",
                        2, "strong", 0.8, False, ("intake",),
                    ))


def plan_intake(raw: str, *, kind: str | None = None) -> IntakePlan:
    """Decompose ``raw`` into the selectors worth investigating, in order."""
    seed = _normalized(raw, kind)
    if seed is None:
        return IntakePlan(
            raw=str(raw), normalized="", seed_type="",
            notes=("seed could not be normalized; no intake plan",),
        )

    derived: list[DerivedSeed] = []
    seen: set[tuple[str, str]] = set()
    notes: list[str] = []

    if seed.type == "url":
        try:
            parts = urlsplit(seed.value if "://" in seed.value else "http://" + seed.value)
            port = parts.port
        except ValueError:
            return IntakePlan(
                raw=str(raw), normalized=seed.normalized, seed_type=seed.type,
                notes=("URL could not be parsed",),
            )
        host = (parts.hostname or "").strip(".").lower()
        if parts.scheme not in ("http", "https"):
            notes.append(
                f"scheme '{parts.scheme}' is not HTTP(S); the link may be a redirector or non-web URI"
            )
        if not host:
            notes.append("URL has no host component")
        if parts.username:
            notes.append("URL embeds credentials in the userinfo section; they were not copied into the plan")
        if port and port not in (80, 443):
            notes.append(f"URL uses non-standard port {port}")

        if host:
            host_selector = _normalized(host)
            if host_selector:
                _add(derived, seen, DerivedSeed(
                    host, host_selector.type, "url-host",
                    "hostname of the submitted link",
                    0, "strong", 1.0, False, ("intake", "url-host"),
                ))
            if host.startswith("xn--") or ".xn--" in host:
                try:
                    decoded = host.encode("ascii").decode("idna")
                    notes.append(f"host is punycode; decoded form is '{decoded}'")
                except (UnicodeError, ValueError):
                    notes.append("host is punycode and could not be decoded")

            parent = registrable_domain(host) if host_selector and host_selector.type == "domain" else ""
            if parent and parent != host:
                parent_selector = _normalized(parent)
                if parent_selector:
                    _add(derived, seen, DerivedSeed(
                        parent, parent_selector.type, "registrable-domain",
                        f"registrable domain behind {host}",
                        4, "strong", 0.9, False, ("intake", "registrable-domain"),
                    ))
            if parent in URL_SHORTENERS:
                notes.append(
                    f"{parent} is a URL shortener: the destination must be resolved before attribution"
                )

        tokens: list[tuple[str, str]] = []
        if parts.path and parts.path not in ("", "/"):
            tokens.append(("", unquote(parts.path)))
            segments = [segment for segment in unquote(parts.path).split("/") if segment]
            if len(segments) == 1:
                tokens.append(("", segments[0]))
        for name, value in parse_qsl(parts.query, keep_blank_values=False):
            tokens.append((name.lower(), unquote(value)))
        if host in TELEGRAM_HOSTS:
            match = TELEGRAM_PATH_RE.match(parts.path or "")
            if match:
                tokens.append(("telegram", match.group(1)))
        _scan_tokens(tokens, derived, seen)

    elif seed.type == "domain":
        parent = registrable_domain(seed.normalized)
        if parent and parent != seed.normalized:
            selector = _normalized(parent)
            if selector:
                _add(derived, seen, DerivedSeed(
                    parent, selector.type, "parent-domain",
                    f"registrable domain that controls {seed.normalized}",
                    6, "medium", 0.8, False, ("intake",),
                ))

    elif seed.type == "email":
        domain = seed.normalized.rsplit("@", 1)[-1]
        selector = _normalized(domain)
        if selector:
            _add(derived, seen, DerivedSeed(
                domain, selector.type, "email-domain",
                "mail domain of the submitted address",
                1, "strong", 0.95, False, ("intake",),
            ))

    else:
        notes.append(f"no deterministic decomposition for seed type '{seed.type}'")

    derived.sort(key=lambda item: (item.priority, item.relation, item.value))
    return IntakePlan(
        raw=str(raw), normalized=seed.normalized, seed_type=seed.type,
        derived=tuple(derived[:MAX_DERIVED]), notes=tuple(dict.fromkeys(notes)),
    )
