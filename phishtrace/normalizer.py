"""Indicator normalization, refanging and extraction.

Everything that enters PhishTrace passes through this module, so that the same
infrastructure never appears twice under cosmetic differences (``HXXP://`` vs
``http://``, ``evil[.]com`` vs ``evil.com``, ``+234803...`` vs ``0803...``).

Design rules
------------
* Never invent data: a value that cannot be validated keeps its raw form and
  gets an ``unverified`` style tag instead of being silently "fixed".
* Never persist secrets: Telegram bot tokens are reduced to ``bot:<id>`` and
  URL userinfo passwords are stripped before storage.
* Deterministic: identical input always yields the identical normalized value,
  which is what lets the storage layer deduplicate nodes and sightings.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from typing import Iterable, Iterator
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import phonenumbers
import publicsuffix2

from phishtrace.models import IndicatorType, NormalizedIndicator

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

#: Query parameters that only carry marketing/analytics state.  Removing them
#: makes two visits to the same phishing page collapse to one canonical URL.
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_name", "utm_cid", "utm_reader", "utm_referrer", "utm_creative_format",
    "fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid", "msclkid",
    "mc_cid", "mc_eid", "mkt_tok", "igshid", "si", "spm", "scm", "_ga", "_gl",
    "yclid", "twclid", "ttclid", "li_fat_id", "vero_id", "oly_anon_id", "oly_enc_id",
    "ref", "referrer", "aff_id", "affiliate_id", "click_id", "trk", "trk_contact",
}

DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}

#: Characters invisible in rendered text but meaningful to parsers.
ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)

#: Latin/Greek/Cyrillic ranges used for a cheap mixed-script (homoglyph) check.
_SCRIPT_RANGES = {
    "latin": ((0x0041, 0x024F), (0x1E00, 0x1EFF)),
    "cyrillic": ((0x0400, 0x04FF), (0x0500, 0x052F)),
    "greek": ((0x0370, 0x03FF), (0x1F00, 0x1FFF)),
    "cjk": ((0x3040, 0x30FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF)),
    "arabic": ((0x0600, 0x06FF), (0x0750, 0x077F)),
    "hebrew": ((0x0590, 0x05FF),),
    "devanagari": ((0x0900, 0x097F),),
}

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9\u00a1-\uffff](?:[a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?\.)+"
    r"[a-z\u00a1-\uffff]{2,63}\.?$",
    re.IGNORECASE,
)
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
ASN_RE = re.compile(r"^(?:AS|ASN)[\s:-]?(\d{1,10})$", re.IGNORECASE)
JA3_RE = re.compile(r"^(?:ja3[:=])?([a-f0-9]{32})$", re.IGNORECASE)
TELEGRAM_TOKEN_RE = re.compile(r"^(\d{5,12}):([A-Za-z0-9_-]{30,})$")
TELEGRAM_HANDLE_RE = re.compile(r"^@?([A-Za-z][A-Za-z0-9_]{4,31})$")
ANALYTICS_RE = re.compile(
    r"^(?:(UA)-\d{4,10}-\d{1,4}|(G|GTM|AW|MC|YO|HJ)-[A-Za-z0-9]{4,20}|(DC)-\d{4,10})$",
    re.IGNORECASE,
)
BTC_BASE58_RE = re.compile(r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$")
BTC_BECH32_RE = re.compile(r"^(bc1)[02-9ac-hj-np-z]{11,71}$", re.IGNORECASE)
CERT_PREFIX_RE = re.compile(r"^(?:cert(?:ificate)?|sha256|cert_sha256)[:=]\s*", re.IGNORECASE)
NS_PREFIX_RE = re.compile(r"^(?:ns|nameserver)[:=]\s*", re.IGNORECASE)
USERNAME_PREFIX_RE = re.compile(r"^(?:user|username|handle)[:=]\s*", re.IGNORECASE)
BTC_PREFIX_RE = re.compile(r"^(?:btc|bitcoin)[:=]\s*", re.IGNORECASE)

URL_CANDIDATE_RE = re.compile(
    r"(?:hxxps?|https?|ftp)://[^\s<>\"'`\]\[}{]+",
    re.IGNORECASE,
)
BARE_DOMAIN_RE = re.compile(
    r"(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?::\d{2,5})?(?:/[^\s<>\"'\)\]]*)?",
    re.IGNORECASE,
)
EMAIL_SCAN_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b")
TELEGRAM_URL_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/(?:s/)?([A-Za-z0-9_+/-]{2,64})", re.IGNORECASE)
ANALYTICS_SCAN_RE = re.compile(r"\b(?:UA-\d{4,10}-\d{1,4}|(?:G|GTM|AW|MC|YO|HJ)-[A-Za-z0-9]{4,20})\b")
BTC_SCAN_RE = re.compile(r"\b(?:bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})\b")
CERT_SCAN_RE = re.compile(r"\b(?:cert(?:ificate)?|sha256)[:=]\s*([a-fA-F0-9]{64})", re.IGNORECASE)
PHONE_SCAN_RE = re.compile(r"(?<![\w.])(?:\+\d{7,15}|0\d{8,14})(?![\w.])")


# --------------------------------------------------------------------------- #
# Low-level text helpers
# --------------------------------------------------------------------------- #

def clean_text(text: str, *, limit: int = 1_000_000) -> str:
    """Normalize unicode, drop zero-width characters, collapse whitespace."""
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", str(text))[:limit]
    return text.translate(ZERO_WIDTH)


_REFANG_RULES = (
    (re.compile(r"hxxps?", re.IGNORECASE), lambda m: m.group(0).lower().replace("xx", "tt")),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}", re.IGNORECASE), "."),
    (re.compile(r"\[:\]|\(:\)|\{:\}|\[colon\]", re.IGNORECASE), ":"),
    (re.compile(r"\[@\]|\(@\)|\{@\}|\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\[/\]|\(/\)", re.IGNORECASE), "/"),
    (re.compile(r"h\s+tt\s+ps?", re.IGNORECASE), lambda m: re.sub(r"\s+", "", m.group(0))),
    (re.compile(r"\\\."), "."),
    (re.compile(r"\[(?=[a-z0-9-]+\.[a-z]{2,})"), ""),
)


def refang(value: str) -> str:
    """Turn ``hxxp://evil[.]com`` into ``http://evil.com``.

    This is intentionally conservative: it only rewrites well-known defanging
    conventions, and it never changes the meaning of an otherwise valid URL.
    """
    if not value:
        return ""
    text = clean_text(value).strip().strip("<>\"'`")
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    # Broken copy/paste from PDFs sometimes renders "evil . com". Only repair
    # it when the whole value is a lone token, so sentence punctuation is safe.
    stripped = text.strip()
    if " . " in stripped and not re.search(r"\s", stripped.replace(" . ", "")):
        stripped = stripped.replace(" . ", ".")
    return stripped


def defang(value: str) -> str:
    """Make an indicator safe to paste into chat/email."""
    if not value:
        return ""
    text = str(value).replace("://", "[:]//")
    text = text.replace(".", "[.]")
    return text.replace("@", "[@]")


def defang_url(url: str) -> str:
    return defang(url)


def _strip_credentials(parts) -> tuple[str, str | None]:
    """Return a netloc without userinfo and the username if one was present."""
    netloc = parts.netloc
    if "@" not in netloc:
        return netloc, None
    userinfo, _, hostport = netloc.rpartition("@")
    username = unquote(userinfo.split(":", 1)[0]) or None
    return hostport, username


def _ascii_host(host: str) -> str:
    host = host.strip().strip(".").lower()
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return host


def _unicode_host(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return host


def _host_scripts(host: str) -> set[str]:
    """Scripts used in the registrable label(s), ignoring the ASCII suffix."""
    unicode_host = _unicode_host(host)
    try:
        suffix = publicsuffix2.get_tld(host) or ""
    except Exception:  # noqa: BLE001
        suffix = ""
    if suffix and unicode_host.lower().endswith("." + suffix.lower()):
        unicode_host = unicode_host[: -(len(suffix) + 1)]
    scripts: set[str] = set()
    for char in unicode_host:
        code = ord(char)
        if code < 0x80:
            if char.isalpha():
                scripts.add("latin")
            continue
        for name, ranges in _SCRIPT_RANGES.items():
            if any(low <= code <= high for low, high in ranges):
                scripts.add(name)
                break
    return scripts


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    """True for addresses that must never be contacted by the fetcher."""
    try:
        ip = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def registrable_domain(host: str) -> str:
    """Registrable domain ("eTLD+1") using the public suffix list."""
    host = _ascii_host(host or "")
    if not host or _is_ip(host):
        return host
    try:
        sld = publicsuffix2.get_sld(host)
    except Exception:  # noqa: BLE001 - PSL data issues must not break a run
        sld = ""
    if sld:
        return sld.lower().strip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _valid_domain(host: str) -> bool:
    if not host or len(host) > 253 or "." not in host:
        return False
    ascii_host = _ascii_host(host)
    if _is_ip(ascii_host):
        return False
    labels = ascii_host.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    if not all(LABEL_RE.match(label) for label in labels):
        return False
    tld = labels[-1]
    if tld.isdigit() or len(tld) < 2:
        return False
    if "." not in ascii_host and not tld.isalpha():
        return False
    try:
        return bool(publicsuffix2.get_tld(ascii_host))
    except Exception:  # noqa: BLE001
        return True


# --------------------------------------------------------------------------- #
# URL canonicalization
# --------------------------------------------------------------------------- #

def _canonical_query(query: str) -> str:
    pairs = parse_qsl(query, keep_blank_values=True)
    kept = [
        (key, value) for key, value in pairs
        if key.lower() not in TRACKING_PARAMS and not key.lower().startswith("utm_")
    ]
    kept.sort(key=lambda kv: (kv[0].lower(), kv[1]))
    return urlencode(kept, doseq=True, quote_via=quote)


def canonicalize_url(raw: str, *, keep_tracking: bool = False) -> dict:
    """Return canonical URL plus the components needed for pivoting.

    Raises ``ValueError`` when the input cannot be interpreted as a URL.
    """
    text = refang(raw)
    if not text:
        raise ValueError("empty URL")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", text, re.IGNORECASE):
        # Bare host/path input: assume plain http, and record the assumption.
        if not re.match(r"^[a-z0-9\u00a1-\uffff\[].*", text, re.IGNORECASE):
            raise ValueError("not a URL")
        text = "http://" + text
    parts = urlsplit(text)
    scheme = (parts.scheme or "http").lower()
    netloc, username = _strip_credentials(parts)
    if not netloc:
        raise ValueError("URL has no host")
    if "@" in netloc:  # strip a second layer of userinfo (e.g. //user@host@evil)
        netloc, username = _strip_credentials(urlsplit(f"//{netloc}"))
    host_raw = netloc
    port: int | None = None
    if netloc.startswith("["):  # IPv6 literal
        host_raw, _, rest = netloc.partition("]")
        host_raw += "]"
        if rest.startswith(":"):
            try:
                port = int(rest[1:])
            except ValueError:
                port = None
    elif ":" in netloc:
        host_raw, _, port_text = netloc.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            port = None
    host = _ascii_host(host_raw.strip("[]"))
    if not host:
        raise ValueError("URL has no host")
    if _is_ip(host):
        host = str(ipaddress.ip_address(host))
    display_host = f"[{host}]" if ":" in host else host
    if port is not None and DEFAULT_PORTS.get(scheme) == port:
        port = None
    netloc = display_host + (f":{port}" if port is not None else "")

    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    # Collapse dot-segments without touching percent-encoded octets.
    try:
        path = re.sub(r"/{2,}", "/", path)
    except re.error:  # pragma: no cover - defensive
        pass
    query = parts.query if keep_tracking else _canonical_query(parts.query)

    canonical = urlunsplit((scheme, netloc, path, query, ""))
    return {
        "url": canonical,
        "scheme": scheme,
        "host": host,
        "display_host": display_host,
        "port": port,
        "path": path,
        "query": query,
        "username": username,
        "assumed_scheme": not re.match(r"^[a-z][a-z0-9+.-]*://", refang(raw), re.IGNORECASE),
    }


def _url_variants(info: dict, raw: str) -> list[dict[str, str]]:
    variants: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        if not value:
            return
        key = (kind, value.lower())
        if key in seen:
            return
        seen.add(key)
        variants.append({"kind": kind, "value": value})

    canonical = info["url"]
    host = info["host"]
    path = info["path"]
    add("url", canonical)
    add("url_defanged", defang(canonical))
    add("host", host)
    add("domain", registrable_domain(host) if not _is_ip(host) else host)
    if path and path != "/":
        add("path", path)
        if info["query"]:
            add("path_query", f"{path}?{info['query']}")
    if info["query"]:
        add("query", info["query"])
    if info["username"]:
        add("username", info["username"])
    if host.startswith("xn--") or ".xn--" in host:
        add("host_unicode", _unicode_host(host))
    origin = urlunsplit((info["scheme"], info["display_host"] + (f":{info['port']}" if info["port"] else ""), "/", "", ""))
    add("origin", origin)
    if refang(raw) != canonical:
        add("url_raw", refang(raw))
    return variants


# --------------------------------------------------------------------------- #
# Per-type normalizers
# --------------------------------------------------------------------------- #

def normalize_url(raw: str) -> NormalizedIndicator:
    info = canonicalize_url(raw)
    tags: list[str] = []
    if info["assumed_scheme"]:
        tags.append("scheme-assumed")
    if info["username"]:
        tags.append("url-credentials-stripped")
    host = info["host"]
    if not _is_ip(host):
        if not _valid_domain(host):
            tags.append("unverified-host")
        if host.startswith("xn--") or ".xn--" in host:
            tags.append("punycode")
            scripts = _host_scripts(host)
            if len(scripts) > 1:
                tags.append("mixed-script")
        rd = registrable_domain(host)
        if rd and rd != host:
            tags.append("subdomain")
        if info["port"]:
            tags.append("non-standard-port")
        if info["query"]:
            tags.append("has-query")
        if re.search(r"\.(?:php|asp|aspx|jsp|cgi|html?)$", info["path"], re.IGNORECASE):
            tags.append("script-or-page")
    else:
        tags.append("ip-host")
        if is_private_ip(host):
            tags.append("private-ip")
    return NormalizedIndicator(
        type=IndicatorType.URL.value,
        value=raw.strip(),
        normalized=info["url"],
        variants=_url_variants(info, raw),
        tags=tags,
        display=defang(info["url"]),
    )


def normalize_domain(raw: str) -> NormalizedIndicator:
    text = refang(raw).strip().strip(".")
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text, flags=re.IGNORECASE)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    text = text.rsplit("@", 1)[-1]
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if ":" in text and not _is_ip(text):
        text = text.split(":", 1)[0]
    host = _ascii_host(text)
    if not host or re.search(r"\s", host):
        raise ValueError("empty or malformed domain")
    if "." not in host and not _is_ip(host):
        raise ValueError("domain must contain a dot")
    tags: list[str] = []
    if not _valid_domain(host):
        tags.append("unverified-domain")
    if text != _ascii_host(text):
        tags.append("idna-encoded")
    if text.startswith("xn--") or ".xn--" in text:
        tags.append("punycode")
    scripts = _host_scripts(host)
    if len(scripts) > 1:
        tags.append("mixed-script")
    rd = registrable_domain(host)
    variants = [{"kind": "domain", "value": host}, {"kind": "domain_defanged", "value": defang(host)}]
    if rd and rd != host:
        variants.append({"kind": "registrable_domain", "value": rd})
    if host != _unicode_host(host):
        variants.append({"kind": "domain_unicode", "value": _unicode_host(host)})
    return NormalizedIndicator(
        type=IndicatorType.DOMAIN.value,
        value=raw.strip(),
        normalized=host,
        variants=variants,
        tags=tags,
        display=defang(host),
    )


def normalize_ip(raw: str) -> NormalizedIndicator:
    text = refang(raw).strip().strip("[]")
    text = text.split("/", 1)[0]
    ip = ipaddress.ip_address(text)
    normalized = str(ip)
    tags = ["ipv6" if ip.version == 6 else "ipv4"]
    if is_private_ip(normalized):
        tags.append("private-ip")
    if ip.is_global:
        tags.append("global")
    return NormalizedIndicator(
        type=IndicatorType.IP.value,
        value=raw.strip(),
        normalized=normalized,
        variants=[{"kind": "ip", "value": normalized}],
        tags=tags,
        display=normalized,
    )


def normalize_email(raw: str) -> NormalizedIndicator:
    text = refang(raw).strip().strip("<>").lower()
    if text.startswith("mailto:"):
        text = text[7:].split("?", 1)[0]
    if "@" not in text:
        raise ValueError("not an email address")
    local, _, domain = text.rpartition("@")
    if not local or not domain:
        raise ValueError("not an email address")
    domain_norm = _ascii_host(domain)
    normalized = f"{local}@{domain_norm}"
    tags: list[str] = []
    if not EMAIL_RE.match(normalized):
        tags.append("unverified-email")
    if "+" in local:
        tags.append("plus-address")
    variants = [
        {"kind": "email", "value": normalized},
        {"kind": "email_defanged", "value": defang(normalized)},
        {"kind": "domain", "value": domain_norm},
    ]
    base_local = local.split("+", 1)[0]
    if base_local != local:
        variants.append({"kind": "email_base", "value": f"{base_local}@{domain_norm}"})
    return NormalizedIndicator(
        type=IndicatorType.EMAIL.value,
        value=raw.strip(),
        normalized=normalized,
        variants=variants,
        tags=tags,
        display=defang(normalized),
    )


def _format_phone(num: phonenumbers.PhoneNumber, region: str | None) -> list[dict[str, str]]:
    variants: list[dict[str, str]] = []
    for kind, fmt in (
        ("phone_e164", phonenumbers.PhoneNumberFormat.E164),
        ("phone_international", phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        ("phone_national", phonenumbers.PhoneNumberFormat.NATIONAL),
        ("phone_rfc3966", phonenumbers.PhoneNumberFormat.RFC3966),
    ):
        try:
            variants.append({"kind": kind, "value": phonenumbers.format_number(num, fmt)})
        except Exception:  # noqa: BLE001
            continue
    digits = str(num.national_number)
    if num.country_code:
        variants.append({"kind": "phone_digits", "value": f"{num.country_code}{digits}"})
    return variants


def normalize_phone(raw: str, *, default_region: str | None = "US") -> NormalizedIndicator:
    text = refang(raw).strip()
    text = re.sub(r"^(?:tel|phone|whatsapp):", "", text, flags=re.IGNORECASE)
    text = text.replace("(", "").replace(")", "").replace("-", " ").strip()
    has_plus = text.startswith("+")
    candidates: list[str | None] = [default_region]
    if has_plus:
        candidates = [None]
    else:
        for region in ("US", "GB", "NG", "IN", "BR", "DE", "FR", "RU", "CN", "ID", "PK", "ZA", "KE", "EG", "AE", "ZA"):
            if region not in candidates:
                candidates.append(region)
    parsed = None
    for region in candidates:
        try:
            candidate = phonenumbers.parse(text, region)
        except phonenumbers.NumberParseException:
            continue
        if phonenumbers.is_valid_number(candidate):
            parsed = candidate
            break
    tags: list[str] = []
    if parsed is None:
        digits = re.sub(r"\D", "", text)
        if not 7 <= len(digits) <= 15:
            raise ValueError("not a phone number")
        tags.append("unverified-phone")
        return NormalizedIndicator(
            type=IndicatorType.PHONE.value,
            value=raw.strip(),
            normalized=digits,
            variants=[{"kind": "phone_digits", "value": digits}],
            tags=tags,
            display=raw.strip(),
        )
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    region_code = phonenumbers.region_code_for_number(parsed)
    if region_code:
        tags.append(f"region-{region_code.lower()}")
    carrier = None
    try:
        carrier = phonenumbers.carrier.name_for_number(parsed, "en")
    except Exception:  # noqa: BLE001
        carrier = None
    variants = _format_phone(parsed, default_region)
    if carrier:
        variants.append({"kind": "phone_carrier", "value": carrier})
    return NormalizedIndicator(
        type=IndicatorType.PHONE.value,
        value=raw.strip(),
        normalized=e164,
        variants=variants,
        tags=tags,
        display=variants[1]["value"] if len(variants) > 1 else e164,
    )


def normalize_hash(raw: str, *, kind: str | None = None) -> NormalizedIndicator:
    text = refang(raw).strip().lower()
    alg = kind
    match = CERT_PREFIX_RE.match(text)
    if match:
        text = text[match.end():].strip()
        alg = "cert_sha256"
    text = text.replace(" ", "")
    if not HEX_RE.match(text):
        raise ValueError("not a hex digest")
    if alg == "cert_sha256" and len(text) != 64:
        raise ValueError("certificate SHA-256 must be 64 hex characters")
    if len(text) == 64:
        hash_type = IndicatorType.CERT_SHA256.value if alg == "cert_sha256" else IndicatorType.FILE_HASH.value
        algo_name = "sha256"
    elif len(text) == 40:
        hash_type = IndicatorType.FILE_HASH.value
        algo_name = "sha1"
    elif len(text) == 32:
        hash_type = IndicatorType.FILE_HASH.value
        algo_name = "md5"
    else:
        raise ValueError("unsupported hash length")
    tags = [f"hash-{algo_name}"]
    variants = [{"kind": "hash", "value": text}, {"kind": "hash_algorithm", "value": algo_name}]
    if hash_type == IndicatorType.CERT_SHA256.value:
        variants.append({"kind": "cert_prefix", "value": f"cert:{text}"})
    return NormalizedIndicator(
        type=hash_type,
        value=raw.strip(),
        normalized=text,
        variants=variants,
        tags=tags,
        display=text,
    )


def normalize_telegram(raw: str) -> NormalizedIndicator:
    text = refang(raw).strip()
    token = TELEGRAM_TOKEN_RE.match(text)
    if token:
        bot_id = token.group(1)
        return NormalizedIndicator(
            type=IndicatorType.TELEGRAM.value,
            value="bot:<redacted>",
            normalized=f"bot:{bot_id}",
            variants=[{"kind": "telegram_bot_id", "value": bot_id}],
            tags=["bot", "bot-token-redacted"],
            display=f"bot:{bot_id} (token redacted)",
        )
    match = TELEGRAM_URL_RE.search(text)
    if match:
        handle = match.group(1).strip("/")
        if handle.startswith("+") or handle.startswith("joinchat/"):
            invite = handle.lstrip("+").replace("joinchat/", "")
            return NormalizedIndicator(
                type=IndicatorType.TELEGRAM.value,
                value=text,
                normalized=f"invite:{invite.lower()}",
                variants=[{"kind": "telegram_invite", "value": invite}],
                tags=["invite-link"],
                display=f"t.me/+{invite}",
            )
        if handle.startswith("s/"):
            handle = handle[2:]
        handle = handle.split("/", 1)[0]
        return _telegram_handle(handle, raw=text)
    if text.lower().startswith("tg://"):
        query = urlsplit(text).query
        for key, value in parse_qsl(query):
            if key.lower() == "domain" and value:
                return _telegram_handle(value, raw=text)
    if text.lower().startswith("bot:"):
        return NormalizedIndicator(
            type=IndicatorType.TELEGRAM.value,
            value=text,
            normalized=text.lower(),
            variants=[{"kind": "telegram_bot_id", "value": text.split(":", 1)[1]}],
            tags=["bot"],
            display=text,
        )
    return _telegram_handle(text, raw=raw)


def _telegram_handle(handle: str, *, raw: str) -> NormalizedIndicator:
    handle = handle.strip().lstrip("@").strip("/")
    if not TELEGRAM_HANDLE_RE.match(handle):
        raise ValueError("not a Telegram handle")
    normalized = handle.lower()
    return NormalizedIndicator(
        type=IndicatorType.TELEGRAM.value,
        value=raw.strip(),
        normalized=normalized,
        variants=[
            {"kind": "telegram_handle", "value": handle},
            {"kind": "telegram_url", "value": f"https://t.me/{handle}"},
        ],
        tags=[],
        display=f"@{handle}",
    )


def normalize_analytics(raw: str) -> NormalizedIndicator:
    text = refang(raw).strip().upper()
    if not ANALYTICS_RE.match(text):
        raise ValueError("not a recognised analytics/tag ID")
    prefix = text.split("-", 1)[0]
    kind = {
        "UA": "google-analytics-universal",
        "G": "google-analytics-4",
        "GTM": "google-tag-manager",
        "AW": "google-ads",
        "MC": "mailchimp",
        "YO": "yandex-metrica",
        "HJ": "hotjar",
        "DC": "doubleclick",
    }.get(prefix, "analytics")
    return NormalizedIndicator(
        type=IndicatorType.ANALYTICS_ID.value,
        value=raw.strip(),
        normalized=text,
        variants=[{"kind": "analytics_id", "value": text}, {"kind": "analytics_kind", "value": kind}],
        tags=[kind],
        display=text,
    )


def normalize_asn(raw: str) -> NormalizedIndicator:
    match = ASN_RE.match(refang(raw).strip())
    if not match:
        raise ValueError("not an ASN")
    normalized = f"AS{int(match.group(1))}"
    return NormalizedIndicator(
        type=IndicatorType.ASN.value,
        value=raw.strip(),
        normalized=normalized,
        variants=[{"kind": "asn", "value": normalized}, {"kind": "asn_number", "value": match.group(1)}],
        tags=[],
        display=normalized,
    )


def _btc_base58_valid(address: str) -> bool:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in address:
        index = alphabet.find(char)
        if index < 0:
            return False
        num = num * 58 + index
    raw = num.to_bytes(25, "big")
    if len(raw) != 25:
        return False
    checksum = hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4]
    return checksum == raw[21:] and raw[0] in (0x00, 0x05)


def normalize_btc(raw: str) -> NormalizedIndicator:
    text = BTC_PREFIX_RE.sub("", refang(raw).strip())
    tags: list[str] = []
    if BTC_BECH32_RE.match(text):
        normalized = text.lower()
        tags.append("bech32")
    elif BTC_BASE58_RE.match(text):
        if not _btc_base58_valid(text):
            tags.append("unverified-checksum")
        normalized = text
        tags.append("p2pkh" if text.startswith("1") else "p2sh")
    else:
        raise ValueError("not a Bitcoin address")
    return NormalizedIndicator(
        type=IndicatorType.BTC_ADDRESS.value,
        value=raw.strip(),
        normalized=normalized,
        variants=[{"kind": "btc_address", "value": normalized}],
        tags=tags,
        display=normalized,
    )


def normalize_ja3(raw: str) -> NormalizedIndicator:
    match = JA3_RE.match(refang(raw).strip())
    if not match:
        raise ValueError("not a JA3 fingerprint")
    normalized = match.group(1).lower()
    return NormalizedIndicator(
        type=IndicatorType.JA3.value,
        value=raw.strip(),
        normalized=normalized,
        variants=[{"kind": "ja3", "value": normalized}],
        tags=[],
        display=normalized,
    )


def normalize_nameserver(raw: str) -> NormalizedIndicator:
    text = NS_PREFIX_RE.sub("", refang(raw).strip()).strip(".")
    host = _ascii_host(text)
    if not _valid_domain(host):
        raise ValueError("not a nameserver hostname")
    return NormalizedIndicator(
        type=IndicatorType.NAMESERVER.value,
        value=raw.strip(),
        normalized=host,
        variants=[{"kind": "nameserver", "value": host}, {"kind": "domain", "value": host}],
        tags=[],
        display=host,
    )


def normalize_username(raw: str) -> NormalizedIndicator:
    text = USERNAME_PREFIX_RE.sub("", refang(raw).strip()).lstrip("@")
    if not re.match(r"^[A-Za-z0-9._-]{2,64}$", text):
        raise ValueError("not a username")
    return NormalizedIndicator(
        type=IndicatorType.USERNAME.value,
        value=raw.strip(),
        normalized=text.lower(),
        variants=[{"kind": "username", "value": text}],
        tags=[],
        display=text,
    )


# --------------------------------------------------------------------------- #
# Type detection + public entry points
# --------------------------------------------------------------------------- #

PREFIX_HANDLERS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("cert", re.compile(r"^(?:cert(?:ificate)?|cert_sha256|sha256)[:=]\s*[a-f0-9]{64}$", re.IGNORECASE), IndicatorType.CERT_SHA256.value),
    ("ja3", re.compile(r"^ja3[:=]", re.IGNORECASE), IndicatorType.JA3.value),
    ("nameserver", re.compile(r"^(?:ns|nameserver)[:=]", re.IGNORECASE), IndicatorType.NAMESERVER.value),
    ("btc", re.compile(r"^(?:btc|bitcoin)[:=]", re.IGNORECASE), IndicatorType.BTC_ADDRESS.value),
    ("username", re.compile(r"^(?:user|username|handle)[:=]", re.IGNORECASE), IndicatorType.USERNAME.value),
    ("phone", re.compile(r"^(?:tel|phone|whatsapp):", re.IGNORECASE), IndicatorType.PHONE.value),
    ("telegram", re.compile(r"^(?:bot:|tg://)|t\.me/|telegram\.me/", re.IGNORECASE), IndicatorType.TELEGRAM.value),
)


def guess_type(raw: str) -> str:
    """Best-effort indicator type for an unlabelled seed."""
    text = refang(raw).strip()
    if not raw or len(raw.strip()) < 2:
        return IndicatorType.UNKNOWN.value
    for _, pattern, type_name in PREFIX_HANDLERS:
        if pattern.search(raw.strip()):
            return type_name
    if re.match(r"^(?:hxxps?|https?)://", raw.strip(), re.IGNORECASE):
        return IndicatorType.URL.value
    if re.match(r"^[a-z0-9-]+\.[a-z]{2,}(?::\d+)?/", text, re.IGNORECASE):
        return IndicatorType.URL.value
    if text.lower().startswith("mailto:") or EMAIL_RE.match(text):
        return IndicatorType.EMAIL.value
    if _is_ip(text) or (text.startswith("[") and text.endswith("]") and _is_ip(text[1:-1])):
        return IndicatorType.IP.value
    if ANALYTICS_RE.match(text):
        return IndicatorType.ANALYTICS_ID.value
    if ASN_RE.match(text):
        return IndicatorType.ASN.value
    if TELEGRAM_TOKEN_RE.match(text) or re.match(r"^@[A-Za-z][A-Za-z0-9_]{4,31}$", text):
        return IndicatorType.TELEGRAM.value
    if BTC_BECH32_RE.match(text) or (BTC_BASE58_RE.match(text) and _btc_base58_valid(text)):
        return IndicatorType.BTC_ADDRESS.value
    if HEX_RE.match(text) and len(text) in (32, 40, 64):
        return IndicatorType.FILE_HASH.value
    if re.match(r"^[+]?\d[\d\s().-]{6,}$", text):
        return IndicatorType.PHONE.value
    if _valid_domain(text):
        return IndicatorType.DOMAIN.value
    return IndicatorType.UNKNOWN.value


NORMALIZERS = {
    IndicatorType.URL.value: normalize_url,
    IndicatorType.DOMAIN.value: normalize_domain,
    IndicatorType.IP.value: normalize_ip,
    IndicatorType.EMAIL.value: normalize_email,
    IndicatorType.PHONE.value: normalize_phone,
    IndicatorType.TELEGRAM.value: normalize_telegram,
    IndicatorType.ANALYTICS_ID.value: normalize_analytics,
    IndicatorType.ASN.value: normalize_asn,
    IndicatorType.BTC_ADDRESS.value: normalize_btc,
    IndicatorType.JA3.value: normalize_ja3,
    IndicatorType.NAMESERVER.value: normalize_nameserver,
    IndicatorType.USERNAME.value: normalize_username,
}


def normalize_indicator(
    raw: str,
    *,
    kind: str | None = None,
    default_region: str | None = "US",
) -> NormalizedIndicator:
    """Normalize a seed indicator, auto-detecting its type when ``kind`` is None.

    Raises ``ValueError`` when the value cannot be normalized as the requested
    (or detected) type; callers should surface that as a user error rather than
    silently storing junk.
    """
    if raw is None or not str(raw).strip():
        raise ValueError("indicator is empty")
    type_name = (kind or guess_type(raw)).lower()
    aliases = {
        "uri": IndicatorType.URL.value,
        "link": IndicatorType.URL.value,
        "hostname": IndicatorType.DOMAIN.value,
        "host": IndicatorType.DOMAIN.value,
        "md5": IndicatorType.FILE_HASH.value,
        "sha1": IndicatorType.FILE_HASH.value,
        "sha256": IndicatorType.FILE_HASH.value,
        "certificate": IndicatorType.CERT_SHA256.value,
        "cert": IndicatorType.CERT_SHA256.value,
        "telegram_handle": IndicatorType.TELEGRAM.value,
        "tg": IndicatorType.TELEGRAM.value,
        "phone_number": IndicatorType.PHONE.value,
        "bitcoin": IndicatorType.BTC_ADDRESS.value,
        "analytics": IndicatorType.ANALYTICS_ID.value,
    }
    type_name = aliases.get(type_name, type_name)
    if type_name == IndicatorType.FILE_HASH.value:
        if not HEX_RE.match(refang(raw).strip().replace(" ", "")):
            raise ValueError("not a file hash")
        result = normalize_hash(raw)
    elif type_name == IndicatorType.CERT_SHA256.value:
        result = normalize_hash(raw, kind="cert_sha256")
    elif type_name == IndicatorType.UNKNOWN.value:
        # Last resort: a dotted string with at least two labels is treated as a
        # domain, but only when it survives domain validation.
        result = normalize_domain(raw)
    else:
        handler = NORMALIZERS.get(type_name)
        if handler is None:
            raise ValueError(f"unsupported indicator type: {type_name}")
        if type_name == IndicatorType.PHONE.value:
            result = normalize_phone(raw, default_region=default_region)
        else:
            result = handler(raw)
    if not result.type:
        result.type = type_name
    return result


def as_variants(indicator: NormalizedIndicator) -> list[dict]:
    """Variant list with deduplication, used by social/search providers."""
    seen: set[tuple[str, str]] = set()
    output: list[dict] = []
    for variant in indicator.variants:
        key = (variant.get("kind", ""), variant.get("value", "").lower())
        if key in seen:
            continue
        seen.add(key)
        output.append(dict(variant))
    return output


# --------------------------------------------------------------------------- #
# Bulk extraction
# --------------------------------------------------------------------------- #

def _iter_matches(text: str) -> Iterator[NormalizedIndicator]:
    for match in URL_CANDIDATE_RE.findall(text):
        try:
            yield normalize_url(match)
        except ValueError:
            continue
    for match in EMAIL_SCAN_RE.findall(text):
        try:
            yield normalize_email(match)
        except ValueError:
            continue
    for match in CERT_SCAN_RE.findall(text):
        try:
            yield normalize_hash(match, kind="cert_sha256")
        except ValueError:
            continue
    for match in HASH_RE.findall(text):
        try:
            yield normalize_hash(match)
        except ValueError:
            continue
    for match in IPV4_RE.findall(text):
        try:
            yield normalize_ip(match)
        except ValueError:
            continue
    for match in TELEGRAM_URL_RE.findall(text):
        try:
            yield normalize_telegram(f"https://t.me/{match}")
        except ValueError:
            continue
    for match in ANALYTICS_SCAN_RE.findall(text):
        try:
            yield normalize_analytics(match)
        except ValueError:
            continue
    for match in BTC_SCAN_RE.findall(text):
        try:
            yield normalize_btc(match)
        except ValueError:
            continue
    for match in BARE_DOMAIN_RE.findall(text):
        host = match if isinstance(match, str) else match[0]
        host = host.split("/", 1)[0].split(":", 1)[0]
        if _is_ip(host) or not _valid_domain(host):
            continue
        try:
            yield normalize_domain(host)
        except ValueError:
            continue


def extract_indicators(
    text: str,
    *,
    limit: int = 200,
    include_url_parts: bool = True,
) -> list[NormalizedIndicator]:
    """Extract every recognisable indicator from free text.

    Ordering is by first appearance, and duplicates are removed by
    ``(type, normalized)`` so downstream storage deduplication stays stable.
    """
    if not text:
        return []
    cleaned = clean_text(refang(text))
    results: list[NormalizedIndicator] = []
    seen: set[tuple[str, str]] = set()

    def push(item: NormalizedIndicator | None) -> bool:
        if item is None:
            return True
        key = item.key()
        if key in seen:
            return True
        seen.add(key)
        results.append(item)
        return len(results) < limit

    for item in _iter_matches(cleaned):
        if not push(item):
            return results
        if include_url_parts and item.type == IndicatorType.URL.value:
            for variant in item.variants:
                if variant["kind"] == "domain" and variant["value"] != item.normalized:
                    try:
                        if not push(normalize_domain(variant["value"])):
                            return results
                    except ValueError:
                        continue
    # Phone numbers are only extracted from explicit international/national
    # forms to avoid turning timestamps and IDs into "phones".
    for match in PHONE_SCAN_RE.findall(cleaned):
        try:
            item = normalize_phone(match, default_region=None)
        except ValueError:
            continue
        if "unverified-phone" in item.tags:
            continue
        if not push(item):
            return results
    return results[:limit]
