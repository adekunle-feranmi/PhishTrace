"""Phishing-kit analyzer.

The analyzer answers the questions an investigator actually asks about a
confirmed phishing page:

* *What is it pretending to be?* — brand, title, form fields, visual lures.
* *Where does it send the loot?* — exfiltration e-mail addresses, Telegram bot
  IDs and chat IDs, Discord/Slack/generic webhooks, mailer recipients.
* *Who built it?* — author handles, signatures, analytics IDs that link
  campaigns together.
* *What is exposed by mistake?* — open log directories, captured credentials,
  disclosed PHP source, downloadable kit archives.
* *Does it match another kit?* — SHA-256 of the landing page, a deterministic
  file-tree hash, and fuzzy hashes (ssdeep/TLSH when installed, otherwise a
  clearly labelled local simhash fallback).

Safety properties
-----------------
* All traffic goes through :class:`~phishtrace.core.fetcher.IsolatedFetcher`
  (SSRF validation, DNS pinning, port denylist, byte caps, no cookies).
* Only **same-origin** assets are fetched. Third-party CDN references are
  recorded as strings and never contacted, so analysis cannot be used to make
  the investigator's host visit arbitrary infrastructure.
* Nothing is executed. HTML, JavaScript, CSS and PHP are parsed as text with
  bounded regular expressions and the standard-library HTML parser.
* Archives are opened **in memory** with :mod:`zipfile` after rejecting
  absolute paths, drive letters, ``..`` components and oversized members. No
  member is ever written to disk or executed. RAR/7z are recorded as metadata
  only because their parsers are not dependency-free.
* Secrets are never persisted: Telegram tokens are reduced to the numeric bot
  ID plus a truncated SHA-256 fingerprint, and webhook paths are redacted.
  Credential exposure is reported as a **count and a type list**, never values.

Gating
------
Active fetching is off by default. The analyzer refuses to run unless
``fetcher.active_fetch`` is true **and** the caller supplies either a hostile
verdict (``malicious``/``phishing``/``suspicious``/``hostile``/``confirmed``)
or an explicit ``force=True`` from an operator-facing flag. A passive run never
silently touches attacker infrastructure.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import re
import time
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from phishtrace.config import Config
from phishtrace.core.fetcher import FetchResult, IsolatedFetcher, fetcher_for
from phishtrace.models import iso, utcnow
from phishtrace.normalizer import normalize_indicator, refang

# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #

HOSTILE_VERDICTS = {"malicious", "phishing", "suspicious", "hostile", "confirmed", "compromised"}
ASSET_MAX_BYTES = 1_500_000
PROBE_BYTES = 8_192
PROBE_FULL_BYTES = 512_000
ARCHIVE_MAX_BYTES = 4_000_000
MAX_CORPUS_CHARS = 2_000_000
MAX_ARCHIVE_MEMBERS = 100
MAX_ARCHIVE_TEXT = 50_000

TEXT_KINDS = {"html", "css", "js", "json", "text", "php", "xml", "log", "config", "source"}

#: Addresses that appear in every template and would drown real exfil hits.
EMAIL_NOISE_DOMAINS = {
    "example.com", "example.org", "example.net", "domain.com", "email.com",
    "yourdomain.com", "sentry.io", "sentry-next.wixpress.com", "wixpress.com",
    "w3.org", "schema.org", "googleapis.com", "gstatic.com", "cloudflare.com",
    "jquery.com", "bootstrapcdn.com", "jsdelivr.net", "unpkg.com",
    "fontawesome.com", "adobe.com",
}

EMAIL_NOISE_LOCALS = {
    "you", "your", "name", "user", "email", "test", "example", "someone",
    "noreply", "no-reply", "donotreply", "info", "support", "admin",
}

ASSET_SUFFIXES = (
    ".js", ".css", ".json", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
)
ARCHIVE_SUFFIXES = (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz")

# --------------------------------------------------------------------------- #
# Extraction patterns
# --------------------------------------------------------------------------- #

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}")
TELEGRAM_TOKEN_RE = re.compile(
    # Tokens appear bare in assignments and after a ``bot`` prefix in API URLs
    # (``api.telegram.org/bot123456:AA...``); the lookbehind covers both
    # without matching inside unrelated words.
    r"(?<![A-Za-z0-9])(?:bot)?(\d{6,12}):([A-Za-z0-9_\-]{30,45})\b",
    re.I,
)
TELEGRAM_CHAT_RE = re.compile(
    r"(?:chat[_\-\s]?id|chatid|chat|from[_\-\s]?id)\s*[\"'=:\s]\s*(-?\d{6,20})",
    re.I,
)
WEBHOOK_RE = re.compile(
    r"https?://(?:"
    r"(?:canary\.)?discord(?:app)?\.com/api/webhooks/[\w\-/]+"
    r"|hooks\.slack\.com/services/[\w\-/]+"
    r"|api\.telegram\.org/bot[^/\s\"'<>]+"
    r"|(?:www\.)?(?:webhook\.site|requestbin\.(?:net|com)|pipedream\.net|hookbin\.com"
    r"|beeceptor\.com|ngrok(?:-free)?\.app|interact\.sh)/[^\s\"'<>]+"
    r")",
    re.I,
)

GA_RE = re.compile(
    r"\b(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,10}|AW-\d{6,12}"
    r"|MC-[A-Z0-9]{6,12}|YO-\d{4,10}|HJ-\d{4,10}|DC-\d{4,10})\b"
)
FB_PIXEL_RE = re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]", re.I)
YANDEX_RE = re.compile(r"ym\(\s*(\d{5,10})\s*[,)]", re.I)
TIKTOK_RE = re.compile(r"ttq\.load\(\s*['\"]([A-Z0-9]{10,30})['\"]", re.I)

AUTHOR_RE = re.compile(
    r"(?:author|developer|creator|coded\s*by|powered\s*by|created\s*by|made\s*by|"
    r"owner|seller|vendor|maintainer|signature)\s*[:=@]?\s*"
    r"([A-Za-z0-9][A-Za-z0-9 _.\-@/]{1,48})",
    re.I,
)
HANDLE_RE = re.compile(r"(?<![\w/])@([A-Za-z][A-Za-z0-9_]{3,31})\b")
HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)

EMAIL_PASS_RE = re.compile(
    r"([A-Za-z0-9._%+\-]{2,64}@[A-Za-z0-9.\-]{2,190}\.[A-Za-z]{2,24})\s*[:|\t;,](?![0-9])\s*(\S{3,120})"
)
KEYVAL_SECRET_RE = re.compile(
    r"\b(?:password|passwd|pass|pwd|pin|otp)\s*[=:]\s*([^\s&<>\"]{3,120})", re.I
)
B64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,160}={0,2}(?![A-Za-z0-9+/])")

# --------------------------------------------------------------------------- #
# Brand vocabulary (global; targeted at the lures seen in real campaigns)
# --------------------------------------------------------------------------- #

BRANDS: dict[str, tuple[str, ...]] = {
    "Microsoft 365": ("microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint", "msonline"),
    "Apple": ("apple id", "appleid", "icloud", "apple support"),
    "Google": ("google account", "gmail", "google drive", "google workspace"),
    "Amazon": ("amazon", "amazon prime", "aws account"),
    "Netflix": ("netflix",),
    "PayPal": ("paypal",),
    "eBay": ("ebay",),
    "Meta": ("facebook", "instagram", "whatsapp"),
    "LinkedIn": ("linkedin",),
    "Dropbox": ("dropbox",),
    "DocuSign": ("docusign",),
    "Adobe": ("adobe", "creative cloud"),
    "Shopify": ("shopify",),
    "Booking.com": ("booking.com",),
    "Airbnb": ("airbnb",),
    "Uber": ("uber",),
    "Steam": ("steam community", "steam guard", "steampowered"),
    "Roblox": ("roblox",),
    "Epic Games": ("epic games", "fortnite"),
    "PlayStation": ("playstation",),
    "Xbox": ("xbox live", "xbox"),
    "Nintendo": ("nintendo",),
    "Discord": ("discord",),
    "Binance": ("binance",),
    "Coinbase": ("coinbase",),
    "MetaMask": ("metamask",),
    "Trust Wallet": ("trust wallet",),
    "Kraken": ("kraken",),
    "OKX": ("okx",),
    "Bybit": ("bybit",),
    "KuCoin": ("kucoin",),
    "Ledger": ("ledger live", "ledger nano"),
    "Trezor": ("trezor",),
    "Revolut": ("revolut",),
    "Monzo": ("monzo",),
    "N26": ("n26",),
    "Klarna": ("klarna",),
    "Wise": ("wise account", "transferwise"),
    "Payoneer": ("payoneer",),
    "Skrill": ("skrill",),
    "Neteller": ("neteller",),
    "Chase": ("chase bank", "jpmorgan"),
    "Bank of America": ("bank of america",),
    "Wells Fargo": ("wells fargo",),
    "Citibank": ("citibank", "citi card"),
    "HSBC": ("hsbc",),
    "Barclays": ("barclays",),
    "Lloyds": ("lloyds bank",),
    "NatWest": ("natwest",),
    "Santander": ("santander",),
    "BBVA": ("bbva",),
    "Deutsche Bank": ("deutsche bank",),
    "Sparkasse": ("sparkasse",),
    "Postbank": ("postbank",),
    "Raiffeisen": ("raiffeisen",),
    "Sberbank": ("sberbank",),
    "Tinkoff": ("tinkoff", "t-bank"),
    "GTBank": ("gtbank", "guaranty trust bank"),
    "Access Bank": ("access bank",),
    "Zenith Bank": ("zenith bank",),
    "First Bank": ("first bank of nigeria", "firstbank"),
    "UBA": ("united bank for africa", "uba group"),
    "Kuda": ("kuda bank", "kuda mfbank"),
    "OPay": ("opay",),
    "PalmPay": ("palmpay",),
    "Moniepoint": ("moniepoint",),
    "Equity Bank": ("equity bank",),
    "KCB": ("kcb bank", "kenya commercial bank"),
    "Absa": ("absa",),
    "Standard Bank": ("standard bank",),
    "Capitec": ("capitec",),
    "Nedbank": ("nedbank",),
    "BDO": ("bdo online", "banco de oro"),
    "BPI": ("bpi online", "bank of the philippine islands"),
    "Maybank": ("maybank",),
    "CIMB": ("cimb",),
    "OCBC": ("ocbc",),
    "DBS": ("dbs bank", "posb"),
    "ICICI": ("icici",),
    "HDFC": ("hdfc",),
    "SBI": ("state bank of india", "onlinesbi"),
    "Alipay": ("alipay",),
    "WeChat Pay": ("wechat pay", "weixin pay"),
    "UnionPay": ("unionpay",),
    "DHL": ("dhl",),
    "FedEx": ("fedex",),
    "UPS": ("united parcel service", "ups delivery"),
    "USPS": ("usps",),
    "Royal Mail": ("royal mail",),
    "DPD": ("dpd parcel", "dpd group"),
    "Poste Italiane": ("poste italiane",),
    "La Poste": ("la poste",),
    "Correos": ("correos",),
    "Canada Post": ("canada post",),
    "Australia Post": ("australia post",),
    "Japan Post": ("japan post", "yucho"),
    "China Post": ("china post",),
    "India Post": ("india post",),
    "Vodafone": ("vodafone",),
    "Orange": ("orange money", "orange business"),
    "Telefonica": ("telefonica", "movistar"),
    "MTN": ("mtn mobile money", "mtn momo", "mtn group"),
    "Airtel": ("airtel money", "airtel"),
    "Safaricom": ("safaricom", "m-pesa"),
    "Globe Telecom": ("globe telecom", "globeone"),
    "Smart Communications": ("smart communications", "smart padala"),
    "Jio": ("jio",),
    "IRS": ("irs.gov", "internal revenue service"),
    "HMRC": ("hmrc", "self assessment"),
    "ATO": ("australian taxation office",),
    "Canada Revenue Agency": ("canada revenue agency", "cra my account"),
}

# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def _truncate(text: str, limit: int = MAX_CORPUS_CHARS) -> str:
    return text[:limit]


def _origin(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme.lower() or "http"
    host = (parts.hostname or "").lower()
    port = parts.port
    default = 443 if scheme == "https" else 80
    netloc = host if not port or port == default else f"{host}:{port}"
    return urlunsplit((scheme, netloc, "", "", ""))


def _same_origin(url: str, origin: str) -> bool:
    try:
        return _origin(url) == origin
    except ValueError:
        return False


def kind_for(path: str, content_type: str | None, data: bytes) -> str:
    """Cheap, deterministic content classification.

    Content type and magic bytes win over the file extension: a ``.php`` file
    served as ``text/plain`` with ``<?php`` at the top is disclosed source, not
    a page, and it must be reported that way.
    """
    path = (path or "").split("?", 1)[0].lower()
    ctype = (content_type or "").lower()
    head = data[:1024].lower()

    if "html" in ctype:
        return "html"
    if "javascript" in ctype or "ecmascript" in ctype:
        return "js"
    if "css" in ctype:
        return "css"
    if "json" in ctype:
        return "json"
    if "xml" in ctype:
        return "xml"
    if "zip" in ctype:
        return "archive"
    if b"<?php" in head:
        return "source"
    if b"<html" in head or b"<!doctype html" in head:
        return "html"

    mapping = {
        ".html": "html", ".htm": "html", ".js": "js", ".css": "css",
        ".json": "json", ".php": "php", ".asp": "source", ".aspx": "source",
        ".txt": "text", ".xml": "xml", ".zip": "archive", ".rar": "archive",
        ".7z": "archive", ".tar": "archive", ".gz": "archive", ".tgz": "archive",
        ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
        ".svg": "image", ".webp": "image", ".ico": "image",
        ".woff": "font", ".woff2": "font", ".ttf": "font", ".eot": "font",
    }
    suffix = ""
    for candidate in sorted(mapping, key=len, reverse=True):
        if path.endswith(candidate):
            suffix = candidate
            break

    if ctype.startswith("text/") or not ctype:
        if "config" in path or path.endswith((".env", ".ini", ".conf")) or "settings" in path:
            return "config"
        log_tokens = ("log", "result", "stolen", "victim", "capture", "creds", "dump")
        if any(token in path for token in log_tokens):
            return "log"
        if suffix in mapping:
            return mapping[suffix]
        return "text"
    if suffix in mapping:
        return mapping[suffix]
    return "binary"


def is_text_kind(kind: str) -> bool:
    return kind in TEXT_KINDS


def looks_like_challenge(result: FetchResult) -> bool:
    """Recognise a WAF/bot challenge so it is never mistaken for kit content."""
    if result.status_code not in (403, 429, 503):
        return False
    lowered = result.text[:4000].lower()
    markers = (
        "just a moment", "cf-chl", "challenge-platform", "attention required",
        "enable javascript and cookies", "ddos-guard", "captcha",
    )
    if any(marker in lowered for marker in markers):
        return True
    return "cloudflare" in (result.headers.get("server") or "").lower()


# --------------------------------------------------------------------------- #
# HTML parsing
# --------------------------------------------------------------------------- #


class PageParser(HTMLParser):
    """Bounded, dependency-free collector for the parts of a page we need."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.base_href = ""
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.images: list[str] = []
        self.iframes: list[str] = []
        self.anchors: list[str] = []
        self.forms: list[dict] = []
        self.inline_blocks: list[str] = []
        self.text_parts: list[str] = []
        self.meta: dict[str, str] = {}
        self._in_title = False
        self._capture: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "base" and values.get("href"):
            self.base_href = values["href"]
        elif tag == "script":
            if values.get("src"):
                self._add(self.scripts, values["src"])
            else:
                self._capture = []
        elif tag == "style":
            self._capture = []
        elif tag == "link":
            rel = values.get("rel", "").lower()
            if "stylesheet" in rel and values.get("href"):
                self._add(self.stylesheets, values["href"])
        elif tag == "img" and values.get("src"):
            self._add(self.images, values["src"])
        elif tag == "iframe" and values.get("src"):
            self._add(self.iframes, values["src"])
        elif tag == "a" and values.get("href"):
            self._add(self.anchors, values["href"])
        elif tag == "form":
            self.forms.append({
                "action": values.get("action", ""),
                "method": values.get("method", "get").lower(),
                "inputs": [],
            })
        elif tag in ("input", "select", "textarea", "button"):
            if self.forms:
                self.forms[-1]["inputs"].append({
                    "name": values.get("name", ""),
                    "type": (values.get("type") or tag).lower(),
                    "placeholder": values.get("placeholder", ""),
                })
        elif tag == "meta":
            name = (values.get("name") or values.get("property") or "").lower()
            if name and values.get("content"):
                self.meta[name] = values["content"][:300]

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag in ("script", "style") and self._capture is not None:
            self.inline_blocks.append("".join(self._capture))
            self._capture = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title = (self.title + data).strip()[:300]
        if self._capture is not None:
            self._capture.append(data)
            return
        if data.strip() and len(self.text_parts) < 4000:
            self.text_parts.append(data.strip()[:400])

    def handle_comment(self, data: str) -> None:
        if len(data) < 4000:
            self.inline_blocks.append(f"<!--{data}-->")

    @staticmethod
    def _add(bucket: list[str], value: str) -> None:
        if len(bucket) < 200 and value not in bucket:
            bucket.append(value)


def parse_html(text: str) -> PageParser:
    parser = PageParser()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup must not stop analysis
        pass
    return parser


# --------------------------------------------------------------------------- #
# Extraction functions
# --------------------------------------------------------------------------- #


def extract_emails(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in EMAIL_RE.finditer(text):
        value = match.group(0).strip(".,;:)]}'\"<>").lower()
        if not value or value in seen:
            continue
        local, _, domain = value.partition("@")
        if domain in EMAIL_NOISE_DOMAINS or any(domain.endswith("." + item) for item in EMAIL_NOISE_DOMAINS):
            continue
        if local in EMAIL_NOISE_LOCALS:
            continue
        if value.endswith(ASSET_SUFFIXES) or re.search(r"@\d+x", value):
            continue
        seen.add(value)
        found.append(value)
        if len(found) >= 50:
            break
    return found


def extract_telegram(text: str) -> list[dict]:
    """Extract bot IDs and chat IDs. The token itself is never returned."""
    bots: dict[str, dict] = {}
    for match in TELEGRAM_TOKEN_RE.finditer(text):
        bot_id, token = match.group(1), match.group(2)
        entry = bots.setdefault(bot_id, {
            "bot_id": bot_id,
            "token_sha256_12": _sha256(f"{bot_id}:{token}")[:12],
            "chat_ids": [],
            "token_redacted": True,
        })
    primary = next(iter(bots), None)
    if primary:
        for match in TELEGRAM_CHAT_RE.finditer(text):
            chat_id = match.group(1)
            entry = bots[primary]
            if chat_id not in entry["chat_ids"] and len(entry["chat_ids"]) < 20:
                entry["chat_ids"].append(chat_id)
    return list(bots.values())[:20]


def extract_webhooks(text: str) -> list[dict]:
    found: list[dict] = []
    seen: set[str] = set()
    for match in WEBHOOK_RE.finditer(text):
        url = match.group(0).rstrip(".,;)]}\"'")
        key = _sha256(url)
        if key in seen:
            continue
        seen.add(key)
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        kind = (
            "discord" if "discord" in host
            else "slack" if "slack" in host
            else "telegram" if "telegram" in host
            else "generic"
        )
        entry: dict = {"kind": kind, "host": host, "url_sha256": key}
        if kind == "telegram":
            # The bot token *is* the first path segment: never echo any of it.
            entry["url_redacted"] = f"{parts.scheme}://{host}/bot<redacted>"
        elif kind in {"discord", "slack"}:
            # The path carries the credential; keep only its shape.
            prefix = parts.path.strip("/").split("/", 1)[0]
            entry["url_redacted"] = f"{parts.scheme}://{host}/{prefix}/<redacted>"
        else:
            entry["url"] = url[:500]
        found.append(entry)
        if len(found) >= 20:
            break
    return found


def extract_analytics(text: str) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value.upper())
        if key in seen or len(found) >= 30:
            return
        seen.add(key)
        found.append({"kind": kind, "value": value.upper()})

    prefixes = {
        "UA": "google-analytics-universal", "G": "google-analytics-4",
        "GTM": "google-tag-manager", "AW": "google-ads", "MC": "mailchimp",
        "YO": "yandex-metrica", "HJ": "hotjar", "DC": "doubleclick",
    }
    for match in GA_RE.finditer(text):
        value = match.group(0)
        add(prefixes.get(value.split("-", 1)[0], "analytics"), value)
    for match in FB_PIXEL_RE.finditer(text):
        add("meta-pixel", match.group(1))
    for match in YANDEX_RE.finditer(text):
        add("yandex-metrica", match.group(1))
    for match in TIKTOK_RE.finditer(text):
        add("tiktok-pixel", match.group(1))
    return found


def extract_author_strings(text: str, *, limit: int = 20) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        value = re.sub(r"\s+", " ", value).strip(" .,:;/-|")
        if len(value) < 2 or len(value) > 60:
            return
        key = value.lower()
        if key in seen or len(found) >= limit:
            return
        seen.add(key)
        found.append(value)

    for comment in HTML_COMMENT_RE.findall(text)[:200]:
        for match in AUTHOR_RE.finditer(comment):
            add(match.group(1))
        for match in HANDLE_RE.finditer(comment):
            add("@" + match.group(1))
    for match in AUTHOR_RE.finditer(text[:200_000]):
        add(match.group(1))
    return found


def detect_brand(*, title: str, text: str, host: str, paths: list[str]) -> tuple[str | None, str | None, dict]:
    """Score brand keywords across title, body, hostname and kit paths."""
    scores: dict[str, int] = {}
    evidence: dict[str, list[str]] = {}
    title_l = title.lower()
    text_l = text[:200_000].lower()
    host_l = host.lower()
    path_l = " ".join(paths).lower()

    for brand, keywords in BRANDS.items():
        for keyword in keywords:
            points = 0
            if keyword in title_l:
                points += 4
            if keyword in host_l:
                points += 4
            if keyword in text_l:
                points += 2
            if keyword in path_l:
                points += 1
            if points:
                scores[brand] = scores.get(brand, 0) + points
                evidence.setdefault(brand, []).append(keyword)
    if not scores:
        return None, None, {}
    brand = max(scores, key=lambda item: (scores[item], item))
    score = scores[brand]
    confidence = "high" if score >= 6 else "medium" if score >= 3 else "low"
    return brand, confidence, {"score": score, "keywords": evidence.get(brand, [])[:8]}


def credential_signals(text: str) -> tuple[int, list[str], list[str]]:
    """Count credential material without ever returning the values.

    Returns ``(count, types, sample_masks)``. ``sample_masks`` keeps only the
    account part (``v***@example.com``), never the password.
    """
    masks: list[str] = []
    seen: set[str] = set()
    types: list[str] = []

    def mask_email(value: str) -> str:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain}" if local else "***"

    pairs = 0
    for match in EMAIL_PASS_RE.finditer(text):
        email, secret = match.group(1), match.group(2)
        if secret.startswith(("$", "{", "%", "<", "&", "http")):
            continue
        if email.lower().rsplit("@", 1)[-1] in EMAIL_NOISE_DOMAINS:
            continue
        key = f"{email.lower()}:{_sha256(secret)[:8]}"
        if key in seen:
            continue
        seen.add(key)
        pairs += 1
        if len(masks) < 5:
            masks.append(mask_email(email))
    if pairs:
        types.append("email:password pairs")

    keyvals = 0
    for match in KEYVAL_SECRET_RE.finditer(text):
        value = match.group(1)
        if value.startswith(("$", "{", "%", "<", "&", "'", '"')):
            continue
        if value.lower() in {"password", "passwd", "required", "true", "false", "null", "none"}:
            continue
        keyvals += 1
    if keyvals:
        types.append("password parameters")

    blobs = 0
    for match in B64_RE.finditer(text):
        candidate = match.group(0)
        try:
            decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4), validate=False)
        except Exception:  # noqa: BLE001
            continue
        if b":" in decoded and b"@" in decoded:
            blobs += 1
    if blobs:
        types.append("base64 credential blobs")

    return pairs + keyvals + blobs, types, masks


def redact_secret_text(text: str) -> str:
    """Mask credential material before text is exposed in a report.

    Raw bytes stay in the quarantined evidence store for forensic use, but
    anything returned by ``as_dict()`` must not carry a live bot token or
    webhook secret. Chat IDs and bot IDs remain, because they are the pivots.
    """
    def replacement(match: re.Match) -> str:
        prefix = "bot" if match.group(0).lower().startswith("bot") else ""
        return f"{prefix}{match.group(1)}:<redacted>"

    text = TELEGRAM_TOKEN_RE.sub(replacement, text)
    text = re.sub(
        r"(hooks\.slack\.com/(?:services|triggers)/)[A-Za-z0-9/_-]+",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(discord(?:app)?\.com/api/webhooks/)\d+/[A-Za-z0-9_-]+",
        r"\1<redacted>",
        text,
    )
    return text


def file_tree_hash(entries: list[tuple[str, str]]) -> str:
    """Deterministic hash of ``(path, sha256)`` pairs, independent of order."""
    lines = sorted(f"{path}\t{digest}" for path, digest in entries if digest)
    return _sha256("\n".join(lines))


def simhash64(data: bytes, *, window: int = 4, limit: int = 131_072) -> str:
    """Local 64-bit simhash fallback when ssdeep/TLSH are not installed."""
    payload = data[:limit]
    if len(payload) < window:
        return "0" * 16
    vector = [0] * 64
    for index in range(0, len(payload) - window + 1, window):
        digest = hashlib.blake2b(payload[index:index + window], digest_size=8).digest()
        number = int.from_bytes(digest, "big")
        for bit in range(64):
            vector[bit] += 1 if number & (1 << bit) else -1
    value = 0
    for bit, weight in enumerate(vector):
        if weight > 0:
            value |= 1 << bit
    return f"{value:016x}"


def fuzzy_hashes(data: bytes) -> tuple[str | None, str | None, str, list[str]]:
    """Return ``(ssdeep, tlsh, local_simhash, notes)``.

    The fallback is explicitly labelled: a report must never imply that ssdeep
    or TLSH was computed when the optional native modules are absent.
    """
    notes: list[str] = []
    ssdeep_value = None
    tlsh_value = None
    try:  # optional native dependency
        import ssdeep  # type: ignore

        ssdeep_value = ssdeep.hash(data) or None
    except Exception:  # noqa: BLE001
        notes.append("ssdeep unavailable (optional dependency not installed)")
    try:  # optional native dependency
        import tlsh  # type: ignore

        digest = tlsh.hash(data)
        tlsh_value = digest if digest and digest != "TNULL" else None
    except Exception:  # noqa: BLE001
        notes.append("TLSH unavailable (optional dependency not installed)")
    local = simhash64(data)
    if not ssdeep_value or not tlsh_value:
        notes.append(f"local simhash64 fallback recorded: {local}")
    return ssdeep_value, tlsh_value, local, notes


# --------------------------------------------------------------------------- #
# Archive handling
# --------------------------------------------------------------------------- #


def safe_member_name(name: str) -> str | None:
    """Return a safe relative member name, or ``None`` for traversal attempts."""
    candidate = (name or "").replace("\\", "/").strip()
    if not candidate or candidate.startswith("/"):
        return None
    if re.match(r"^[A-Za-z]:", candidate):
        return None
    parts = [part for part in candidate.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def inspect_zip(
    data: bytes,
    *,
    max_members: int = 200,
    max_member_bytes: int = 2_000_000,
    max_total_bytes: int = 32_000_000,
) -> tuple[list[dict], list[str]]:
    """Read a ZIP archive in memory, returning safe members and warnings."""
    members: list[dict] = []
    warnings: list[str] = []
    total = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError) as exc:
        return [], [f"archive could not be opened: {type(exc).__name__}"]
    with archive:
        for info in archive.infolist()[:max_members]:
            if info.is_dir():
                continue
            name = safe_member_name(info.filename)
            if name is None:
                warnings.append(f"skipped unsafe archive member: {info.filename[:120]}")
                continue
            if info.file_size > max_member_bytes:
                warnings.append(f"skipped oversized member {name}: {info.file_size} bytes")
                continue
            if total + info.file_size > max_total_bytes:
                warnings.append("archive uncompressed size cap reached")
                break
            try:
                with archive.open(info) as handle:
                    content = handle.read(max_member_bytes + 1)
            except (RuntimeError, zipfile.BadZipFile, OSError) as exc:
                warnings.append(f"could not read {name}: {type(exc).__name__}")
                continue
            total += len(content)
            members.append({
                "path": name,
                "size": len(content),
                "sha256": _sha256(content),
                "content": content,
            })
    return members, warnings


# --------------------------------------------------------------------------- #
# Report objects
# --------------------------------------------------------------------------- #


@dataclass
class KitFile:
    path: str
    url: str
    kind: str
    origin: str = "asset"
    status_code: int | None = None
    size: int = 0
    sha256: str = ""
    evidence_id: str | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "path": self.path,
            "url": self.url,
            "kind": self.kind,
            "origin": self.origin,
            "status_code": self.status_code,
            "size": self.size,
            "sha256": self.sha256,
            "evidence_id": self.evidence_id,
            "error": self.error,
        }


@dataclass
class KitReport:
    url: str
    fetched_at: datetime = field(default_factory=utcnow)
    final_url: str = ""
    status_code: int | None = None
    truncated: bool = False
    redirects: list[dict] = field(default_factory=list)
    title: str = ""
    brand: str | None = None
    brand_confidence: str | None = None
    brand_evidence: dict = field(default_factory=dict)
    kit_id: str | None = None
    files: list[KitFile] = field(default_factory=list)
    kit_sha256: str | None = None
    file_tree_hash: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None
    local_simhash: str | None = None
    exfil_emails: list[dict] = field(default_factory=list)
    telegram_bots: list[dict] = field(default_factory=list)
    webhooks: list[dict] = field(default_factory=list)
    analytics_ids: list[dict] = field(default_factory=list)
    author_strings: list[str] = field(default_factory=list)
    form_fields: list[dict] = field(default_factory=list)
    exposed_paths: list[dict] = field(default_factory=list)
    archive_members: list[dict] = field(default_factory=list)
    credential_exposure_count: int = 0
    credential_exposure_types: list[str] = field(default_factory=list)
    credential_masks: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    denied: list[dict] = field(default_factory=list)
    skipped: str | None = None
    pivots: list[dict] = field(default_factory=list)
    elapsed_ms: int = 0

    def add_note(self, note: str) -> None:
        if note and note not in self.notes and len(self.notes) < 40:
            self.notes.append(note)

    def to_db_dict(self, *, indicator_id: str | None = None) -> dict:
        return {
            "indicator_id": indicator_id,
            "url": self.final_url or self.url,
            "kit_sha256": self.kit_sha256,
            "file_tree_hash": self.file_tree_hash,
            "ssdeep": self.ssdeep,
            "tlsh": self.tlsh,
            "exfil_emails": [item["value"] for item in self.exfil_emails],
            "telegram_bots": self.telegram_bots,
            "webhooks": self.webhooks,
            "analytics_ids": self.analytics_ids,
            "author_strings": self.author_strings,
            "brand": self.brand,
            "form_fields": self.form_fields,
            "files": [item.as_dict() for item in self.files],
            "exposed_paths": self.exposed_paths,
            "credential_exposure_count": self.credential_exposure_count,
            "credential_exposure_types": self.credential_exposure_types,
            "notes": "; ".join(self.notes)[:4000] if self.notes else None,
        }

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "fetched_at": iso(self.fetched_at),
            "redirects": self.redirects,
            "title": self.title,
            "brand": self.brand,
            "brand_confidence": self.brand_confidence,
            "brand_evidence": self.brand_evidence,
            "kit_id": self.kit_id,
            "kit_sha256": self.kit_sha256,
            "file_tree_hash": self.file_tree_hash,
            "ssdeep": self.ssdeep,
            "tlsh": self.tlsh,
            "local_simhash": self.local_simhash,
            "files": [item.as_dict() for item in self.files],
            "exfil_emails": self.exfil_emails,
            "telegram_bots": self.telegram_bots,
            "webhooks": self.webhooks,
            "analytics_ids": self.analytics_ids,
            "author_strings": self.author_strings,
            "form_fields": self.form_fields,
            "exposed_paths": self.exposed_paths,
            "archive_members": self.archive_members,
            "credential_exposure_count": self.credential_exposure_count,
            "credential_exposure_types": self.credential_exposure_types,
            "credential_masks": self.credential_masks,
            "notes": self.notes,
            "errors": self.errors,
            "denied": self.denied,
            "skipped": self.skipped,
            "pivots": self.pivots,
            "elapsed_ms": self.elapsed_ms,
        }


# --------------------------------------------------------------------------- #
# Analyzer
# --------------------------------------------------------------------------- #


class KitAnalyzer:
    """Fetch and statically analyze a confirmed phishing page."""

    def __init__(
        self,
        config: Config,
        *,
        fetcher: IsolatedFetcher | None = None,
        repo=None,
        investigation_id: str | None = None,
        logger=None,
    ):
        self.config = config
        self.repo = repo
        self.investigation_id = investigation_id
        self.logger = logger
        self._owns_fetcher = fetcher is None
        self.fetcher = fetcher or fetcher_for(
            config,
            repo,
            investigation_id=investigation_id,
            provider="kit",
        )
        self._texts: dict[str, str] = {}
        #: Raw archive member text, used for extraction only; the report keeps a
        #: redacted copy so exports never carry bot tokens or webhook secrets.
        self._archive_texts: list[tuple[str, str]] = []

    # -- policy -------------------------------------------------------------
    def gate(self, verdict: str | None, force: bool) -> tuple[bool, str]:
        if not self.config.fetcher.active_fetch:
            return False, "active fetching is disabled (set fetcher.active_fetch: true to allow kit analysis)"
        if force:
            return True, "operator forced kit analysis"
        if (verdict or "").strip().lower() in HOSTILE_VERDICTS:
            return True, f"hostile verdict supplied: {verdict}"
        return False, (
            "kit analysis needs a confirmed hostile verdict "
            f"({', '.join(sorted(HOSTILE_VERDICTS))}) or force=True"
        )

    async def close(self) -> None:
        if self._owns_fetcher and self.fetcher is not None:
            await self.fetcher.close()

    async def __aenter__(self) -> "KitAnalyzer":
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    # -- main ---------------------------------------------------------------
    async def analyze(
        self,
        url: str,
        *,
        force: bool = False,
        verdict: str | None = None,
        persist: bool = False,
        indicator_id: str | None = None,
        investigation_id: str | None = None,
        max_probes: int | None = 12,
    ) -> KitReport:
        started = time.monotonic()
        self._texts = {}
        self._archive_texts = []
        report = KitReport(url=refang(url).strip())
        allowed, reason = self.gate(verdict, force)
        if not allowed:
            report.skipped = reason
            report.elapsed_ms = int((time.monotonic() - started) * 1000)
            return report
        if self.fetcher is None:
            report.errors.append("no fetcher available")
            report.skipped = "fetcher unavailable"
            return report

        landing = await self.fetcher.fetch(report.url, provider="kit", note="kit landing page")
        report.status_code = landing.status_code
        report.final_url = landing.final_url or landing.url
        report.truncated = landing.truncated
        report.redirects = list(landing.redirects)
        if landing.error:
            report.errors.append(landing.error)
            report.add_note(f"landing fetch failed: {landing.error}")
            report.denied = list(self.fetcher.denied)
            report.elapsed_ms = int((time.monotonic() - started) * 1000)
            return report
        if landing.status_code and landing.status_code >= 400:
            report.add_note(f"landing page returned HTTP {landing.status_code}")

        origin = _origin(report.final_url)
        landing_kind = kind_for(urlsplit(report.final_url).path or "/", landing.content_type, landing.content)
        report.files.append(KitFile(
            path=urlsplit(report.final_url).path or "/",
            url=report.final_url,
            kind=landing_kind,
            origin="landing",
            status_code=landing.status_code,
            size=landing.size_bytes,
            sha256=landing.sha256,
            evidence_id=landing.evidence_id,
        ))
        report.kit_sha256 = landing.sha256 or _sha256(landing.content)
        self._texts[report.final_url] = landing.text
        if landing_kind == "archive":
            # A seed URL can point straight at a downloadable kit archive.
            await self._inspect_archive_bytes(
                report, landing.content, urlsplit(report.final_url).path or "/"
            )

        parsed = parse_html(landing.text) if landing_kind in {"html", "text"} else PageParser()
        report.title = parsed.title
        base = urljoin(report.final_url, parsed.base_href) if parsed.base_href else report.final_url

        # ---- same-origin assets -------------------------------------------
        assets = await self._fetch_assets(self._asset_urls(parsed, base, origin))
        report.files.extend(assets)

        # ---- archive links (in-memory inspection) -------------------------
        for archive_url in self._archive_urls(parsed, base, origin)[:3]:
            await self._inspect_archive_url(report, archive_url)

        # ---- probe known kit paths ----------------------------------------
        report.files.extend(await self._probe_paths(report, origin, max_probes=max_probes))

        # ---- extraction ----------------------------------------------------
        corpus: list[tuple[str, str]] = [(report.final_url, _truncate(landing.text))]
        for item in report.files:
            if item.kind in {"log", "source", "text", "json", "php", "js", "css"}:
                body = self._file_text(item)
                if body:
                    corpus.append((item.url, _truncate(body)))
        corpus.extend(self._archive_texts)

        self._extract(report, corpus, parsed=parsed)
        self._hash_report(report, landing.content)

        # ---- notes / pivots -----------------------------------------------
        self._summarize(report, parsed)
        report.pivots = self._pivots(report)
        report.denied = list(self.fetcher.denied)

        if persist and self.repo is not None:
            target = investigation_id or self.investigation_id
            if target:
                try:
                    report.kit_id = self.repo.add_kit(
                        target, report.to_db_dict(indicator_id=indicator_id)
                    )
                except Exception as exc:  # noqa: BLE001 - persistence must not lose the analysis
                    report.errors.append(
                        f"could not persist kit analysis: {type(exc).__name__}: {exc}"[:300]
                    )
            else:
                report.add_note("not persisted: no investigation id supplied")
        report.elapsed_ms = int((time.monotonic() - started) * 1000)
        if self.logger:
            try:
                self.logger(
                    f"kit analysis {report.final_url}: {len(report.files)} file(s), "
                    f"{len(report.exfil_emails)} exfil email(s), {len(report.pivots)} pivot(s)"
                )
            except Exception:  # noqa: BLE001
                pass
        return report

    # -- URL collection ------------------------------------------------------
    def _asset_urls(self, parsed: PageParser, base: str, origin: str) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        for raw in parsed.scripts + parsed.stylesheets + parsed.images:
            absolute = urljoin(base, raw.strip())
            if not absolute.lower().startswith(("http://", "https://")):
                continue
            if not _same_origin(absolute, origin) or absolute in seen:
                continue
            seen.add(absolute)
            urls.append(absolute)
        return urls[: max(0, int(self.config.fetcher.max_assets))]

    @staticmethod
    def _archive_urls(parsed: PageParser, base: str, origin: str) -> list[str]:
        urls: list[str] = []
        for raw in parsed.anchors + parsed.scripts + parsed.iframes:
            candidate = urljoin(base, raw.strip())
            if not candidate.lower().startswith(("http://", "https://")):
                continue
            if not _same_origin(candidate, origin):
                continue
            if urlsplit(candidate).path.lower().endswith(ARCHIVE_SUFFIXES) and candidate not in urls:
                urls.append(candidate)
        return urls

    # -- fetching ------------------------------------------------------------
    async def _fetch_assets(self, urls: list[str]) -> list[KitFile]:
        if not urls:
            return []
        semaphore = asyncio.Semaphore(3)

        async def one(url: str) -> KitFile:
            async with semaphore:
                result = await self.fetcher.fetch(
                    url,
                    provider="kit",
                    note="kit asset",
                    max_bytes=ASSET_MAX_BYTES,
                    max_redirects=2,
                )
            return self._file_from_result(url, result)

        return list(await asyncio.gather(*(one(url) for url in urls)))

    def _file_from_result(self, url: str, result: FetchResult) -> KitFile:
        final = result.final_url or url
        path = urlsplit(final).path or "/"
        kind = kind_for(path, result.content_type, result.content)
        if result.content:
            # Text is needed for extraction even when no repository/evidence
            # store is bound (the fetcher then returns no evidence id).
            self._texts[final] = result.text
        return KitFile(
            path=path,
            url=final,
            kind=kind,
            origin="asset",
            status_code=result.status_code,
            size=result.size_bytes,
            sha256=result.sha256,
            evidence_id=result.evidence_id,
            error=result.error,
        )

    def _file_text(self, item: KitFile) -> str:
        text = self._texts.get(item.url)
        if text is not None:
            return text
        if not item.evidence_id or not item.sha256:
            return ""
        store = getattr(self.fetcher, "store", None)
        if store is None:
            return ""
        path = store.root / item.sha256[:2] / f"{item.sha256}.bin"
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    # -- probing -------------------------------------------------------------
    async def _probe_paths(
        self,
        report: KitReport,
        origin: str,
        *,
        max_probes: int | None,
    ) -> list[KitFile]:
        configured = list(self.config.fetcher.kit_paths or [])
        # Text/log/config paths first; archives last so a small probe budget is
        # spent on the paths that actually disclose data.
        configured.sort(key=lambda path: urlsplit(path).path.lower().endswith(ARCHIVE_SUFFIXES))
        if max_probes is not None:
            configured = configured[: max(0, max_probes)]
        existing = {urlsplit(item.url).path for item in report.files}
        paths = [path for path in dict.fromkeys(configured) if path not in existing]
        if not paths:
            return []
        semaphore = asyncio.Semaphore(3)

        async def probe(path: str) -> tuple[str, FetchResult]:
            async with semaphore:
                return path, await self.fetcher.fetch(
                    origin + path,
                    provider="kit",
                    note=f"kit path probe {path}",
                    max_bytes=PROBE_BYTES,
                    max_redirects=2,
                    record=False,
                )

        results = await asyncio.gather(*(probe(path) for path in paths))
        files: list[KitFile] = []
        counted: set[str] = set()
        for path, result in results:
            if result.error or result.status_code is None:
                continue
            if result.status_code in (400, 404, 410):
                continue
            challenge = looks_like_challenge(result)
            kind = "challenge" if challenge else kind_for(path, result.content_type, result.content)
            entry = {
                "path": path,
                "status_code": result.status_code,
                "kind": kind,
                "size": result.size_bytes,
                "content_type": result.content_type,
                "note": self._probe_note(result, kind),
                "evidence_id": None,
            }
            if challenge:
                report.add_note(f"{path}: bot challenge / WAF page (HTTP {result.status_code})")
                report.exposed_paths.append(entry)
                continue
            if result.status_code >= 400:
                report.exposed_paths.append(entry)
                continue
            if kind == "binary":
                continue

            full = await self.fetcher.fetch(
                origin + path,
                provider="kit",
                note=f"kit exposed path {path}",
                max_bytes=ARCHIVE_MAX_BYTES if kind == "archive" else PROBE_FULL_BYTES,
                max_redirects=2,
            )
            if full.error:
                entry["note"] = (entry["note"] + f"; full fetch failed: {full.error}")[:300]
                report.exposed_paths.append(entry)
                continue
            if full.sha256 and full.sha256 == report.kit_sha256:
                entry["note"] = "same content as landing page (catch-all route)"
                report.exposed_paths.append(entry)
                continue
            entry["size"] = full.size_bytes
            entry["evidence_id"] = full.evidence_id
            kind = kind_for(path, full.content_type, full.content)
            entry["kind"] = kind
            entry["note"] = self._probe_note(full, kind)
            report.exposed_paths.append(entry)

            if kind == "archive":
                await self._inspect_archive_bytes(report, full.content, path)
                continue
            final = full.final_url or origin + path
            self._texts[final] = full.text
            files.append(KitFile(
                path=path,
                url=final,
                kind=kind,
                origin="probe",
                status_code=full.status_code,
                size=full.size_bytes,
                sha256=full.sha256,
                evidence_id=full.evidence_id,
            ))
            if kind in {"log", "text", "source", "json", "php"}:
                # The same dump is often reachable at several spellings
                # (/logs, /logs/, /results.csv); count each unique body once.
                digest = full.sha256 or ""
                count, types, masks = credential_signals(full.text)
                if count and digest and digest in counted:
                    report.add_note(f"{path}: duplicate of an already-counted dump (not recounted)")
                    count = 0
                if count:
                    if digest:
                        counted.add(digest)
                    report.credential_exposure_count += count
                    for item in types:
                        if item not in report.credential_exposure_types:
                            report.credential_exposure_types.append(item)
                    for mask in masks:
                        if mask not in report.credential_masks and len(report.credential_masks) < 8:
                            report.credential_masks.append(mask)
                    report.add_note(
                        f"{path}: {count} credential record(s) exposed "
                        f"({', '.join(types)}); values redacted, not stored"
                    )
                if kind == "source" or full.text.lstrip().startswith("<?php"):
                    report.add_note(f"{path}: server-side source disclosed (PHP)")
        return files

    @staticmethod
    def _probe_note(result: FetchResult, kind: str) -> str:
        if kind == "challenge":
            return f"protected by bot challenge (HTTP {result.status_code})"
        if kind == "log":
            return "open log file — captured credentials may be exposed"
        if kind == "source":
            return "server-side source code disclosed"
        if kind == "archive":
            return "downloadable archive — inspected in memory, never executed"
        if result.status_code == 200:
            return "open path"
        return f"HTTP {result.status_code}"

    # -- archives ------------------------------------------------------------
    async def _inspect_archive_url(self, report: KitReport, url: str) -> None:
        result = await self.fetcher.fetch(
            url,
            provider="kit",
            note="kit archive",
            max_bytes=ARCHIVE_MAX_BYTES,
            max_redirects=2,
        )
        if result.error or not result.content:
            report.add_note(f"archive {urlsplit(url).path}: fetch failed ({result.error or 'empty'})")
            return
        report.files.append(KitFile(
            path=urlsplit(url).path,
            url=result.final_url or url,
            kind="archive",
            origin="archive",
            status_code=result.status_code,
            size=result.size_bytes,
            sha256=result.sha256,
            evidence_id=result.evidence_id,
        ))
        await self._inspect_archive_bytes(report, result.content, urlsplit(url).path)

    async def _inspect_archive_bytes(self, report: KitReport, data: bytes, path: str) -> None:
        if not data.startswith(b"PK"):
            report.add_note(f"{path}: archive format not ZIP (RAR/7z/tar recorded as metadata only)")
            return
        members, warnings = inspect_zip(data)
        for warning in warnings:
            report.add_note(warning)
        if not members:
            report.add_note(f"{path}: archive contained no safe members")
            return
        report.add_note(f"{path}: {len(members)} archive member(s) inspected in memory")
        for member in members[:MAX_ARCHIVE_MEMBERS]:
            kind = kind_for(member["path"], None, member["content"])
            text = ""
            if is_text_kind(kind):
                text = member["content"].decode("utf-8", errors="replace")[:MAX_ARCHIVE_TEXT]
                self._archive_texts.append((member["path"], text))
            report.archive_members.append({
                "archive": path,
                "path": member["path"],
                "size": member["size"],
                "sha256": member["sha256"],
                "kind": kind,
                "text": redact_secret_text(text),
            })

    # -- extraction -----------------------------------------------------------
    def _extract(self, report: KitReport, corpus: list[tuple[str, str]], *, parsed: PageParser) -> None:
        emails: dict[str, dict] = {}
        telegram: dict[str, dict] = {}
        webhooks: dict[str, dict] = {}
        analytics: dict[tuple[str, str], dict] = {}
        authors: list[str] = []
        author_keys: set[str] = set()

        for source, text in corpus:
            if not text:
                continue
            for value in extract_emails(text):
                entry = emails.setdefault(value, {"value": value, "sources": []})
                if source not in entry["sources"] and len(entry["sources"]) < 5:
                    entry["sources"].append(source)
            for bot in extract_telegram(text):
                current = telegram.get(bot["bot_id"])
                if current is None:
                    telegram[bot["bot_id"]] = bot
                else:
                    for chat in bot.get("chat_ids", []):
                        if chat not in current["chat_ids"] and len(current["chat_ids"]) < 20:
                            current["chat_ids"].append(chat)
            for hook in extract_webhooks(text):
                webhooks.setdefault(hook["url_sha256"], hook)
            for item in extract_analytics(text):
                analytics.setdefault((item["kind"], item["value"]), item)
            for author in extract_author_strings(text):
                key = author.lower()
                if key not in author_keys and len(authors) < 20:
                    author_keys.add(key)
                    authors.append(author)

        report.exfil_emails = list(emails.values())[:30]
        report.telegram_bots = list(telegram.values())[:10]
        report.webhooks = list(webhooks.values())[:15]
        report.analytics_ids = list(analytics.values())[:20]
        report.author_strings = authors

        fields: list[dict] = []
        seen_fields: set[tuple[str, str]] = set()
        for form in parsed.forms[:20]:
            action = urljoin(report.final_url or report.url, form.get("action") or "")[:500]
            for form_field in form.get("inputs", [])[:40]:
                name = (form_field.get("name") or "").strip()
                if not name:
                    continue
                key = (name.lower(), form_field.get("type", ""))
                if key in seen_fields:
                    continue
                seen_fields.add(key)
                fields.append({
                    "name": name[:80],
                    "type": form_field.get("type", "")[:30],
                    "form_action": action,
                    "placeholder": form_field.get("placeholder", "")[:80],
                })
        report.form_fields = fields[:60]

        paths = [item.path for item in report.files]
        host = urlsplit(report.final_url or report.url).hostname or ""
        body_text = " ".join(text for _, text in corpus[:4])[:200_000]
        brand, confidence, evidence = detect_brand(
            title=report.title, text=body_text, host=host, paths=paths
        )
        report.brand = brand
        report.brand_confidence = confidence
        report.brand_evidence = evidence

        if report.telegram_bots:
            report.add_note(f"Telegram exfiltration: {len(report.telegram_bots)} bot(s) (tokens redacted)")
        if report.exfil_emails:
            report.add_note(f"exfiltration e-mail candidate(s): {len(report.exfil_emails)}")
        if report.webhooks:
            report.add_note(f"webhook(s) referenced: {len(report.webhooks)}")
        if report.analytics_ids:
            report.add_note(f"tracking/analytics identifiers: {len(report.analytics_ids)}")
        if any(field.get("type") == "password" for field in report.form_fields):
            report.add_note("credential-harvesting form contains a password field")
        otp_names = {"otp", "code", "pin", "otpcode", "2fa", "token"}
        if any(str(field.get("name", "")).lower() in otp_names for field in report.form_fields):
            report.add_note("form also collects one-time codes (OTP/2FA)")

    # -- hashing -------------------------------------------------------------
    def _hash_report(self, report: KitReport, landing: bytes) -> None:
        entries = [(item.path, item.sha256) for item in report.files if item.sha256]
        entries.extend((member["path"], member["sha256"]) for member in report.archive_members)
        report.file_tree_hash = file_tree_hash(entries) if entries else None
        ssdeep_value, tlsh_value, local, notes = fuzzy_hashes(landing)
        report.ssdeep = ssdeep_value
        report.tlsh = tlsh_value
        report.local_simhash = local
        for note in notes:
            report.add_note(note)

    # -- summary / pivots -----------------------------------------------------
    def _summarize(self, report: KitReport, parsed: PageParser) -> None:
        if report.status_code:
            report.add_note(
                f"landing page HTTP {report.status_code}, {len(report.files)} file(s) captured, "
                f"{sum(item.size for item in report.files)} bytes"
            )
        if report.truncated:
            report.add_note("landing page truncated at the configured byte cap")
        if report.brand:
            report.add_note(f"brand lure: {report.brand} ({report.brand_confidence} confidence)")
        if parsed.iframes:
            report.add_note(f"embedded iframe(s): {len(parsed.iframes)} (not fetched)")
        if report.exposed_paths:
            open_paths = [item for item in report.exposed_paths if item.get("status_code") == 200]
            if open_paths:
                report.add_note(f"open paths: {', '.join(item['path'] for item in open_paths[:8])}")

    def _pivots(self, report: KitReport) -> list[dict]:
        """Candidate indicators for the graph, validated by the normalizer."""
        candidates: list[dict] = []

        def add(kind: str, value: str, relation: str, strength: str, confidence: float, note: str) -> None:
            try:
                indicator = normalize_indicator(value, kind=kind)
            except (ValueError, TypeError):
                return
            candidates.append({
                "type": indicator.type,
                "value": indicator.normalized,
                "display": indicator.display or indicator.normalized,
                "relation": relation,
                "strength": strength,
                "confidence": round(max(0.0, min(1.0, confidence)), 4),
                "note": note,
                "tags": list(dict.fromkeys(["kit", *indicator.tags])),
            })

        for item in report.exfil_emails:
            add("email", item["value"], "kit-exfil-email", "strong", 0.9,
                "exfiltration address embedded in kit code")
        for bot in report.telegram_bots:
            add("telegram", f"bot:{bot['bot_id']}", "kit-telegram-exfil", "strong", 0.9,
                "Telegram bot used by the kit (token redacted)")
            for chat in bot.get("chat_ids", []):
                add("telegram", chat, "kit-telegram-chat", "medium", 0.7,
                    "Telegram chat ID hardcoded in the kit")
        for hook in report.webhooks:
            if hook.get("url"):
                add("url", hook["url"], "kit-webhook", "medium", 0.75,
                    f"{hook['kind']} webhook endpoint")
        for item in report.analytics_ids:
            if item["kind"] in {
                "google-analytics-universal", "google-analytics-4", "google-tag-manager",
                "google-ads", "mailchimp", "yandex-metrica", "hotjar", "doubleclick",
            }:
                add("analytics_id", item["value"], "kit-analytics-id", "medium", 0.7,
                    "analytics identifier reused across the campaign")

        deduped: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for item in candidates:
            key = (item["type"], item["value"])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped[:60]
