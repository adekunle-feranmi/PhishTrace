"""Evidence body classification for the console's evidence browser.

The evidence browser renders captures instead of dumping their bytes: HTML in
a sandboxed frame, JSON as a collapsible tree, images and PDFs natively and
everything else as text. The API exposes this classification so the client
does not have to guess, and the guessing rules stay on the server where they
are covered by tests.

Classification is deliberately conservative. A declared media type wins; an
absent or generic one (``application/octet-stream``, no ``Content-Type`` at
all) falls back to sniffing the body, and an unrecognisable body is reported
as ``binary`` rather than being rendered as markup.
"""

from __future__ import annotations

import json
import re

#: Number of bytes the API hands to the viewer. Captures larger than this are
#: truncated, and the API flags that so the UI can say so instead of silently
#: showing an incomplete page.
PREVIEW_LIMIT = 100_000

KINDS = ("html", "json", "image", "pdf", "text", "binary")

_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_JSON_TYPES = {"application/json", "text/json", "application/dns-json"}
_SCRIPT_TYPES = {"application/javascript", "application/x-javascript", "text/javascript"}

#: Cheap structural test for a JSON document; ``json.loads`` is not used on its
#: own because previews are routinely truncated mid-document.
_JSON_START = re.compile(r'^\s*[\[{]\s*(?:"|[\[\]{}\-0-9]|true\b|false\b|null\b)')


def _media_type(content_type: str | None) -> str:
    """Return the bare media type: ``text/html; charset=utf-8`` -> ``text/html``."""
    return (content_type or "").split(";", 1)[0].strip().lower()


def _looks_like_html(sample: str) -> bool:
    head = sample.lstrip()[:512].lower()
    return head.startswith(("<!doctype html", "<html", "<head", "<body", "<!--")) or "<html" in head


def _looks_like_json(sample: str) -> bool:
    if not _JSON_START.match(sample):
        return False
    try:
        json.loads(sample)
    except ValueError:
        # A truncated preview of a JSON document is still worth a tree view;
        # the viewer falls back to plain text when parsing fails client-side.
        return True
    return True


def _is_printable(sample: str) -> bool:
    if not sample:
        return True
    bad = sum(1 for char in sample if (ord(char) < 32 and char not in "\t\n\r\f") or char == "\ufffd")
    return bad / len(sample) < 0.02


def classify_evidence(content_type: str | None, sample: str = "") -> str:
    """Return one of :data:`KINDS` for a stored evidence body.

    ``sample`` is the decoded preview, used only when the media type is absent
    or too generic to be actionable.
    """
    media = _media_type(content_type)
    if media in _HTML_TYPES:
        return "html"
    if media in _JSON_TYPES or media.endswith("+json"):
        return "json"
    if media == "application/pdf":
        return "pdf"
    if media.startswith("image/"):
        return "image"
    if media.startswith("text/") or media in _SCRIPT_TYPES or media.endswith("+xml") or media == "application/xml":
        return "text"
    if _looks_like_html(sample):
        return "html"
    if _looks_like_json(sample):
        return "json"
    return "text" if _is_printable(sample) else "binary"
