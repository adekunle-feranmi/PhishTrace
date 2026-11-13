"""Tests for the evidence classification behind the console's viewer.

The console picks a renderer from this classification, so a wrong answer is a
functional bug (JSON shown as source) or a safety bug (bytes rendered as a
page). Both directions are covered here, including the awkward captures that
really exist in the database: JSON API responses, RDAP, DNS-over-HTTPS JSON,
Cloudflare block pages served as ``text/html`` and bodies with no
``Content-Type`` at all.
"""

from __future__ import annotations

import pytest

from phishtrace.evidence_preview import KINDS, PREVIEW_LIMIT, classify_evidence


@pytest.mark.parametrize(
    "content_type, expected",
    [
        ("text/html", "html"),
        ("text/html; charset=iso-8859-1", "html"),
        ("application/xhtml+xml", "html"),
        ("application/json", "json"),
        ("application/json; charset=utf-8", "json"),
        ("application/dns-json", "json"),
        ("application/rdap+json", "json"),
        ("application/rdap+json; charset=UTF-8", "json"),
        ("application/vnd.censys.api.v3.host.v1+json", "json"),
        ("image/png", "image"),
        ("image/jpeg", "image"),
        ("application/pdf", "pdf"),
        ("text/plain", "text"),
        ("text/plain; charset=utf-8", "text"),
    ],
)
def test_declared_media_type_wins(content_type, expected):
    assert classify_evidence(content_type, "") == expected


def test_missing_content_type_sniffs_html():
    assert classify_evidence(None, "<!DOCTYPE html>\n<html><body>blocked</body></html>") == "html"
    assert classify_evidence("", '  <html lang="en">') == "html"


def test_missing_content_type_sniffs_json():
    assert classify_evidence(None, '{"data": [1, 2]}') == "json"
    assert classify_evidence("application/octet-stream", '[{"a": 1}]') == "json"


def test_truncated_json_preview_is_still_json():
    assert classify_evidence(None, '{"results": [{"id": "a"}, {"id": "b"') == "json"


def test_plain_words_are_text():
    assert classify_evidence(None, "No records found") == "text"
    assert classify_evidence("application/vnd.some.vendor.type", "plain words") == "text"


def test_binary_body_is_not_rendered_as_markup():
    png = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    assert classify_evidence("application/octet-stream", png) == "binary"


def test_preview_limit_is_usable():
    assert PREVIEW_LIMIT >= 50_000
    assert {"html", "json", "image", "pdf", "text", "binary"} == set(KINDS)


def test_html_preview_budget_covers_inline_stylesheets():
    """A page's first 100 KB is usually CSS; cutting there blanks the frame."""
    from phishtrace.evidence_preview import HTML_PREVIEW_LIMIT, preview_limit_for

    assert HTML_PREVIEW_LIMIT > PREVIEW_LIMIT
    assert preview_limit_for("text/html; charset=utf-8") == HTML_PREVIEW_LIMIT
    assert preview_limit_for("application/xhtml+xml") == HTML_PREVIEW_LIMIT
    assert preview_limit_for("application/json") == PREVIEW_LIMIT
    assert preview_limit_for(None) == PREVIEW_LIMIT
