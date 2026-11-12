"""Normalizer behaviour that every downstream phase depends on."""

from __future__ import annotations

import pytest

from phishtrace.normalizer import (
    canonicalize_url,
    defang,
    extract_indicators,
    guess_type,
    normalize_indicator,
    refang,
    registrable_domain,
)


def test_refang_and_defang_round_trip():
    assert refang("hxxps://evil[.]example[.]com/a") == "https://evil.example.com/a"
    assert refang("hxxp://bad(.)site[dot]net") == "http://bad.site.net"
    assert refang("evil . com") == "evil.com"
    # Sentence punctuation must survive untouched.
    assert refang("Visit evil.com. Then run.") == "Visit evil.com. Then run."
    assert defang("https://evil.example.com/a") == "https[:]//evil[.]example[.]com/a"


def test_canonicalize_url_removes_tracking_and_sorts_query():
    info = canonicalize_url("HTTPS://Evil.Example.COM:443/Path?utm_source=x&b=2&a=1#frag")
    assert info["url"] == "https://evil.example.com/Path?a=1&b=2"
    assert info["host"] == "evil.example.com"
    assert info["port"] is None
    assert info["scheme"] == "https"


def test_canonicalize_url_strips_credentials_and_default_port():
    info = canonicalize_url("http://user:secret@evil.example:80/login")
    assert info["url"] == "http://evil.example/login"
    assert info["username"] == "user"
    assert "secret" not in info["url"]


def test_canonicalize_url_keeps_non_default_port_and_ipv6():
    assert canonicalize_url("https://evil.example:8443/x")["url"] == "https://evil.example:8443/x"
    assert canonicalize_url("http://[2001:db8::1]:8080/a")["url"] == "http://[2001:db8::1]:8080/a"


def test_bare_host_is_treated_as_http_url():
    item = normalize_indicator("evil.example/login")
    assert item.type == "url"
    assert item.normalized == "http://evil.example/login"
    assert "scheme-assumed" in item.tags


def test_url_variants_include_defanged_and_domain():
    item = normalize_indicator("https://login.evil.example.co.uk/a/b?x=1")
    kinds = {v["kind"]: v["value"] for v in item.variants}
    assert kinds["domain"] == "example.co.uk"
    assert kinds["host"] == "login.evil.example.co.uk"
    assert "hxxp" not in kinds["url_defanged"]
    assert "[.]" in kinds["url_defanged"]


@pytest.mark.parametrize(
    "raw,expected_type,expected",
    [
        ("evil[.]example", "domain", "evil.example"),
        ("EVIL.EXAMPLE.", "domain", "evil.example"),
        ("https://xn--bcher-kva.example/", "url", "https://xn--bcher-kva.example/"),
        ("1.2.3.4", "ip", "1.2.3.4"),
        ("[2001:db8::1]", "ip", "2001:db8::1"),
        ("Attacker@Example.COM", "email", "attacker@example.com"),
        ("+1 (415) 555-0132", "phone", "+14155550132"),
        ("08031234567", "phone", "+2348031234567"),
        ("@Some_Channel", "telegram", "some_channel"),
        ("https://t.me/Some_Channel", "telegram", "some_channel"),
        ("UA-12345-1", "analytics_id", "UA-12345-1"),
        ("AS13335", "asn", "AS13335"),
        ("cert:" + "a" * 64, "cert_sha256", "a" * 64),
        ("d41d8cd98f00b204e9800998ecf8427e", "file_hash", "d41d8cd98f00b204e9800998ecf8427e"),
    ],
)
def test_normalization_matrix(raw, expected_type, expected):
    item = normalize_indicator(raw)
    assert item.type == expected_type
    assert item.normalized == expected


def test_telegram_bot_token_is_never_stored_in_full():
    token = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawA"
    item = normalize_indicator(token)
    assert item.type == "telegram"
    assert item.normalized == "bot:123456789"
    blob = item.model_dump_json()
    assert "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawA" not in blob
    assert "123456789:" not in blob


def test_btc_checksum_validation():
    good = normalize_indicator("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
    assert good.normalized.startswith("1") and "p2pkh" in good.tags
    # A truncated/altered address is still useful intelligence, but must be
    # flagged rather than presented as verified.
    bad = normalize_indicator("1BoatSLRHtKNngkdXEeobR76b53LETtpyX", kind="btc_address")
    assert "unverified-checksum" in bad.tags


def test_registrable_domain_uses_public_suffix_list():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("evil.example.com") == "example.com"
    assert registrable_domain("1.2.3.4") == "1.2.3.4"


def test_punycode_domain_flagged():
    item = normalize_indicator("xn--bcher-kva.example")
    assert "punycode" in item.tags
    assert any(v["kind"] == "domain_unicode" for v in item.variants)


def test_guess_type_prefers_explicit_prefixes():
    assert guess_type("cert:" + "b" * 64) == "cert_sha256"
    assert guess_type("ja3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == "ja3"
    assert guess_type("ns:ns1.example.com") == "nameserver"
    assert guess_type("+2348031234567") == "phone"
    assert guess_type("evil.example/login") == "url"


def test_extract_indicators_from_free_text():
    text = (
        "Pay at hxxp://bad-login[.]example.co.uk/secure?x=1 or mail thief@example.org. "
        "Backup IP 203.0.113.9 and hash d41d8cd98f00b204e9800998ecf8427e. "
        "TG https://t.me/scam_channel GA UA-99999-2"
    )
    found = {(i.type, i.normalized) for i in extract_indicators(text)}
    assert ("url", "http://bad-login.example.co.uk/secure?x=1") in found
    assert ("domain", "example.co.uk") in found
    assert ("email", "thief@example.org") in found
    assert ("ip", "203.0.113.9") in found
    assert ("file_hash", "d41d8cd98f00b204e9800998ecf8427e") in found
    assert ("telegram", "scam_channel") in found
    assert ("analytics_id", "UA-99999-2") in found
    # No sentence punctuation or newline-mangled pseudo-domains.
    assert not any(n.endswith(".backup") or n.endswith(".tg") for _, n in found)


def test_extract_indicators_respects_limit():
    text = " ".join(f"https://host{i}.example.com/p" for i in range(60))
    assert len(extract_indicators(text, limit=10)) <= 10


def test_invalid_values_raise():
    with pytest.raises(ValueError):
        normalize_indicator("", kind="domain")
    with pytest.raises(ValueError):
        normalize_indicator("not a domain", kind="domain")
