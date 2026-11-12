"""Phase 11: deterministic intake decomposition (one link -> ordered seeds)."""

from __future__ import annotations

import asyncio

from phishtrace.core.intake import MAX_DERIVED, plan_intake, registrable_domain
from phishtrace.core.pivot import PivotEngine
from phishtrace.core.registry import Registry
from phishtrace.normalizer import normalize_indicator
from phishtrace.tests.conftest import make_config


# ------------------------------------------------------------------- unit tests
def test_url_host_email_and_registrable_domain_are_ordered():
    plan = plan_intake(
        "https://paypal-secure.login-check.co.uk/verify?email=owner@evil-example.com"
    )

    assert plan.seed_type == "url"
    assert [item.relation for item in plan.derived] == [
        "url-host",
        "url-email",
        "registrable-domain",
    ]
    host, mailbox, parent = plan.derived
    assert host.type == "domain" and host.priority == 0
    assert mailbox.type == "email" and mailbox.value == "owner@evil-example.com"
    assert "query parameter 'email'" in mailbox.reason
    assert parent.value == "login-check.co.uk"


def test_ip_url_does_not_produce_a_bogus_parent_domain():
    plan = plan_intake("http://8.8.8.8:8080/login?phone=%2B2348012345678")

    assert [item.type for item in plan.derived] == ["ip", "phone"]
    assert plan.derived[0].value == "8.8.8.8"
    assert plan.derived[1].value == "+2348012345678"
    assert any("non-standard port 8080" in note for note in plan.notes)


def test_analytics_and_wallet_selectors_are_extracted():
    plan = plan_intake(
        "https://evil.example/pay?utm_id=G-ABC123XYZ"
        "&wallet=1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    )
    by_relation = {item.relation: item for item in plan.derived}

    assert by_relation["url-analytics"].value == "G-ABC123XYZ"
    assert by_relation["url-wallet"].type == "btc_address"


def test_punycode_and_shortener_are_explained():
    puny = plan_intake("https://xn--bcher-kva.example/login")
    short = plan_intake("https://bit.ly/3xYzAbC")

    assert any("punycode" in note and "bücher" in note for note in puny.notes)
    assert any("shortener" in note for note in short.notes)


def test_telegram_link_is_recognized_as_telegram_seed():
    plan = plan_intake("https://t.me/scam_support_ng")

    assert plan.seed_type == "telegram"
    assert plan.normalized == "scam_support_ng"
    assert plan.derived == ()


def test_subdomain_seed_derives_parent_domain():
    plan = plan_intake("login.evil-example.com")

    assert plan.seed_type == "domain"
    assert [item.relation for item in plan.derived] == ["parent-domain"]
    assert plan.derived[0].value == "evil-example.com"


def test_email_seed_derives_mail_domain():
    plan = plan_intake("user@example.com")

    assert plan.seed_type == "email"
    assert [(item.type, item.value) for item in plan.derived] == [("domain", "example.com")]


def test_invalid_seed_returns_a_note_instead_of_raising():
    plan = plan_intake("   ")

    assert plan.seed_type == ""
    assert plan.derived == ()
    assert plan.notes


def test_duplicate_selectors_are_deduplicated_and_bounded():
    repeated = "email=a@evil-example.com&email=a@evil-example.com&phone=%2B2348012345678"
    plan = plan_intake(f"https://evil.example/verify?{repeated}")

    values = [item.value.lower() for item in plan.derived]
    assert values.count("a@evil-example.com") == 1
    assert len(plan.derived) <= MAX_DERIVED


def test_registrable_domain_handles_multi_label_suffixes():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("example.com") == "example.com"
    assert registrable_domain("8.8.8.8") == "8.8.8.8"


# ------------------------------------------------------------------ integration
def test_pivot_expands_mailbox_embedded_in_url_seed(tmp_path, repo):
    config = make_config(tmp_path)
    registry = Registry(config, provider_classes=[])
    raw = "https://login.evil-example.com/verify?email=owner@evil-example.com"
    seed = normalize_indicator(raw)
    investigation = repo.create_investigation(
        seed=raw, seed_type=seed.type, seed_normalized=seed.normalized, config_snapshot={}
    )

    engine = PivotEngine(config, registry, repo, investigation["id"])
    asyncio.run(engine.run(seed))

    graph = repo.graph(investigation["id"])
    nodes = {node["normalized_value"]: node for node in graph["nodes"]}
    mailbox = nodes["owner@evil-example.com"]
    assert "intake" in mailbox["tags"]
    edges = [edge for edge in graph["edges"] if edge["relation"] == "url-email"]
    assert edges and edges[0]["dst"] == mailbox["id"]
    assert edges[0]["meta"]["note"].startswith("mailbox found in")
