"""Phase 10: cross-investigation entity resolution and suspect ranking.

The tests are offline: graphs are built by hand through the repository, then the
resolver runs against a real temporary SQLite database.  Every assertion about a
"suspect" is therefore traceable to a persisted membership row.
"""

from __future__ import annotations

import pytest

from phishtrace.core.entities import (
    ALWAYS_CAVEAT,
    KIND_CASE,
    KIND_IDENTITY,
    KIND_INFRASTRUCTURE,
    ROLE_PROVIDER,
    ROLE_REGISTRANT,
    EntityResolver,
    joins_for,
    rank_suspects,
    score_band,
    suspect_score,
)


# --------------------------------------------------------------------- helpers
def investigation(repo, seed: str = "login.evil-example.com", seed_type: str = "domain") -> str:
    row = repo.create_investigation(
        seed=seed,
        seed_type=seed_type,
        seed_normalized=seed,
        config_snapshot={"test": True},
    )
    return row["id"]


def node(repo, inv: str, type_: str, value: str, *, normalized: str | None = None, **kwargs) -> dict:
    indicator, _ = repo.ensure_indicator(
        inv,
        type=type_,
        value=value,
        normalized_value=normalized if normalized is not None else value.lower(),
        **kwargs,
    )
    return indicator


def seed_node(repo, inv: str, seed: str, type_: str = "domain") -> dict:
    return node(repo, inv, type_, seed, meta={"seed": True, "display": seed}, tags=["seed"])


def relate(repo, inv: str, src: dict, dst: dict, relation: str = "related-to", provider: str = "test") -> None:
    repo.add_edge(
        inv,
        src_id=src["id"],
        dst_id=dst["id"],
        relation=relation,
        provider=provider,
        confidence=0.8,
        selector_strength="medium",
    )


# ------------------------------------------------------------------- join rules
def test_provider_desk_mailbox_is_infrastructure_not_identity():
    joins = joins_for({"type": "email", "normalized_value": "abuse@interserver.net"})

    assert len(joins) == 1
    assert joins[0].kind == KIND_INFRASTRUCTURE
    assert joins[0].role == ROLE_PROVIDER
    assert joins[0].rule == "provider-desk"
    assert "excluded from attribution" in joins[0].reason


def test_privacy_proxy_is_infrastructure_and_flagged():
    joins = joins_for({"type": "email", "normalized_value": "abc@withheldforprivacy.com"})

    assert len(joins) == 1
    assert joins[0].kind == KIND_INFRASTRUCTURE
    assert joins[0].rule == "privacy-proxy"
    assert joins[0].meta["privacy_proxy"] is True


def test_whois_tagged_mailbox_becomes_registrant_contact():
    join = joins_for(
        {"type": "email", "normalized_value": "Owner@Evil-Example.com", "tags": ["whois"]}
    )[0]

    assert join.kind == KIND_IDENTITY
    assert join.role == ROLE_REGISTRANT
    assert join.key == "email:owner@evil-example.com"
    assert join.strength == "strong"


def test_untagged_mailbox_is_weaker_than_registrant():
    tagged = joins_for({"type": "email", "normalized_value": "a@evil-example.com", "tags": ["rdap"]})[0]
    plain = joins_for({"type": "email", "normalized_value": "a@evil-example.com"})[0]

    assert plain.kind == KIND_IDENTITY
    assert plain.role != ROLE_REGISTRANT
    assert plain.confidence < tagged.confidence


def test_unknown_indicator_type_produces_no_join():
    assert joins_for({"type": "ja3", "normalized_value": "abcdef"}) == []


# ---------------------------------------------------------------- scoring maths
def test_score_rewards_cross_case_repetition_and_caps_it():
    single = suspect_score(best_strength="strong", investigation_count=1, roles=[], rule_count=1)
    two = suspect_score(best_strength="strong", investigation_count=2, roles=[], rule_count=1)
    many = suspect_score(best_strength="strong", investigation_count=50, roles=[], rule_count=1)

    assert single == 45
    assert two == 60
    assert many == 75  # +30 cap rather than +15 * 49


def test_context_only_membership_is_penalised():
    plain = suspect_score(best_strength="medium", investigation_count=1, roles=[], rule_count=1)
    contextual = suspect_score(
        best_strength="medium", investigation_count=1, roles=[], rule_count=1, context_only=True
    )

    assert contextual == plain - 10
    assert contextual >= 1


def test_score_bands():
    assert score_band(85) == "high"
    assert score_band(70) == "high"
    assert score_band(69) == "medium"
    assert score_band(45) == "medium"
    assert score_band(44) == "low"


# --------------------------------------------------------------------- resolver
def test_resolver_creates_identity_and_case_entities(repo):
    inv = investigation(repo)
    seed = seed_node(repo, inv, "login.evil-example.com")
    email = node(repo, inv, "email", "owner@evil-example.com", tags=["rdap"])
    phone = node(repo, inv, "phone", "+15550100432")
    relate(repo, inv, seed, email, "registrant-email")
    relate(repo, inv, seed, phone, "contact-phone")

    summary = EntityResolver(repo).resolve(inv)

    assert summary["case_entity_id"]
    assert summary["identity_entities"] == 2
    assert summary["entities_created"] >= 3

    entity = repo.get_entity_by_key("email:owner@evil-example.com")
    assert entity["kind"] == KIND_IDENTITY
    members = repo.entity_members(entity["id"])
    assert [m["role"] for m in members] == [ROLE_REGISTRANT]
    assert members[0]["join_rule"] == "email-indicator"
    assert members[0]["investigation_id"] == inv

    case = repo.get_entity(summary["case_entity_id"])
    assert case["kind"] == KIND_CASE
    assert case["key"] == "case:login.evil-example.com"
    assert [m["role"] for m in case["members"]] == ["seed"]


def test_resolver_is_idempotent(repo):
    inv = investigation(repo)
    seed_node(repo, inv, "login.evil-example.com")
    node(repo, inv, "email", "owner@evil-example.com", tags=["rdap"])

    first = EntityResolver(repo).resolve(inv)
    second = EntityResolver(repo).resolve(inv)

    assert first["members_added"] > 0
    assert second["entities_created"] == 0
    assert second["members_added"] == 0
    assert second["links_added"] == 0
    assert repo.get_entity(first["case_entity_id"])["member_count"] == 1


def test_resolver_on_empty_investigation_returns_zeros(repo):
    inv = investigation(repo, seed="empty.evil-example.com")

    summary = EntityResolver(repo).resolve(inv)

    assert summary == {
        "investigation_id": inv,
        "entities_created": 0,
        "members_added": 0,
        "links_added": 0,
        "identity_entities": 0,
        "provider_contacts": 0,
        "case_entity_id": None,
    }


# ------------------------------------------------------------- cross-case joins
def test_same_phone_across_investigations_raises_count_and_score(repo):
    first = investigation(repo, seed="a.evil-example.com")
    second = investigation(repo, seed="b.evil-example.com")
    for inv in (first, second):
        seed = seed_node(repo, inv, repo.get_investigation(inv)["seed"])
        phone = node(repo, inv, "phone", "+15550100432")
        relate(repo, inv, seed, phone, "contact-phone")

    EntityResolver(repo).resolve(first)
    second_summary = EntityResolver(repo).resolve(second)

    phone_entity = repo.get_entity_by_key("phone:+15550100432")
    assert phone_entity["investigation_count"] == 2
    assert second_summary["links_added"] >= 1

    cases = repo.entity_cases(phone_entity["id"])
    assert {c["id"] for c in cases} == {first, second}

    links = repo.get_entity(phone_entity["id"])["links"]
    observed = [link for link in links if link["relation"] == "observed-in-case"]
    assert len(observed) == 2

    ranked = rank_suspects(repo, second)
    assert ranked["suspects"], ranked
    top = ranked["suspects"][0]
    assert top["entity_id"] == phone_entity["id"]
    assert top["investigation_count"] == 2
    assert top["score"] == 60
    assert top["band"] == "medium"
    assert any("a.evil-example.com" in reason for reason in top["why"])


def test_provider_desk_is_recorded_but_never_a_suspect(repo):
    inv = investigation(repo)
    seed = seed_node(repo, inv, "login.evil-example.com")
    desk = node(repo, inv, "email", "abuse@interserver.net", tags=["whois"])
    relate(repo, inv, seed, desk, "abuse-contact")

    summary = EntityResolver(repo).resolve(inv)

    assert summary["provider_contacts"] == 1
    ranked = rank_suspects(repo, inv)
    assert ranked["suspects"] == []

    desk_entity = repo.get_entity_by_key("provider:interserver.net")
    assert desk_entity["kind"] == KIND_INFRASTRUCTURE
    assert [m["role"] for m in repo.entity_members(desk_entity["id"])] == [ROLE_PROVIDER]


def test_analytics_publisher_outranks_platform_handle(repo):
    inv = investigation(repo)
    seed = seed_node(repo, inv, "login.evil-example.com")
    handle = node(repo, inv, "username", "shadowadmin", tags=["sherlock"], context_only=True)
    publisher = node(repo, inv, "analytics_id", "UA-123456-7", tags=["html"])
    relate(repo, inv, seed, handle, "claimed-handle")
    relate(repo, inv, seed, publisher, "tracking-id")

    EntityResolver(repo).resolve(inv)
    ranked = rank_suspects(repo, inv)

    labels = [item["label"] for item in ranked["suspects"]]
    assert labels[0] == "ua-123456-7"
    assert labels[1] == "shadowadmin"
    assert ranked["suspects"][0]["score"] > ranked["suspects"][1]["score"]


def test_nameserver_pair_clusters_domains(repo):
    inv = investigation(repo, seed="evil-one.example")
    first = seed_node(repo, inv, "evil-one.example")
    second = node(repo, inv, "domain", "evil-two.example")
    ns1 = node(repo, inv, "nameserver", "ns1.bulletproof.example")
    ns2 = node(repo, inv, "nameserver", "ns2.bulletproof.example")
    for domain in (first, second):
        relate(repo, inv, domain, ns1, "uses-nameserver", provider="dns")
        relate(repo, inv, domain, ns2, "uses-nameserver", provider="dns")

    EntityResolver(repo).resolve(inv)

    entity = repo.get_entity_by_key("ns:ns1.bulletproof.example|ns2.bulletproof.example")
    assert entity is not None
    assert entity["kind"] == KIND_INFRASTRUCTURE
    assert entity["meta"]["domains"] == ["evil-one.example", "evil-two.example"]
    assert len(repo.entity_members(entity["id"])) == 2


def test_suspect_output_carries_attribution_caveats(repo):
    inv = investigation(repo)
    seed = seed_node(repo, inv, "login.evil-example.com")
    mailbox = node(repo, inv, "email", "operator@gmail.com", tags=["exfil"])
    relate(repo, inv, seed, mailbox, "exfil-to")

    EntityResolver(repo).resolve(inv)
    ranked = rank_suspects(repo, inv)

    caveats = ranked["suspects"][0]["caveats"]
    assert ALWAYS_CAVEAT in caveats
    assert any("free webmail" in caveat for caveat in caveats)
    assert ranked["wording"].startswith("candidate identity")


def test_rank_suspects_handles_unknown_investigation(repo):
    ranked = rank_suspects(repo, "does-not-exist")

    assert ranked["suspects"] == []
    assert ranked["candidate_count"] == 0
    assert ranked["investigation_ids"] == ["does-not-exist"]
