"""Cross-investigation entity resolution and suspect ranking.

One investigation answers "what is attached to this link".  Attribution needs
the second question: *have we seen this contact, handle, publisher ID or
certificate before, on a different case?*  This module builds that layer.

Three persisted objects make the reasoning auditable:

``Entity``
    A normalized join key with a kind: ``identity`` (email, phone, handle,
    telegram, wallet, analytics publisher ID), ``infrastructure`` (certificate,
    nameserver pair, provider desk) or ``case`` (one investigation).

``EntityMember``
    One row per (entity, indicator, investigation, role).  It records which
    rule fired, at what strength, with which evidence ID and a human-readable
    reason.  Nothing is attributed without a row pointing back to an indicator.

``EntityLink``
    Typed edges between entities (``observed-in-case``, ``co-occurs-with``), so
    a URL can be walked to a person and a person walked back to every case.

The rules are deliberately conservative.  Registrar and hosting desks
(``abuse@``, ``hostmaster@``, ``noc@``, privacy-proxy domains) are recorded as
provider contacts and never promoted to suspects: mistaking a datacentre abuse
mailbox for the operator is the classic phishing-attribution false positive.
Every identity claim carries the caveat that linkage is circumstantial.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

KIND_IDENTITY = "identity"
KIND_INFRASTRUCTURE = "infrastructure"
KIND_CASE = "case"

ROLE_SEED = "seed"
ROLE_REGISTRANT = "registrant-contact"
ROLE_CONTACT = "contact"
ROLE_PROVIDER = "provider-contact"
ROLE_OPERATOR = "operator-handle"
ROLE_EXFIL = "exfil-channel"
ROLE_PUBLISHER = "publisher-id"
ROLE_WALLET = "wallet"
ROLE_CERTIFICATE = "certificate"
ROLE_NAMESERVER = "nameserver-pair"
ROLE_NETWORK = "network-aggregate"

#: Mailboxes that belong to a registrar/hoster, never to a suspect.
PROVIDER_MAILBOXES = frozenset({
    "abuse", "hostmaster", "postmaster", "noc", "whois", "domains", "domainadmin",
    "registrar", "dns", "netadmin", "ipadmin", "ripe", "abuse-reports",
})

#: Hosting, registrar and DNS providers whose own contact data is not evidence.
PROVIDER_DOMAINS = frozenset({
    "godaddy.com", "namecheap.com", "cloudflare.com", "interserver.net", "hostinger.com",
    "namesilo.com", "tucows.com", "enom.com", "gandi.net", "ovh.com", "ovh.net",
    "digitalocean.com", "contabo.com", "hetzner.com", "ionos.com", "porkbun.com",
    "dynadot.com", "nic.ru", "reg.ru", "fastly.com", "akamai.com", "imperva.com",
    "sucuri.net", "cpanel.net", "privateemail.com", "namebright.com", "bluehost.com",
    "hostgator.com", "siteground.com", "name.com", "1and1.com", "ionos.co.uk",
    "registrar-servers.com", "above.com", "dan.com", "sedo.com",
})

#: Privacy services: the published address identifies the proxy, not a person.
PRIVACY_PROXY_DOMAINS = frozenset({
    "privacyprotect.org", "withheldforprivacy.com", "contactprivacy.com",
    "domainsbyproxy.com", "whoisguard.com", "gdpr-masking.com", "privacyguardian.org",
    "whoisproxy.com", "domainprivacygroup.com",
})

#: Free webmail: a mailbox, not an identity.  Recorded as a caveat.
FREE_MAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
    "live.com", "msn.com", "protonmail.com", "proton.me", "mail.ru", "yandex.ru",
    "yandex.com", "gmx.com", "gmx.net", "aol.com", "icloud.com", "me.com", "zoho.com",
    "tutanota.com", "tuta.io", "mail.com", "web.de", "naver.com", "qq.com", "163.com",
})

_ROLE_BONUS = {
    ROLE_PUBLISHER: 20,
    ROLE_REGISTRANT: 15,
    ROLE_EXFIL: 12,
    ROLE_OPERATOR: 10,
    ROLE_WALLET: 8,
    ROLE_CERTIFICATE: 6,
    ROLE_CONTACT: 0,
    ROLE_PROVIDER: -25,
}

_BASE_SCORE = {"strong": 40, "medium": 22, "weak": 10}

ALWAYS_CAVEAT = (
    "Attribution is circumstantial: a shared contact, certificate or tracking ID "
    "demonstrates a link between cases, not intent or identity. Corroborate with "
    "registry records, subscriber data or legal process before naming a person."
)


@dataclass(frozen=True)
class Join:
    """One deterministic membership decision for one indicator."""

    kind: str
    key: str
    label: str
    role: str
    rule: str
    strength: str
    confidence: float
    reason: str
    meta: dict = field(default_factory=dict)


def _tagged(tags: Iterable[str]) -> set[str]:
    return {str(tag).lower() for tag in tags or ()}


def joins_for(indicator: dict) -> list[Join]:
    """Map one persisted indicator onto zero or more entity memberships.

    The mapping is intentionally table-driven and side-effect free so it can be
    unit-tested without a database.
    """
    type_ = str(indicator.get("type") or "")
    value = str(indicator.get("normalized_value") or "").strip()
    if not value:
        return []
    tags = _tagged(indicator.get("tags") or [])
    meta = indicator.get("meta") or {}
    role_hint = str(meta.get("role") or "").lower()

    if type_ == "email":
        local, _, domain = value.lower().partition("@")
        if not local or not domain:
            return []
        if domain in PRIVACY_PROXY_DOMAINS:
            return [Join(
                KIND_INFRASTRUCTURE, f"provider:{domain}", domain, ROLE_PROVIDER,
                "privacy-proxy", "weak", 0.5,
                f"{value} is published by privacy service {domain}, not by the registrant",
                {"privacy_proxy": True},
            )]
        if domain in PROVIDER_DOMAINS or local in PROVIDER_MAILBOXES:
            return [Join(
                KIND_INFRASTRUCTURE, f"provider:{domain}", domain, ROLE_PROVIDER,
                "provider-desk", "weak", 0.4,
                f"{value} is a registrar/hosting desk mailbox and is excluded from attribution",
            )]
        exfil = bool({"exfil", "exfiltration", "credential-exfil"} & tags) or role_hint in {"exfil", "exfiltration"}
        if exfil:
            return [Join(
                KIND_IDENTITY, f"email:{value.lower()}", value, ROLE_EXFIL,
                "email-indicator", "strong", 0.85,
                "the phishing kit sends captured credentials to this address",
                {"free_mail": domain in FREE_MAIL_DOMAINS},
            )]
        registrant = bool({"rdap", "whois", "registrant"} & tags) or role_hint in {"registrar", "registrant"}
        role = ROLE_REGISTRANT if registrant else ROLE_CONTACT
        return [Join(
            KIND_IDENTITY, f"email:{value.lower()}", value, role, "email-indicator",
            "strong" if registrant else "medium",
            0.8 if registrant else 0.55,
            "registrant/administrative contact published in RDAP/WHOIS" if registrant
            else "email selector observed for this case",
            {"free_mail": domain in FREE_MAIL_DOMAINS},
        )]

    if type_ == "phone":
        return [Join(
            KIND_IDENTITY, f"phone:{value}", value, ROLE_CONTACT, "phone-indicator",
            "strong", 0.7, "phone number observed as a contact channel for the case",
        )]

    if type_ == "telegram":
        handle = value.lstrip("@").lower()
        if not handle:
            return []
        return [Join(
            KIND_IDENTITY, f"telegram:{handle}", f"@{handle}", ROLE_OPERATOR,
            "telegram-indicator", "strong", 0.75,
            "telegram account used to operate or collect from the phishing kit",
        )]

    if type_ == "username":
        handle = value.lower()
        return [Join(
            KIND_IDENTITY, f"handle:{handle}", value, ROLE_OPERATOR, "username-indicator",
            "medium", 0.4,
            f"handle '{value}' is claimed on at least one platform; a handle alone is not an identity",
            {"context_only": bool(indicator.get("context_only"))},
        )]

    if type_ == "btc_address":
        return [Join(
            KIND_IDENTITY, f"wallet:{value.lower()}", value, ROLE_WALLET, "wallet-indicator",
            "strong", 0.8, "cryptocurrency address used for payment or cash-out",
        )]

    if type_ == "analytics_id":
        return [Join(
            KIND_IDENTITY, f"publisher:{value.lower()}", value, ROLE_PUBLISHER,
            "analytics-publisher", "strong", 0.9,
            "tracking/publisher ID embedded in the kit; the same ID implies the same operator",
        )]

    if type_ == "cert_sha256":
        return [Join(
            KIND_INFRASTRUCTURE, f"cert:{value.lower()}", value[:16] + "…", ROLE_CERTIFICATE,
            "certificate-cluster", "strong", 0.85,
            "TLS certificate fingerprint shared by the hosting behind the phishing page",
        )]

    if type_ == "asn":
        return [Join(
            KIND_INFRASTRUCTURE, f"asn:{value.upper()}", value.upper(), ROLE_NETWORK,
            "asn-aggregate", "weak", 0.25,
            "autonomous system hosting the infrastructure; shared hosting is not attribution",
        )]

    return []


def suspect_score(
    *,
    best_strength: str,
    investigation_count: int,
    roles: Iterable[str],
    rule_count: int,
    context_only: bool = False,
) -> int:
    """Score a candidate 1-99 from evidence volume and corroboration.

    Deliberately additive and explainable: an analyst can recompute the number
    by hand from the members listed next to it.  Cross-case repetition is the
    heaviest factor because it is the hardest thing for an actor to fake
    accidentally.
    """
    base = _BASE_SCORE.get(best_strength, 10)
    cases = min(30, 15 * max(0, int(investigation_count) - 1))
    role = max((_ROLE_BONUS.get(r, 0) for r in roles), default=0)
    rules = min(15, 5 * max(0, int(rule_count)))
    penalty = 10 if context_only else 0
    return int(max(1, min(99, base + cases + role + rules - penalty)))


def score_band(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def _strength_of(members: Iterable[dict]) -> str:
    order = {"strong": 3, "medium": 2, "weak": 1}
    best = "weak"
    for member in members:
        if order.get(member.get("strength"), 0) > order.get(best, 0):
            best = member.get("strength") or "weak"
    return best


def _evidence_by_node(edges: Iterable[dict]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for edge in edges:
        evidence = edge.get("evidence_id")
        if not evidence:
            continue
        for node_key in ("src", "dst"):
            node_id = edge.get(node_key)
            if node_id and node_id not in mapping:
                mapping[node_id] = evidence
    return mapping


class EntityResolver:
    """Derive entity memberships for one finished investigation."""

    def __init__(self, repo):
        self.repo = repo

    # ------------------------------------------------------------------ public
    def resolve(self, investigation_id: str) -> dict:
        graph = self.repo.graph(investigation_id)
        nodes = graph.get("nodes") or []
        edges = graph.get("edges") or []
        summary = {
            "investigation_id": investigation_id,
            "entities_created": 0,
            "members_added": 0,
            "links_added": 0,
            "identity_entities": 0,
            "provider_contacts": 0,
            "case_entity_id": None,
        }
        if not nodes:
            return summary

        evidence_by_node = _evidence_by_node(edges)
        case_entity = self._case_entity(investigation_id, nodes, summary)
        touched: set[str] = set()
        identity: dict[str, dict] = {}

        for node in nodes:
            for join in joins_for(node):
                entity, created = self.repo.upsert_entity(
                    kind=join.kind, key=join.key, label=join.label,
                    confidence=join.confidence, meta=join.meta,
                )
                summary["entities_created"] += int(created)
                touched.add(entity["id"])
                if join.kind == KIND_IDENTITY:
                    identity[entity["id"]] = entity
                elif join.role == ROLE_PROVIDER:
                    summary["provider_contacts"] += 1
                member_meta = dict(join.meta)
                member_meta["context_only"] = bool(node.get("context_only"))
                _, added = self.repo.add_entity_member(
                    entity["id"], investigation_id,
                    indicator_id=node.get("id"),
                    role=join.role,
                    join_rule=join.rule,
                    strength=join.strength,
                    confidence=join.confidence,
                    evidence_id=evidence_by_node.get(node.get("id")),
                    reason=join.reason,
                    meta=member_meta,
                )
                summary["members_added"] += int(added)

        for entity in self._nameserver_entities(investigation_id, nodes, edges, evidence_by_node, summary):
            touched.add(entity)
            identity.pop(entity, None)

        summary["identity_entities"] = len(identity)

        if case_entity:
            for entity_id, entity in identity.items():
                _, added = self.repo.link_entities(
                    entity_id, case_entity["id"], "observed-in-case",
                    strength=_strength_of(self.repo.entity_members(entity_id)),
                    confidence=float(entity.get("confidence") or 0.0),
                    shared=[entity.get("label")],
                    investigations=[investigation_id],
                )
                summary["links_added"] += int(added)
            self._co_occurrence_links(list(identity.values()), case_entity, investigation_id, summary)

        for entity_id in touched | ({case_entity["id"]} if case_entity else set()):
            entity = self.repo.refresh_entity(entity_id)
            if not entity:
                continue
            members = self.repo.entity_members(entity_id)
            score = suspect_score(
                best_strength=_strength_of(members),
                investigation_count=entity.get("investigation_count") or 1,
                roles=[m.get("role") for m in members],
                rule_count=len({m.get("join_rule") for m in members}),
                context_only=all((m.get("meta") or {}).get("context_only") for m in members),
            )
            self.repo.set_entity_score(entity_id, score)
        return summary

    # ----------------------------------------------------------------- helpers
    def _case_entity(self, investigation_id: str, nodes: list[dict], summary: dict):
        seed = next((n for n in nodes if (n.get("meta") or {}).get("seed")), None)
        row = self.repo.get_investigation(investigation_id) or {}
        if seed is None:
            seed_normalized = row.get("seed_normalized")
            seed_value = row.get("seed")
            seed_id = None
            seed_type = row.get("seed_type")
        else:
            seed_normalized = seed.get("normalized_value")
            seed_value = seed.get("value")
            seed_id = seed.get("id")
            seed_type = seed.get("type")
        if not seed_normalized:
            return None
        entity, created = self.repo.upsert_entity(
            kind=KIND_CASE,
            key=f"case:{seed_normalized}",
            label=str(seed_value or seed_normalized),
            confidence=1.0,
            meta={"seed_type": seed_type, "seed_normalized": seed_normalized},
        )
        summary["entities_created"] += int(created)
        summary["case_entity_id"] = entity["id"]
        self.repo.add_entity_member(
            entity["id"], investigation_id,
            indicator_id=seed_id,
            role=ROLE_SEED,
            join_rule="case-seed",
            strength="strong",
            confidence=1.0,
            reason="indicator the investigation was started from",
        )
        self.repo.refresh_entity(entity["id"])
        return entity

    def _nameserver_entities(self, investigation_id, nodes, edges, evidence_by_node, summary) -> list[str]:
        """Cluster domains that delegate to the same pair of nameservers."""
        node_by_id = {n.get("id"): n for n in nodes}
        per_domain: dict[str, set[str]] = {}
        for edge in edges:
            if edge.get("dst_type") != "nameserver" or edge.get("src_type") != "domain":
                continue
            src = node_by_id.get(edge.get("src"))
            dst = node_by_id.get(edge.get("dst"))
            if not src or not dst:
                continue
            value = str(dst.get("normalized_value") or "").strip(".").lower()
            if value:
                per_domain.setdefault(src.get("normalized_value") or "", set()).add(value)

        groups: dict[tuple[str, ...], list[str]] = {}
        for domain, names in per_domain.items():
            if len(names) < 2:
                continue
            groups.setdefault(tuple(sorted(names)[:4]), []).append(domain)

        touched: list[str] = []
        for pair, domains in groups.items():
            entity, created = self.repo.upsert_entity(
                kind=KIND_INFRASTRUCTURE,
                key="ns:" + "|".join(pair),
                label=" / ".join(pair),
                confidence=0.55,
                meta={"nameservers": list(pair), "domains": sorted(domains)[:25]},
            )
            summary["entities_created"] += int(created)
            touched.append(entity["id"])
            for domain in sorted(domains):
                node = next(
                    (n for n in nodes if n.get("normalized_value") == domain and n.get("type") == "domain"),
                    None,
                )
                _, added = self.repo.add_entity_member(
                    entity["id"], investigation_id,
                    indicator_id=(node or {}).get("id"),
                    role=ROLE_NAMESERVER,
                    join_rule="nameserver-pair",
                    strength="medium",
                    confidence=0.55,
                    evidence_id=evidence_by_node.get((node or {}).get("id")),
                    reason=f"{domain} delegates to {', '.join(pair)}",
                )
                summary["members_added"] += int(added)
        return touched

    def _co_occurrence_links(self, identity: list[dict], case_entity: dict, investigation_id: str, summary: dict) -> None:
        top = sorted(identity, key=lambda e: float(e.get("confidence") or 0.0), reverse=True)[:12]
        for index, left in enumerate(top):
            for right in top[index + 1:]:
                _, added = self.repo.link_entities(
                    left["id"], right["id"], "co-occurs-with",
                    strength="weak", confidence=0.25,
                    shared=[case_entity.get("label")],
                    investigations=[investigation_id],
                )
                summary["links_added"] += int(added)


def rank_suspects(repo, investigation_ids: str | Iterable[str], *, limit: int = 10) -> dict:
    """Rank identity candidates for one case or a set of related cases.

    Everything in the output is derived from persisted memberships, so an
    analyst can audit each statement against the graph.
    """
    if isinstance(investigation_ids, str):
        ids = [investigation_ids]
    else:
        ids = [str(item) for item in investigation_ids]
    ids = list(dict.fromkeys(ids))

    graphs = {inv: repo.graph(inv) for inv in ids}
    node_values: dict[str, dict[str, dict]] = {}
    neighbour_values: dict[str, dict[str, list[dict]]] = {}
    for inv, graph in graphs.items():
        nodes = {n["id"]: n for n in graph.get("nodes") or []}
        node_values[inv] = nodes
        neighbours: dict[str, list[dict]] = {}
        for edge in graph.get("edges") or []:
            src, dst = edge.get("src"), edge.get("dst")
            if src in nodes and dst in nodes:
                neighbours.setdefault(src, []).append(nodes[dst])
                neighbours.setdefault(dst, []).append(nodes[src])
        neighbour_values[inv] = neighbours

    seen: dict[str, dict] = {}
    for inv in ids:
        for entity in repo.entities_for_investigation(inv):
            if entity.get("kind") != KIND_IDENTITY:
                continue
            if entity["id"] not in seen:
                seen[entity["id"]] = entity

    suspects: list[dict] = []
    for entity in seen.values():
        members = repo.entity_members(entity["id"])
        if not members:
            continue
        roles = [m.get("role") for m in members]
        rules = sorted({m.get("join_rule") for m in members})
        cases = repo.entity_cases(entity["id"])
        strength = _strength_of(members)
        context_only = all((m.get("meta") or {}).get("context_only") for m in members)
        score = suspect_score(
            best_strength=strength,
            investigation_count=len(cases),
            roles=roles,
            rule_count=len(rules),
            context_only=context_only,
        )

        infrastructure: list[dict] = []
        evidence_ids: list[str] = []
        why: list[str] = []
        for member in members:
            reason = member.get("reason") or ""
            why.append(
                f"{reason} [{member.get('join_rule')}, {member.get('strength')}]"
                if reason else f"member of {entity.get('label')} [{member.get('join_rule')}]"
            )
            if member.get("evidence_id") and member["evidence_id"] not in evidence_ids:
                evidence_ids.append(member["evidence_id"])
            indicator_id = member.get("indicator_id")
            inv = member.get("investigation_id")
            node = (node_values.get(inv) or {}).get(indicator_id) if indicator_id else None
            if not node:
                continue
            for neighbour in (neighbour_values.get(inv) or {}).get(indicator_id, []):
                if neighbour.get("type") in {"domain", "ip", "url", "cert_sha256", "nameserver", "asn"}:
                    item = {
                        "type": neighbour.get("type"),
                        "value": neighbour.get("value"),
                        "display": (neighbour.get("meta") or {}).get("display") or neighbour.get("value"),
                    }
                    if item not in infrastructure:
                        infrastructure.append(item)

        if len(cases) > 1:
            others = [c for c in cases if c["id"] not in ids]
            if others:
                why.append(
                    "also seen in " + ", ".join(str(c.get("seed")) for c in others[:5])
                    + (" …" if len(others) > 5 else "")
                )

        caveats = [ALWAYS_CAVEAT]
        if any((m.get("meta") or {}).get("free_mail") for m in members):
            caveats.append("The contact is a free webmail mailbox: it identifies an account, not a person.")
        if ROLE_OPERATOR in roles:
            caveats.append("A reused handle can be impersonation; confirm control of the account.")
        if any((m.get("meta") or {}).get("context_only") for m in members):
            caveats.append("Some memberships come from context-only observations (profile listings, lookalikes).")

        suspects.append({
            "entity_id": entity["id"],
            "label": entity.get("label"),
            "kind": entity.get("kind"),
            "score": score,
            "band": score_band(score),
            "strength": strength,
            "roles": sorted(set(roles)),
            "rules": rules,
            "investigation_count": len(cases),
            "cases": cases,
            "evidence_ids": evidence_ids[:12],
            "linked_infrastructure": infrastructure[:12],
            "why": why[:12],
            "caveats": caveats,
            "first_seen": entity.get("first_seen"),
            "last_seen": entity.get("last_seen"),
        })

    suspects.sort(key=lambda item: (item["score"], item["investigation_count"]), reverse=True)
    return {
        "investigation_ids": ids,
        "seeds": [
            {"investigation_id": inv, "seed": (repo.get_investigation(inv) or {}).get("seed")}
            for inv in ids
        ],
        "suspects": suspects[:limit],
        "candidate_count": len(suspects),
        "method": "deterministic join rules over persisted indicators; provider desks excluded",
        "wording": "candidate identity linked to the case, not a proven offender",
    }
