"""Registration and DNS intelligence: RDAP, DNS-over-HTTPS, HackerTarget, ThreatMiner."""

from __future__ import annotations

from urllib.parse import quote

from phishtrace.models import SelectorStrength
from phishtrace.normalizer import extract_indicators
from phishtrace.providers._util import (
    as_list, first, host_matches, indicator_host, iter_lines, parse_date, result_error,
    safe_domain, safe_ip, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DOH_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}

RDAP_EVENT_KINDS = {
    "registration": ("domain-registered", "Domain registration"),
    "last changed": ("domain-updated", "Registration record last changed"),
    "expiration": ("domain-expires", "Domain registration expires"),
    "registrar expiration": ("domain-expires", "Registrar expiration"),
    "last update of RDAP database": ("rdap-updated", "RDAP database last updated"),
    "transfer": ("domain-transfer", "Domain transfer"),
}


def _vcard_values(entity: dict) -> tuple[str, str]:
    """Return (display name, email) from an RDAP jCard."""
    vcard = first(entity, "vcardArray")
    name = email = ""
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return name, email
    for field in vcard[1]:
        if not isinstance(field, list) or len(field) < 4:
            continue
        key = text(field[0]).lower()
        value = field[3]
        if key == "fn" and not name:
            name = text(value)
        elif key == "email" and not email:
            email = text(value)
    return name, email


def _walk_entities(entities, roles_of_interest: tuple[str, ...], depth: int = 0):
    """Yield (role, name, email) for entities carrying one of the wanted roles."""
    if depth > 3:
        return
    for entity in as_list(entities):
        if not isinstance(entity, dict):
            continue
        roles = {text(role).lower() for role in as_list(first(entity, "roles", default=[]))}
        matched = roles.intersection(roles_of_interest)
        if matched:
            name, email = _vcard_values(entity)
            yield sorted(matched)[0], name, email
        yield from _walk_entities(first(entity, "entities", default=[]), roles_of_interest, depth + 1)


class RdapProvider(BaseProvider):
    meta = ProviderMeta(
        name="rdap",
        accepts=("domain", "ip"),
        emits=("nameserver", "email", "asn"),
        rate_limit=0.7,
        timeout=40.0,
        reliability=0.9,
        category="registration",
        description="Registration data (WHOIS successor) via the public RDAP bootstrap",
        homepage="https://rdap.org/",
        cache_ttl=21600.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        if indicator.type == "ip":
            url = f"https://rdap.org/ip/{quote(indicator.normalized)}"
        else:
            domain = indicator_host(indicator)
            if not domain:
                ctx.partial("rdap requires a domain or IP seed")
                return ctx.result
            url = f"https://rdap.org/domain/{quote(domain)}"
        res = await ctx.http.get_json(url, timeout=40.0,
                                      cache_key=f"rdap:{indicator.type}:{indicator.normalized}",
                                      cache_ttl=21600.0)
        if not res.ok or not isinstance(res.data, dict):
            ctx.partial(f"RDAP unavailable: {result_error(res)}")
            return ctx.result
        data = res.data
        if data.get("errorCode"):
            ctx.partial(f"RDAP error: {text(first(data, 'title', 'description'))}")
            return ctx.result

        for event in as_list(first(data, "events", default=[])):
            action = text(first(event, "eventAction")).lower()
            when = parse_date(first(event, "eventDate"))
            kind, label = RDAP_EVENT_KINDS.get(action, (f"rdap-{action or 'event'}", f"RDAP {action or 'event'}"))
            if when:
                ctx.event(
                    when, kind=kind, label=f"{label} for {indicator.normalized}",
                    evidence_id=res.evidence_id, indicator_value=indicator.normalized,
                    meta={"event_action": action},
                )

        for ns in as_list(first(data, "nameservers", default=[])):
            host = safe_domain(first(ns, "ldhName", "unicodeName"))
            if host:
                ctx.emit("nameserver", host, "nameserver", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["rdap"])

        for role, name, email in _walk_entities(first(data, "entities", default=[]),
                                                ("registrant", "administrative", "technical")):
            if name:
                ctx.result.notes.append(f"{role}: {name}")
            if email and "@" in email:
                ctx.emit("email", email, f"rdap-{role}-contact", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["rdap", role])

        # Some RDAP servers expose the network's ASN on IP lookups.
        for role, name, _ in _walk_entities(first(data, "entities", default=[]), ("registrar",)):
            if name:
                ctx.result.notes.append(f"registrar: {name}")
        asn_value = first(data, "autnum", "asn")
        if asn_value:
            digits = "".join(ch for ch in text(asn_value) if ch.isdigit())
            if digits:
                ctx.emit("asn", f"AS{digits}", "announced-by", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["rdap"])
        return ctx.result


class DnsIntelProvider(BaseProvider):
    meta = ProviderMeta(
        name="dns_intel",
        accepts=("domain", "url", "ip"),
        emits=("ip", "nameserver", "domain", "analytics_id", "email"),
        rate_limit=1.0,
        timeout=20.0,
        reliability=0.95,
        category="dns",
        description="Authoritative-ish DNS records through Cloudflare DNS-over-HTTPS (keyless)",
        homepage="https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
        cache_ttl=900.0,
    )

    async def _query(self, ctx, name: str, qtype: str):
        params = {"name": name, "type": qtype}
        return await ctx.http.get_json(
            DOH_ENDPOINT, params=params, headers={"Accept": "application/dns-json"},
            timeout=15.0, cache_key=f"doh:{qtype}:{name}", cache_ttl=900.0,
        )

    async def run(self, ctx):
        host = indicator_host(ctx.indicator)
        if not host:
            ctx.partial("dns_intel requires a domain, URL or IP seed")
            return ctx.result

        if ctx.indicator.type == "ip":
            import ipaddress
            ip = ipaddress.ip_address(host)
            reverse = ip.reverse_pointer
            res = await self._query(ctx, reverse, "PTR")
            for answer in self._answers(res):
                ptr = safe_domain(text(answer.get("data")).rstrip("."))
                if ptr:
                    ctx.emit("domain", ptr, "ptr-record", SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, tags=["dns", "ptr"])
            if not res.ok:
                ctx.partial(f"DoH PTR lookup failed: {result_error(res)}")
            return ctx.result

        if ctx.indicator.type == "url":
            host = indicator_host(ctx.indicator)
        queried = 0
        for qtype in ("A", "NS", "MX", "TXT", "CNAME"):
            res = await self._query(ctx, host, qtype)
            if not res.ok:
                if res.error:
                    ctx.partial(f"DoH {qtype} lookup failed: {result_error(res)}")
                continue
            queried += 1
            for answer in self._answers(res):
                self._handle_answer(ctx, res, qtype, answer, host)
        if not queried:
            ctx.partial("no DNS answers could be retrieved")
        return ctx.result

    @staticmethod
    def _answers(res) -> list[dict]:
        data = res.data if isinstance(res.data, dict) else {}
        return [a for a in as_list(data.get("Answer")) if isinstance(a, dict)]

    def _handle_answer(self, ctx, res, qtype: str, answer: dict, seed_host: str) -> None:
        value = text(answer.get("data")).strip()
        if qtype == "TXT":
            value = value.strip('"')
        value = value.rstrip(".")
        evidence = res.evidence_id
        if qtype in ("A", "AAAA"):
            ip = safe_ip(value)
            if ip:
                ctx.emit("ip", ip, "resolves-to", SelectorStrength.STRONG, evidence_id=evidence,
                         tags=["dns", qtype.lower()])
        elif qtype == "NS":
            ns = safe_domain(value)
            if ns:
                ctx.emit("nameserver", ns, "nameserver", SelectorStrength.STRONG,
                         evidence_id=evidence, tags=["dns"])
        elif qtype in ("MX", "CNAME"):
            parts = value.split()
            target = safe_domain(parts[-1] if parts else "")
            if target and target != seed_host:
                ctx.emit("domain", target, f"{qtype.lower()}-target", SelectorStrength.MEDIUM,
                         evidence_id=evidence, tags=["dns", qtype.lower()])
        elif qtype == "TXT":
            self._handle_txt(ctx, res, value, seed_host)

    def _handle_txt(self, ctx, res, value: str, seed_host: str) -> None:
        lowered = value.lower()
        if lowered.startswith("v=spf1"):
            for token in value.split():
                if token.lower().startswith("include:"):
                    include = safe_domain(token.split(":", 1)[1])
                    if include and include != seed_host:
                        ctx.emit("domain", include, "spf-include", SelectorStrength.WEAK,
                                 evidence_id=res.evidence_id, tags=["dns", "spf"])
        if len(value) > 2000:
            return
        for found in extract_indicators(value, limit=10, include_url_parts=False):
            if found.type in {"analytics_id", "email"}:
                ctx.emit(found.type, found.normalized, "dns-txt-record", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["dns", "txt"])


class HackerTargetProvider(BaseProvider):
    meta = ProviderMeta(
        name="hackertarget",
        accepts=("domain",),
        emits=("domain", "ip"),
        rate_limit=0.2,
        timeout=30.0,
        reliability=0.7,
        category="dns",
        description="Host search (passive DNS) via HackerTarget's free API",
        homepage="https://hackertarget.com/host-search/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        domain = indicator_host(ctx.indicator)
        if not domain:
            ctx.partial("hackertarget requires a domain seed")
            return ctx.result
        res = await ctx.http.get_text(
            "https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=30.0,
            cache_key=f"hackertarget:{domain}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"hackertarget unavailable: {result_error(res)}")
            return ctx.result
        if "API count exceeded" in res.text or res.text.lower().startswith("error"):
            ctx.partial(f"hackertarget quota/error: {res.text[:160]}")
            return ctx.result
        for line in iter_lines(res.text, limit=500):
            host, _, ip_text = line.partition(",")
            host = safe_domain(host)
            ip = safe_ip(ip_text)
            if host and host_matches(host, domain):
                ctx.emit("domain", host, "passive-dns", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["passive-dns"])
            if ip:
                ctx.emit("ip", ip, "passive-dns", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["passive-dns"])
        return ctx.result


class ThreatMinerProvider(BaseProvider):
    meta = ProviderMeta(
        name="threatminer",
        accepts=("domain", "ip"),
        emits=("ip", "domain"),
        rate_limit=0.3,
        timeout=30.0,
        reliability=0.75,
        category="threat-intel",
        description="Passive DNS and related infrastructure via ThreatMiner",
        homepage="https://www.threatminer.org/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        if indicator.type == "ip":
            url = "https://api.threatminer.org/v2/host.php"
            params = {"q": indicator.normalized, "rt": "2"}  # passive DNS domains
        else:
            domain = indicator_host(indicator)
            if not domain:
                ctx.partial("threatminer requires a domain or IP seed")
                return ctx.result
            url = "https://api.threatminer.org/v2/domain.php"
            params = {"q": domain, "rt": "5"}  # passive DNS
        res = await ctx.http.get_json(url, params=params, timeout=30.0,
                                      cache_key=f"threatminer:{indicator.type}:{indicator.normalized}",
                                      cache_ttl=3600.0)
        if not res.ok:
            ctx.partial(f"threatminer unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        if text(data.get("status_code")) not in {"200", ""}:
            ctx.partial(f"threatminer status {text(data.get('status_code'))}")
            return ctx.result
        for row in as_list(data.get("results")):
            if isinstance(row, dict):
                candidate = first(row, "ip", "domain", "value")
            else:
                candidate = row
            ip = safe_ip(candidate)
            if ip:
                ctx.emit("ip", ip, "passive-dns", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["passive-dns"])
                continue
            domain_name = safe_domain(candidate)
            if domain_name:
                ctx.emit("domain", domain_name, "passive-dns", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["passive-dns"])
        return ctx.result
