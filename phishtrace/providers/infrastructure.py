"""Hosting, exposure and look-alike-domain providers.

* Shodan InternetDB  - keyless port/hostname/vuln summary for an IP
* ipinfo             - keyless ASN/org/geo enrichment
* Hudson Rock        - infostealer exposure, aggregate-only for data minimisation
* typosquat          - locally generated look-alike domains (no network)
"""

from __future__ import annotations

from urllib.parse import quote

from phishtrace.models import SelectorStrength
from phishtrace.normalizer import registrable_domain
from phishtrace.providers._util import (
    as_int, as_list, first, indicator_host, parse_date, result_error, safe_domain, safe_ip, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta


class ShodanInternetDbProvider(BaseProvider):
    meta = ProviderMeta(
        name="shodan_internetdb",
        accepts=("ip",),
        emits=("domain",),
        rate_limit=0.8,
        timeout=20.0,
        reliability=0.8,
        category="hosting",
        description="Shodan InternetDB: open ports, hostnames, CPEs and known vulns per IP (keyless)",
        homepage="https://internetdb.shodan.io/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        if ctx.indicator.type != "ip":
            ctx.partial("shodan_internetdb requires an IP seed")
            return ctx.result
        ip = ctx.indicator.normalized
        res = await ctx.http.get_json(
            f"https://internetdb.shodan.io/{quote(ip)}", timeout=20.0,
            cache_key=f"internetdb:{ip}", cache_ttl=3600.0,
        )
        if res.status == 404:
            ctx.result.notes.append("shodan_internetdb: no record for this IP")
            return ctx.result
        if not res.ok:
            ctx.partial(f"shodan_internetdb unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        for hostname in as_list(data.get("hostnames"))[:50]:
            host = safe_domain(hostname)
            if host:
                ctx.emit("domain", host, "reverse-dns-hostname", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["internetdb", "hostname"])
        ports = [as_int(port) for port in as_list(data.get("ports")) if as_int(port)]
        vulns = [text(v) for v in as_list(data.get("vulns")) if text(v)]
        tags = [text(t) for t in as_list(data.get("tags")) if text(t)]
        if ports:
            ctx.result.notes.append("open ports: " + ", ".join(str(port) for port in sorted(set(ports))[:40]))
        if vulns:
            ctx.result.notes.append("known CVEs: " + ", ".join(sorted(set(vulns))[:40]))
        if tags:
            ctx.result.notes.append("shodan tags: " + ", ".join(sorted(set(tags))[:20]))
        return ctx.result


class IpinfoProvider(BaseProvider):
    meta = ProviderMeta(
        name="ipinfo",
        accepts=("ip",),
        emits=("asn", "domain"),
        rate_limit=0.7,
        timeout=20.0,
        reliability=0.85,
        category="hosting",
        description="ipinfo.io geolocation and ASN (keyless; optional IPINFO_TOKEN)",
        homepage="https://ipinfo.io/",
        cache_ttl=86400.0,
    )

    async def run(self, ctx):
        if ctx.indicator.type != "ip":
            ctx.partial("ipinfo requires an IP seed")
            return ctx.result
        ip = ctx.indicator.normalized
        params = {}
        token = ctx.config.api_key("IPINFO_TOKEN")
        if token:
            params["token"] = token
        res = await ctx.http.get_json(
            f"https://ipinfo.io/{quote(ip)}/json", params=params or None, timeout=20.0,
            cache_key=f"ipinfo:{ip}", cache_ttl=86400.0,
        )
        if not res.ok:
            ctx.partial(f"ipinfo unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        asn_data = first(data, "asn", default={})
        asn_value = ""
        asn_name = ""
        if isinstance(asn_data, dict):
            asn_value = text(first(asn_data, "asn"))
            asn_name = text(first(asn_data, "name", "domain"))
        if not asn_value:
            org = text(first(data, "org"))
            if org.upper().startswith("AS"):
                asn_value = org.split()[0]
                asn_name = org[len(asn_value):].strip()
        digits = "".join(ch for ch in asn_value if ch.isdigit())
        if digits:
            ctx.emit(
                "asn", f"AS{digits}", "announced-by", SelectorStrength.STRONG,
                evidence_id=res.evidence_id, tags=["ipinfo"],
                meta={"asn_name": asn_name, "country": text(first(data, "country")),
                      "org": text(first(data, "org"))},
            )
        hostname = safe_domain(first(data, "hostname"))
        if hostname:
            ctx.emit("domain", hostname, "reverse-dns-hostname", SelectorStrength.MEDIUM,
                     evidence_id=res.evidence_id, tags=["ipinfo"])
        country = text(first(data, "country"))
        city = text(first(data, "city"))
        if country:
            ctx.result.notes.append(f"ipinfo location: {city + ', ' if city else ''}{country}")
        return ctx.result


class HudsonRockProvider(BaseProvider):
    meta = ProviderMeta(
        name="hudsonrock",
        accepts=("domain", "email", "username", "ip"),
        emits=(),
        rate_limit=0.4,
        timeout=30.0,
        reliability=0.7,
        category="exposure",
        description="Hudson Rock infostealer exposure (keyless, aggregate-only: no credentials stored)",
        homepage="https://www.hudsonrock.com/",
        cache_ttl=3600.0,
    )

    def _endpoint(self, indicator) -> tuple[str, str] | None:
        if indicator.type == "domain":
            return "search-by-domain", "domain"
        if indicator.type == "email":
            return "search-by-email", "email"
        if indicator.type == "ip":
            return "search-by-ip", "ip"
        if indicator.type in {"username", "telegram"}:
            return "search-by-username", "username"
        return None

    async def run(self, ctx):
        target = self._endpoint(ctx.indicator)
        if target is None:
            ctx.partial("hudsonrock supports domain, email, username and IP seeds")
            return ctx.result
        endpoint, param = target
        value = ctx.indicator.normalized
        res = await ctx.http.get_json(
            f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{endpoint}",
            params={param: value}, timeout=30.0, max_bytes=3_000_000,
            cache_key=f"hudsonrock:{endpoint}:{value}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"hudsonrock unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        stealers = [row for row in as_list(data.get("stealers")) if isinstance(row, dict)]
        # Aggregate only: family names and counts.  Credentials, computer names
        # and victim URLs are deliberately never copied into PhishTrace.
        families: dict[str, int] = {}
        earliest = None
        latest = None
        for row in stealers[:500]:
            family = text(first(row, "stealerFamily", "malware", "stealer"))
            if family:
                families[family] = families.get(family, 0) + 1
            when = parse_date(first(row, "date_compromised", "dateCompromised"))
            if when:
                earliest = when if earliest is None or when < earliest else earliest
                latest = when if latest is None or when > latest else latest
        total = len(stealers) or as_int(first(data, "total", "employees"), 0)
        if not total and not families:
            ctx.result.notes.append("hudsonrock: no infostealer exposure found")
            return ctx.result
        detail = ", ".join(f"{name} x{count}" for name, count in sorted(families.items())[:8])
        when = latest or earliest
        if when:
            ctx.event(
                when, kind="infostealer-exposure",
                label=f"Infostealer exposure associated with {value}",
                detail=(detail or None) if not latest else f"latest={latest.date().isoformat()}; {detail}",
                evidence_id=res.evidence_id, indicator_value=value,
                meta={"records": total, "families": families,
                      "earliest": earliest.isoformat() if earliest else None},
            )
        ctx.result.notes.append(
            f"hudsonrock: {total} record(s) aggregated, families={detail or 'unknown'}"
        )
        return ctx.result


_HOMOGLYPHS = {
    "a": ["4", "@"], "b": ["6", "8"], "c": ["(", "k"], "d": ["cl"], "e": ["3"],
    "g": ["9", "q"], "h": ["lh"], "i": ["1", "l", "!"], "l": ["1", "i"],
    "m": ["rn", "nn"], "n": ["m"], "o": ["0"], "q": ["g"], "s": ["5", "$"],
    "t": ["7"], "u": ["v"], "v": ["u"], "w": ["vv"], "x": ["ks"], "y": ["i"],
    "z": ["2"],
}
_TLD_SWAPS = ("com", "net", "org", "info", "top", "xyz", "online", "site", "live", "click", "shop")


class TyposquatProvider(BaseProvider):
    meta = ProviderMeta(
        name="typosquat",
        accepts=("domain",),
        emits=("domain",),
        rate_limit=10.0,
        timeout=10.0,
        reliability=0.55,
        category="lookalike",
        description="Locally generated look-alike domains (homoglyph, bitsquat, omission, TLD swap)",
        homepage="https://en.wikipedia.org/wiki/Typosquatting",
    )

    async def run(self, ctx):
        domain = indicator_host(ctx.indicator).lower()
        if not domain or "." not in domain:
            ctx.partial("typosquat requires a domain seed")
            return ctx.result
        base = registrable_domain(domain)
        label, _, tld = base.rpartition(".")
        if not label or len(label) > 40:
            ctx.partial("typosquat: domain label unsuitable for permutation")
            return ctx.result
        candidates = self.generate(label, tld)
        emitted = 0
        for candidate in candidates:
            if emitted >= 80:
                break
            if candidate == base or not safe_domain(candidate):
                continue
            emitted += 1
            ctx.emit(
                "domain", candidate, "typosquat-candidate", SelectorStrength.WEAK,
                tags=["typosquat", "unresolved"], confidence_hint=0.15,
                meta={"technique": self._technique(label, candidate)},
            )
        if not emitted:
            ctx.result.notes.append("typosquat: no permutations generated")
        return ctx.result

    @staticmethod
    def _technique(label: str, candidate: str) -> str:
        stem = candidate.rsplit(".", 1)[0]
        if stem == label.replace("-", ""):
            return "tld-swap"
        if len(stem) == len(label):
            diffs = [i for i, (a, b) in enumerate(zip(label, stem)) if a != b]
            if len(diffs) == 1:
                a, b = label[diffs[0]], stem[diffs[0]]
                if a == b.replace("1", "l") or a == b.replace("0", "o"):
                    return "homoglyph"
                return "substitution"
            if len(diffs) == 2 and diffs[0] + 1 == diffs[1]:
                return "transposition"
        if len(stem) == len(label) + 1:
            return "insertion"
        if len(stem) == len(label) - 1:
            return "omission"
        return "variation"

    @staticmethod
    def generate(label: str, tld: str) -> list[str]:
        output: list[str] = []

        def add(stem: str, suffix: str | None = None) -> None:
            if stem and stem != label:
                output.append(f"{stem}.{suffix or tld}")

        for index, char in enumerate(label):
            for replacement in _HOMOGLYPHS.get(char, []):
                add(label[:index] + replacement + label[index + 1:])
            add(label[:index] + label[index + 1:])            # omission
            add(label[:index] + char + label[index:])          # duplication
            if index + 1 < len(label):
                add(label[:index] + label[index + 1] + char + label[index + 2:])  # transposition
        for tld_swap in _TLD_SWAPS:
            if tld_swap != tld:
                output.append(f"{label}.{tld_swap}")
        add(f"{label}-secure")
        add(f"{label}-login")
        add(f"{label}-verify")
        add(f"login-{label}")
        seen: set[str] = set()
        unique: list[str] = []
        for name in output:
            lowered = name.lower()
            if lowered not in seen:
                seen.add(lowered)
                unique.append(lowered)
        return unique[:150]
