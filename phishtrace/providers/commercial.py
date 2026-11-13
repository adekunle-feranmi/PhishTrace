"""Commercial threat-intelligence feed providers (Phase B).

These close the "commercial feeds" gap tracked in docs/PROVIDERS.md:
DomainTools, ValidIn, SilentPush, Netlas, CriminalIP and a dedicated
GreyNoise RIOT lookup that reuses the existing ``GREYNOISE_API_KEY``.

The same defensive parsing rules as ``keyed.py`` apply: vendor payloads change
shape without notice, so every record access goes through ``first``/``as_list``
and one malformed record never aborts the pivot.  All credentials travel in
headers or query parameters the evidence redactor already covers
(``Authorization``, ``X-API-KEY``, ``x-api-key``, ``key``, ``api_key``).
"""

from __future__ import annotations

from datetime import datetime, timezone

from phishtrace.models import SelectorStrength
from phishtrace.providers._util import (
    as_int, as_list, first, parse_date, result_error, safe_domain, safe_ip, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta
from phishtrace.providers.keyed import _KeyedProvider, _asn_label


def _epoch(value) -> datetime | None:
    """Convert a ValidIn-style unix-seconds stamp to UTC datetime."""
    try:
        seconds = int(float(value))
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _observed(row: dict) -> datetime | None:
    """Best-effort observation time from a ValidIn record (epoch or ISO)."""
    raw = first(row, "last_seen", "first_seen")
    return _epoch(raw) or parse_date(raw)


def _dns_records_from_validin(data: dict) -> list[tuple[str, dict]]:
    """Flatten a ValidIn ``records`` map into ``(record_type, row)`` pairs."""
    records = first(data, "records", default={})
    if not isinstance(records, dict):
        return []
    pairs: list[tuple[str, dict]] = []
    for record_type, rows in records.items():
        for row in as_list(rows):
            if isinstance(row, dict):
                pairs.append((text(record_type).upper(), row))
    return pairs


# --------------------------------------------------------------------------- #
# DomainTools
# --------------------------------------------------------------------------- #
class DomainToolsProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="domaintools",
        phase="B",
        accepts=("domain", "url"),
        emits=("nameserver", "email", "ip"),
        api_keys=("DOMAINTOOLS_API_KEY",),
        rate_limit=0.5,
        timeout=30.0,
        reliability=0.85,
        category="domain-intel",
        description="DomainTools WHOIS: registrar, registration dates, nameservers, registrant contacts",
        homepage="https://www.domaintools.com/",
        cache_ttl=86400.0,
    )

    def missing_keys(self, config) -> list[str]:
        missing = super().missing_keys(config)
        if not (self.options.get("username") or config.has_key("DOMAINTOOLS_USERNAME")):
            missing.append("DOMAINTOOLS_USERNAME")
        return missing

    async def run(self, ctx):
        key = self.key(ctx.config)
        username = self.options.get("username") or ctx.config.api_key("DOMAINTOOLS_USERNAME")
        if not key or not username:
            ctx.partial("domaintools: DOMAINTOOLS_API_KEY / DOMAINTOOLS_USERNAME not configured")
            return ctx.result
        domain = safe_domain(ctx.indicator.normalized)
        if not domain and ctx.indicator.type == "url":
            from phishtrace.providers._util import url_host
            domain = safe_domain(url_host(ctx.indicator.normalized))
        if not domain:
            ctx.partial("domaintools needs a domain or URL indicator")
            return ctx.result
        res = await ctx.http.get_json(
            f"https://api.domaintools.com/v1/whois/{domain}/",
            params={"api_username": username, "api_key": key},
            timeout=30.0, max_bytes=2_000_000,
            cache_key=f"domaintools:{domain}", cache_ttl=86400.0,
        )
        if not res.ok:
            ctx.partial(f"domaintools unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        whois = first(data, "whois", default={})
        if not isinstance(whois, dict):
            whois = {}
        parsed = whois.get("parsed")
        if isinstance(parsed, list):
            parsed = parsed[0] if parsed and isinstance(parsed[0], dict) else {}
        if not isinstance(parsed, dict):
            parsed = {}
        if not parsed:
            ctx.partial("domaintools returned no parsed WHOIS record")
            return ctx.result
        registrar = text(first(parsed, "registrar"))
        created = parse_date(first(parsed, "created_date", "created"))
        ctx.event(
            created, kind="domain-registered",
            label=f"DomainTools: {domain} registered",
            detail=f"registrar={registrar}",
            evidence_id=res.evidence_id, precision="day", indicator_value=domain,
            meta={
                "registrar": registrar,
                "created": text(first(parsed, "created_date", "created")),
                "expires": text(first(parsed, "expiration_date", "expires")),
                "updated": text(first(parsed, "updated_date", "updated")),
                "whois_server": text(first(parsed, "whois_server")),
            },
        )
        servers = as_list(first(parsed, "name_servers", "nameservers", default=[]))
        for host in servers[:20]:
            value = safe_domain(text(host).split(",")[0])
            if value:
                ctx.emit("nameserver", value, "nameserver", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["domaintools"])
        emails = as_list(first(parsed, "email", "emails", default=[]))
        for email in emails[:10]:
            value = text(email).lower()
            if "@" in value and len(value) < 320:
                ctx.emit(
                    "email", value, "registrant-contact", SelectorStrength.WEAK,
                    evidence_id=res.evidence_id, tags=["domaintools", "registrant"],
                    context_only=True, note="WHOIS contact address; often a privacy proxy",
                )
        return ctx.result


# --------------------------------------------------------------------------- #
# ValidIn
# --------------------------------------------------------------------------- #
class ValidinProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="validin",
        phase="B",
        accepts=("domain", "url", "ip"),
        emits=("ip", "nameserver", "domain"),
        api_keys=("VALIDIN_API_KEY",),
        rate_limit=1.0,
        timeout=45.0,
        reliability=0.8,
        category="infrastructure",
        description="ValidIn historical DNS: A/AAAA/NS observations for domains and IPs",
        homepage="https://www.validin.com/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("VALIDIN_API_KEY not configured")
            return ctx.result
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        indicator_type = ctx.indicator.type
        if indicator_type in ("domain", "url"):
            domain = safe_domain(ctx.indicator.normalized)
            if not domain and indicator_type == "url":
                from phishtrace.providers._util import url_host
                domain = safe_domain(url_host(ctx.indicator.normalized))
            if not domain:
                ctx.partial("validin needs a domain or URL indicator")
                return ctx.result
            url = f"https://app.validin.com/api/axon/domain/dns/history/{domain}"
            params = {"wildcard": "true", "limit": 1000, "exclude_nx": "true", "time_format": "iso"}
            cache_key = f"validin:dom:{domain}"
        elif indicator_type == "ip":
            ip = safe_ip(ctx.indicator.normalized)
            if not ip:
                ctx.partial("validin needs a valid IP indicator")
                return ctx.result
            url = f"https://app.validin.com/api/axon/ip/dns/history/{ip}"
            params = {"limit": 1000, "time_format": "iso"}
            cache_key = f"validin:ip:{ip}"
        else:
            ctx.partial(f"validin does not accept {indicator_type} indicators")
            return ctx.result
        res = await ctx.http.get_json(
            url, params=params, headers=headers,
            timeout=45.0, max_bytes=4_000_000,
            cache_key=cache_key, cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"validin unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        pairs = _dns_records_from_validin(data)
        if not pairs:
            ctx.partial("validin returned no DNS records")
            return ctx.result
        emitted = 0
        for record_type, row in pairs[:400]:
            value = text(row.get("value"))
            if not value or record_type == "NX":
                continue
            seen = _observed(row)
            if record_type in ("A", "AAAA"):
                ip_value = safe_ip(value)
                if not ip_value:
                    continue
                ctx.emit("ip", ip_value, "resolves-to",
                         SelectorStrength.MEDIUM if record_type == "A" else SelectorStrength.WEAK,
                         evidence_id=res.evidence_id, tags=["validin"], observed_at=seen,
                         meta={"record_type": record_type})
                emitted += 1
            elif record_type in ("NS", "NS_FOR"):
                ns = safe_domain(value)
                if ns:
                    ctx.emit("nameserver", ns, "nameserver", SelectorStrength.WEAK,
                             evidence_id=res.evidence_id, tags=["validin"], observed_at=seen)
                    emitted += 1
            elif record_type == "WAYWARD_NS":
                wayward = safe_domain(value)
                if wayward and wayward != (data.get("query_key") or ""):
                    ctx.emit("domain", wayward, "wayward-nameserver", SelectorStrength.WEAK,
                             evidence_id=res.evidence_id, tags=["validin", "pnp"], context_only=True,
                             note="Domain sharing a nameserver; common misconfiguration signal")
                    emitted += 1
        ctx.event(
            ctx.now(), kind="historical-dns",
            label=f"ValidIn: {as_int(data.get('records_returned'), len(pairs))} historical DNS observations",
            detail="types=" + ",".join(sorted({rtype for rtype, _ in pairs})),
            evidence_id=res.evidence_id, precision="day",
            indicator_value=ctx.indicator.normalized,
            meta={"types": sorted({rtype for rtype, _ in pairs}), "limited": bool(data.get("limited"))},
        )
        if not emitted:
            ctx.result.notes.append("validin: no usable A/AAAA/NS records in payload")
        return ctx.result


# --------------------------------------------------------------------------- #
# SilentPush
# --------------------------------------------------------------------------- #
class SilentPushProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="silentpush",
        phase="B",
        accepts=("domain", "url", "ip"),
        emits=("ip", "asn", "email"),
        api_keys=("SILENTPUSH_API_KEY",),
        rate_limit=1.0,
        timeout=30.0,
        reliability=0.8,
        category="infrastructure",
        description="SilentPush enrichment: risk scores, ASN, WHOIS context for domains and IPs",
        homepage="https://www.silentpush.com/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("SILENTPUSH_API_KEY not configured")
            return ctx.result
        headers = {"X-API-KEY": key, "Accept": "application/json"}
        if ctx.indicator.type == "ip":
            ip = safe_ip(ctx.indicator.normalized)
            if not ip:
                ctx.partial("silentpush needs a valid IP indicator")
                return ctx.result
            url = f"https://api.silentpush.com/api/v1/merge-api/explore/enrich/ipv4/{ip}"
            subject = ip
        else:
            domain = safe_domain(ctx.indicator.normalized)
            if not domain and ctx.indicator.type == "url":
                from phishtrace.providers._util import url_host
                domain = safe_domain(url_host(ctx.indicator.normalized))
            if not domain:
                ctx.partial("silentpush needs a domain or URL indicator")
                return ctx.result
            url = f"https://api.silentpush.com/api/v1/merge-api/explore/enrich/domain/{domain}"
            subject = domain
        res = await ctx.http.get_json(
            url, headers=headers, timeout=30.0, max_bytes=2_000_000,
            cache_key=f"silentpush:{subject}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"silentpush unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        payload = first(data, "data", default={})
        if not isinstance(payload, dict):
            payload = {}
        if not payload:
            ctx.partial("silentpush returned no enrichment data")
            return ctx.result
        score = None
        for score_key in ("sp_risk_score", "risk_score", "riskscore", "sp_risk_score_explain"):
            if payload.get(score_key) not in (None, "", []):
                score = payload.get(score_key)
                break
        asn = _asn_label(first(payload, "asn", default=""))
        whois = first(payload, "whois", default={})
        if not isinstance(whois, dict):
            whois = {}
        created = parse_date(first(whois, "create_date", "created_date", "created", "age"))
        registrar = text(first(whois, "registrar"))
        ctx.event(
            created, kind="reputation-check",
            label=f"SilentPush: {subject}" + (f" risk score {score}" if score is not None else ""),
            detail=f"asn={asn or 'n/a'} registrar={registrar or 'n/a'}",
            evidence_id=res.evidence_id, precision="day", indicator_value=subject,
            meta={"risk_score": score, "asn": asn, "registrar": registrar,
                  "keys": sorted(str(key) for key in payload)[:20]},
        )
        if asn:
            ctx.emit("asn", asn, "hosted-in", SelectorStrength.WEAK,
                     evidence_id=res.evidence_id, tags=["silentpush"])
        for ip_value in as_list(first(payload, "ips", default=[]))[:10]:
            ip_value = safe_ip(ip_value)
            if ip_value:
                ctx.emit("ip", ip_value, "resolves-to", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["silentpush"])
        for email in as_list(first(whois, "email", "emails", default=[]))[:10]:
            value = text(email).lower()
            if "@" in value and len(value) < 320:
                ctx.emit(
                    "email", value, "registrant-contact", SelectorStrength.WEAK,
                    evidence_id=res.evidence_id, tags=["silentpush", "registrant"],
                    context_only=True, note="WHOIS contact address; often a privacy proxy",
                )
        return ctx.result


# --------------------------------------------------------------------------- #
# Netlas
# --------------------------------------------------------------------------- #
class NetlasProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="netlas",
        phase="B",
        accepts=("domain", "url", "ip"),
        emits=("ip", "nameserver", "domain"),
        api_keys=("NETLAS_API_KEY",),
        rate_limit=1.0,
        timeout=45.0,
        reliability=0.75,
        category="infrastructure",
        description="Netlas internet-asset search: DNS records and host responses for domains and IPs",
        homepage="https://netlas.io/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("NETLAS_API_KEY not configured")
            return ctx.result
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        if ctx.indicator.type == "ip":
            ip = safe_ip(ctx.indicator.normalized)
            if not ip:
                ctx.partial("netlas needs a valid IP indicator")
                return ctx.result
            url = "https://app.netlas.io/api/responses/"
            params = {"q": f"ip:{ip}", "source_type": "include", "start": 0, "fields": "domain,port"}
            subject = ip
        else:
            domain = safe_domain(ctx.indicator.normalized)
            if not domain and ctx.indicator.type == "url":
                from phishtrace.providers._util import url_host
                domain = safe_domain(url_host(ctx.indicator.normalized))
            if not domain:
                ctx.partial("netlas needs a domain or URL indicator")
                return ctx.result
            url = "https://app.netlas.io/api/domains/"
            params = {"q": f"domain:{domain}", "source_type": "include", "start": 0,
                      "fields": "domain,a,aaaa,ns,mx"}
            subject = domain
        res = await ctx.http.get_json(
            url, params=params, headers=headers,
            timeout=45.0, max_bytes=4_000_000,
            cache_key=f"netlas:{subject}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"netlas unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        items = as_list(data.get("items"))
        if not items:
            ctx.partial("netlas returned no items for this indicator")
            return ctx.result
        emitted = 0
        for item in items[:60]:
            record = first(item, "data", default={})
            if not isinstance(record, dict):
                continue
            if ctx.indicator.type == "ip":
                host = safe_domain(record.get("domain"))
                if host:
                    ctx.emit("domain", host, "hosted-on", SelectorStrength.WEAK,
                             evidence_id=res.evidence_id, tags=["netlas"], context_only=True,
                             note="Domain observed on this IP by Netlas")
                    emitted += 1
                continue
            fqdn = safe_domain(record.get("domain"))
            for ip_value in as_list(record.get("a"))[:20] + as_list(record.get("aaaa"))[:20]:
                ip_value = safe_ip(ip_value)
                if ip_value:
                    ctx.emit("ip", ip_value, "resolves-to", SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, tags=["netlas"])
                    emitted += 1
            for ns in as_list(record.get("ns"))[:20]:
                ns_value = safe_domain(ns)
                if ns_value:
                    ctx.emit("nameserver", ns_value, "nameserver", SelectorStrength.WEAK,
                             evidence_id=res.evidence_id, tags=["netlas"])
                    emitted += 1
            if fqdn and fqdn != subject:
                ctx.emit("domain", fqdn, "subdomain-observed", SelectorStrength.WEAK,
                         evidence_id=res.evidence_id, tags=["netlas", "subdomain"], context_only=True)
                emitted += 1
        ctx.event(
            ctx.now(), kind="host-response-survey",
            label=f"Netlas: {len(items)} asset records for {subject}",
            detail=f"emitted={emitted}",
            evidence_id=res.evidence_id, precision="day", indicator_value=subject,
            meta={"items": len(items)},
        )
        return ctx.result


# --------------------------------------------------------------------------- #
# CriminalIP
# --------------------------------------------------------------------------- #
class CriminalIpProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="criminalip",
        phase="B",
        accepts=("ip", "domain", "url"),
        emits=("ip", "domain", "url"),
        api_keys=("CRIMINALIP_API_KEY",),
        rate_limit=0.5,
        timeout=45.0,
        reliability=0.75,
        category="reputation",
        description="CriminalIP asset reports: risk scores, open ports, connected domains",
        homepage="https://www.criminalip.io/",
        cache_ttl=3600.0,
    )

    def _headers(self, ctx) -> dict:
        return {"x-api-key": self.key(ctx.config), "Accept": "application/json"}

    async def run(self, ctx):
        if not self.key(ctx.config):
            ctx.partial("CRIMINALIP_API_KEY not configured")
            return ctx.result
        if ctx.indicator.type == "ip":
            return await self._run_ip(ctx)
        return await self._run_domain(ctx)

    async def _run_ip(self, ctx):
        ip = safe_ip(ctx.indicator.normalized)
        if not ip:
            ctx.partial("criminalip needs a valid IP indicator")
            return ctx.result
        res = await ctx.http.get_json(
            "https://api.criminalip.io/v1/asset/ip/report",
            params={"ip": ip, "full": "false"}, headers=self._headers(ctx),
            timeout=45.0, max_bytes=4_000_000,
            cache_key=f"criminalip:ip:{ip}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"criminalip unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        score = first(data, "score", default={})
        if not isinstance(score, dict):
            score = {}
        inbound = text(score.get("inbound")) or "unknown"
        outbound = text(score.get("outbound")) or "unknown"
        issues = first(data, "issues", default={})
        flags = sorted(key for key, value in (issues or {}).items() if value is True) if isinstance(issues, dict) else []
        ctx.event(
            ctx.now(), kind="reputation-check",
            label=f"CriminalIP: inbound {inbound} / outbound {outbound}",
            detail=", ".join(flags) or "no issue flags",
            evidence_id=res.evidence_id, precision="day", indicator_value=ip,
            meta={"inbound": inbound, "outbound": outbound, "issues": flags},
        )
        ports = first(data, "port", default={})
        for row in as_list(first(ports, "data", default=[]))[:30]:
            if isinstance(row, dict):
                port = as_int(row.get("open_port_no"), 0)
                if port:
                    ctx.emit("port", str(port), "open-port", SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, tags=["criminalip"])
        connected = first(data, "domain", default={})
        for row in as_list(first(connected, "data", default=[]))[:20]:
            if isinstance(row, dict):
                domain = safe_domain(row.get("domain"))
                if domain:
                    ctx.emit("domain", domain, "connected-domain", SelectorStrength.WEAK,
                             evidence_id=res.evidence_id, tags=["criminalip"], context_only=True,
                             note="Domain observed on this IP by CriminalIP")
        return ctx.result

    async def _run_domain(self, ctx):
        domain = safe_domain(ctx.indicator.normalized)
        if not domain and ctx.indicator.type == "url":
            from phishtrace.providers._util import url_host
            domain = safe_domain(url_host(ctx.indicator.normalized))
        if not domain:
            ctx.partial("criminalip needs a domain or URL indicator")
            return ctx.result
        res = await ctx.http.get_json(
            "https://api.criminalip.io/v1/domain/reports",
            params={"query": domain, "offset": 0}, headers=self._headers(ctx),
            timeout=45.0, max_bytes=4_000_000,
            cache_key=f"criminalip:dom:{domain}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"criminalip unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        inner = first(data, "data", default={})
        reports = as_list(first(inner, "reports", default=[])) if isinstance(inner, dict) else []
        if not reports:
            ctx.partial("criminalip returned no domain report")
            return ctx.result
        report = reports[0] if isinstance(reports[0], dict) else {}
        score = text(report.get("score")) or "unknown"
        registered = parse_date(report.get("reg_dtime"))
        ctx.event(
            registered, kind="reputation-check",
            label=f"CriminalIP: {domain} scored {score}",
            detail=f"scan_id={text(report.get('scan_id'))} issues={','.join(as_list(report.get('issue'))[:8])}",
            evidence_id=res.evidence_id, precision="day", indicator_value=domain,
            meta={"score": score, "jarm": text(report.get("jarm")),
                  "scan_id": text(report.get("scan_id")),
                  "title": text(report.get("title"))},
        )
        for link in as_list(report.get("url"))[:10]:
            value = text(link)
            if value:
                ctx.emit("url", value, "observed-url", SelectorStrength.WEAK,
                         evidence_id=res.evidence_id, tags=["criminalip"], context_only=True)
        return ctx.result


# --------------------------------------------------------------------------- #
# GreyNoise RIOT (reuses GREYNOISE_API_KEY)
# --------------------------------------------------------------------------- #
class GreyNoiseRiotProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="greynoise_ri",
        phase="B",
        accepts=("ip",),
        emits=(),
        api_keys=("GREYNOISE_API_KEY",),
        rate_limit=0.5,
        timeout=30.0,
        reliability=0.8,
        category="reputation",
        description="GreyNoise RIOT v2: is this IP a known benign common business service",
        homepage="https://www.greynoise.io/",
        cache_ttl=86400.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("GREYNOISE_API_KEY not configured")
            return ctx.result
        ip = safe_ip(ctx.indicator.normalized)
        if not ip:
            ctx.partial("greynoise_ri needs an IP address")
            return ctx.result
        res = await ctx.http.get_json(
            f"https://api.greynoise.io/v2/riot/{ip}",
            headers={"key": key, "Accept": "application/json"},
            timeout=30.0, max_bytes=1_000_000,
            cache_key=f"greynoise_riot:{ip}", cache_ttl=86400.0,
        )
        if not res.ok:
            if res.status == 404:
                ctx.result.notes.append("greynoise_ri: IP is not in the RIOT data set")
                return ctx.result
            ctx.partial(f"greynoise_ri unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        if not bool(data.get("riot")):
            ctx.result.notes.append("greynoise_ri: IP is not in the RIOT data set")
            return ctx.result
        name = text(first(data, "name"))
        classification = text(data.get("classification")) or "benign"
        owners = [text(row) for row in as_list(first(data, "common_owners", default=[]))[:10] if text(row)]
        ctx.event(
            parse_date(data.get("last_updated")), kind="reputation-check",
            label=f"GreyNoise RIOT: known benign service {name or ip}",
            detail=f"classification={classification} owners={','.join(owners)}",
            evidence_id=res.evidence_id, precision="day", indicator_value=ip,
            meta={"classification": classification, "name": name,
                  "common_owners": owners, "last_updated": text(data.get("last_updated"))},
        )
        # A shared CDN or SaaS egress must never be treated as attacker infra.
        ctx.emit(
            "ip", ip, "known-benign-service", SelectorStrength.WEAK,
            evidence_id=res.evidence_id, tags=["greynoise", "riot", "stoplist"],
            context_only=True, meta={"service": name},
            note="GreyNoise RIOT: shared benign service; do not attribute",
        )
        return ctx.result
