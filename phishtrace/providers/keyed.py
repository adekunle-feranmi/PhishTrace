"""Providers that need an API key.

Every plugin here is inert until its key is present in the environment; the
registry then reports it as ``skipped`` with the missing variable name, which is
what the coverage section of a report shows.  Keys are preferred in headers; the
few vendors that authenticate through the query string (Shodan, WhoisXML) are
covered by ``redact_url``, so a key is never stored verbatim in evidence.

Parsers are deliberately defensive: vendor payloads change shape without notice
and one malformed record must not abort the pivot.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from phishtrace.models import SelectorStrength, parse_timestamp
from phishtrace.providers._util import (
    as_int, as_list, first, indicator_host, result_error, safe_domain, safe_ip, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta


def _asn_label(value: Any) -> str:
    """Normalize ``64500``, ``"64500"`` and ``"AS64500"`` to ``AS64500``."""
    raw = text(value).strip().upper()
    if raw.startswith("AS"):
        raw = raw[2:]
    digits = re.sub(r"\D", "", raw)
    return f"AS{digits}" if digits else ""


def _stats_text(stats: Any) -> str:
    if not isinstance(stats, dict):
        return ""
    parts = []
    for key in ("malicious", "suspicious", "harmless", "undetected", "timeout"):
        if key in stats:
            parts.append(f"{key}={as_int(stats.get(key))}")
    return " ".join(parts)


class _KeyedProvider(BaseProvider):
    """Small shared surface: the key comes from ``config.env``, never YAML."""

    key_names: tuple[str, ...] = ()

    def key(self, config) -> str | None:
        for name in self.key_names or tuple(self.meta.api_keys):
            value = config.api_key(name)
            if value:
                return value
        return None


# --------------------------------------------------------------------------- #
# VirusTotal
# --------------------------------------------------------------------------- #
class VirusTotalProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="virustotal",
        phase="B",
        accepts=("domain", "ip", "url", "file_hash", "cert_sha256"),
        emits=("ip", "asn", "domain", "url"),
        api_keys=("VIRUSTOTAL_API_KEY",),
        rate_limit=0.1,
        timeout=45.0,
        reliability=0.9,
        category="reputation",
        description="VirusTotal v3 file/URL/domain/IP reputation and DNS records",
        homepage="https://www.virustotal.com/",
        cache_ttl=3600.0,
    )

    _PATHS = {
        "domain": "domains",
        "ip": "ip_addresses",
        "url": "urls",
        "file_hash": "files",
        "cert_sha256": "files",
    }

    def _identifier(self, indicator) -> str:
        if indicator.type == "url":
            encoded = base64.urlsafe_b64encode(indicator.normalized.encode()).decode()
            return encoded.rstrip("=")
        return indicator.normalized

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("VIRUSTOTAL_API_KEY not configured")
            return ctx.result
        indicator = ctx.indicator
        path = self._PATHS.get(indicator.type)
        if not path:
            ctx.partial(f"virustotal does not handle {indicator.type}")
            return ctx.result
        ident = self._identifier(indicator)
        res = await ctx.http.get_json(
            f"https://www.virustotal.com/api/v3/{path}/{ident}",
            headers={"x-apikey": key, "Accept": "application/json"},
            timeout=45.0, max_bytes=4_000_000,
            cache_key=f"vt:{indicator.type}:{ident}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"virustotal unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        body = data.get("data")
        attributes = body.get("attributes") if isinstance(body, dict) else None
        if not isinstance(attributes, dict) or not attributes:
            ctx.partial("virustotal response had no attributes")
            return ctx.result

        stats = attributes.get("last_analysis_stats")
        when = parse_timestamp(attributes.get("last_analysis_date") or attributes.get("last_modification_date"))
        malicious = as_int(first(stats, "malicious", default=0)) if isinstance(stats, dict) else 0
        suspicious = as_int(first(stats, "suspicious", default=0)) if isinstance(stats, dict) else 0
        link = f"https://www.virustotal.com/gui/{'url' if indicator.type == 'url' else path}/{ident}"
        ctx.event(
            when, kind="reputation-check",
            label=f"VirusTotal: {malicious} malicious / {suspicious} suspicious engine(s)",
            detail=_stats_text(stats) or "no analysis stats",
            url=link, evidence_id=res.evidence_id, precision="hour",
            indicator_value=indicator.normalized,
            meta={"malicious": malicious, "suspicious": suspicious,
                  "reputation": as_int(attributes.get("reputation")),
                  "tags": [text(tag) for tag in as_list(attributes.get("tags"))][:20]},
        )

        for record in as_list(attributes.get("last_dns_records"))[:40]:
            if not isinstance(record, dict):
                continue
            kind = text(record.get("type")).upper()
            value = text(record.get("value"))
            if kind in {"A", "AAAA"}:
                ip = safe_ip(value)
                if ip:
                    ctx.emit("ip", ip, "resolves-to", SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, tags=["virustotal"],
                             meta={"record": kind})
            elif kind in {"NS", "CNAME"}:
                host = safe_domain(value)
                if host:
                    ctx.emit("domain", host, "dns-record" if kind == "CNAME" else "nameserver",
                             SelectorStrength.MEDIUM, evidence_id=res.evidence_id, tags=["virustotal"])
        for record in as_list(attributes.get("resolutions"))[:40]:
            if isinstance(record, dict):
                ip = safe_ip(record.get("ip_address"))
                if ip:
                    ctx.emit(
                        "ip", ip, "historical-resolution", SelectorStrength.MEDIUM,
                        evidence_id=res.evidence_id,
                        observed_at=parse_timestamp(record.get("date")),
                        tags=["virustotal", "historical"],
                    )
        asn = _asn_label(attributes.get("asn"))
        owner = text(attributes.get("as_owner"))
        if asn:
            ctx.emit(
                "asn", asn, "hosted-on", SelectorStrength.MEDIUM,
                evidence_id=res.evidence_id, tags=["virustotal"],
                meta={"as_owner": owner, "country": text(attributes.get("country"))},
            )
        for domain in as_list(attributes.get("subdomains"))[:50]:
            host = safe_domain(domain)
            if host:
                ctx.emit("domain", host, "subdomain", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["virustotal"])
        registrar = text(attributes.get("registrar"))
        if registrar:
            ctx.emit(
                "domain", indicator_host(indicator), "registered-with", SelectorStrength.WEAK,
                evidence_id=res.evidence_id, tags=["virustotal", "registrar"],
                meta={"registrar": registrar,
                      "created": text(attributes.get("creation_date")),
                      "expires": text(attributes.get("expiration_date"))},
                context_only=True,
            )
        return ctx.result


# --------------------------------------------------------------------------- #
# Shodan
# --------------------------------------------------------------------------- #
class ShodanProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="shodan",
        phase="B",
        accepts=("ip", "domain"),
        emits=("ip", "domain", "asn"),
        api_keys=("SHODAN_API_KEY",),
        rate_limit=0.2,
        timeout=45.0,
        reliability=0.85,
        category="attack-surface",
        description="Open ports, banners, hostnames and ASN from Shodan host lookup",
        homepage="https://www.shodan.io/",
        cache_ttl=3600.0,
    )

    async def _host(self, ctx, ip: str, key: str):
        return await ctx.http.get_json(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key, "minify": "true"},
            timeout=45.0, max_bytes=3_000_000,
            cache_key=f"shodan:{ip}", cache_ttl=3600.0,
        )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("SHODAN_API_KEY not configured")
            return ctx.result
        indicator = ctx.indicator
        targets: list[str] = []
        if indicator.type == "ip":
            targets = [indicator.normalized]
        else:
            host = indicator_host(indicator)
            resolved = await ctx.http.get_json(
                "https://api.shodan.io/dns/resolve",
                params={"hostnames": host, "key": key},
                timeout=30.0, max_bytes=200_000,
                cache_key=f"shodan-resolve:{host}", cache_ttl=1800.0,
            )
            if not resolved.ok:
                ctx.partial(f"shodan dns/resolve failed: {result_error(resolved)}")
                return ctx.result
            payload = resolved.data if isinstance(resolved.data, dict) else {}
            ip = safe_ip(payload.get(host))
            if ip:
                targets = [ip]
                ctx.emit("ip", ip, "resolves-to", SelectorStrength.MEDIUM,
                         evidence_id=resolved.evidence_id, tags=["shodan"],
                         observed_at=ctx.now())
            else:
                ctx.partial("shodan could not resolve the domain")
                return ctx.result

        for ip in targets[:3]:
            res = await self._host(ctx, ip, key)
            if not res.ok:
                ctx.partial(f"shodan host lookup failed for {ip}: {result_error(res)}")
                continue
            data = res.data if isinstance(res.data, dict) else {}
            ports = [as_int(port) for port in as_list(data.get("ports"))][:50]
            if not ports and data.get("port"):
                ports = [as_int(data.get("port"))]
            org = text(data.get("org") or data.get("isp"))
            asn = _asn_label(data.get("asn"))
            country = text(data.get("country_code") or data.get("country_name"))
            ctx.event(
                parse_timestamp(data.get("last_update") or data.get("timestamp")),
                kind="service-exposure",
                label=f"Shodan: {len(ports)} open port(s) on {ip}" + (f" ({org})" if org else ""),
                detail="ports=" + ",".join(str(port) for port in ports[:20]) + (f" os={text(data.get('os'))}" if data.get("os") else ""),
                evidence_id=res.evidence_id, precision="hour", indicator_value=ip,
                meta={"ports": ports, "org": org, "country": country,
                      "hostnames": [text(h) for h in as_list(data.get("hostnames"))][:20],
                      "vulns": sorted(str(v) for v in (data.get("vulns") or {}))[:30]},
            )
            if asn:
                ctx.emit("asn", asn, "hosted-on", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["shodan"],
                         meta={"org": org, "country": country})
            for hostname in as_list(data.get("hostnames"))[:20]:
                host = safe_domain(hostname)
                if host:
                    ctx.emit("domain", host, "reverse-dns-hostname", SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, tags=["shodan"])
            for domain in as_list(data.get("domains"))[:10]:
                host = safe_domain(domain)
                if host:
                    ctx.emit("domain", host, "hosted-domain", SelectorStrength.WEAK,
                             evidence_id=res.evidence_id, tags=["shodan"], context_only=True)
        return ctx.result


# --------------------------------------------------------------------------- #
# Censys
# --------------------------------------------------------------------------- #
class CensysProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="censys",
        phase="B",
        accepts=("ip",),
        emits=("domain", "asn"),
        api_keys=("CENSYS_API_TOKEN",),
        rate_limit=0.1,
        timeout=45.0,
        reliability=0.85,
        category="attack-surface",
        description="Host service and certificate observations for an IP (Censys Platform asset lookup)",
        homepage="https://censys.com/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        # Censys retired the legacy Search API v2 on 2026-09-30, and the Platform
        # search endpoint needs a paid organization.  The per-asset lookup still
        # works on the free wallet with a Personal Access Token, so that is the
        # only call this provider makes.
        token = self.key(ctx.config)
        if not token:
            ctx.partial("CENSYS_API_TOKEN not configured")
            return ctx.result
        ip = safe_ip(ctx.indicator.normalized)
        if not ip:
            ctx.partial("censys needs an IP address")
            return ctx.result
        res = await ctx.http.get_json(
            f"https://api.platform.censys.io/v3/global/asset/host/{ip}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=45.0, max_bytes=3_000_000,
            cache_key=f"censys:{ip}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"censys unavailable: {result_error(res)}")
            return ctx.result
        payload = res.data if isinstance(res.data, dict) else {}
        result = first(payload, "result", default={})
        resource = first(result, "resource", default={}) if isinstance(result, dict) else {}
        if not isinstance(resource, dict) or not resource:
            ctx.partial("censys returned no host resource")
            return ctx.result
        services = [svc for svc in as_list(resource.get("services")) if isinstance(svc, dict)]
        ports = [port for port in (as_int(svc.get("port")) for svc in services[:50]) if port]
        scan_times = [parse_timestamp(svc.get("scan_time")) for svc in services[:50]]
        last_seen = max((stamp for stamp in scan_times if stamp), default=None)
        asn = first(resource, "autonomous_system", default={})
        location = first(resource, "location", default={})
        asn_number = first(asn, "asn") if isinstance(asn, dict) else None
        org = text(first(asn, "name", "description")) if isinstance(asn, dict) else ""
        country = text(first(location, "country_code")) if isinstance(location, dict) else ""
        ctx.event(
            last_seen, kind="service-exposure",
            label=f"Censys: {len(ports)} observed service(s) on {ip}",
            detail="ports=" + ",".join(str(port) for port in ports[:20]),
            evidence_id=res.evidence_id, precision="hour", indicator_value=ip,
            meta={"ports": ports, "service_count": as_int(resource.get("service_count")),
                  "labels": [text(v) for v in as_list(resource.get("labels"))][:10]},
        )
        asn_label = _asn_label(asn_number)
        if asn_label:
            asn_country = text(first(asn, "country_code", "country")) if isinstance(asn, dict) else ""
            ctx.emit("asn", asn_label, "hosted-on", SelectorStrength.MEDIUM,
                     evidence_id=res.evidence_id, tags=["censys"],
                     meta={"org": org, "country": asn_country or country})
        for service in services[:50]:
            cert = first(service, "cert", default={})
            if not isinstance(cert, dict):
                continue
            for name in as_list(first(cert, "names", default=[]))[:20]:
                host = safe_domain(str(name).lstrip("*."))
                if host:
                    ctx.emit("domain", host, "certificate-san", SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, tags=["censys", "ct"])
        return ctx.result


# --------------------------------------------------------------------------- #
# SecurityTrails
# --------------------------------------------------------------------------- #
class SecurityTrailsProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="securitytrails",
        phase="B",
        accepts=("domain",),
        emits=("domain", "ip", "nameserver"),
        api_keys=("SECURITYTRAILS_API_KEY",),
        rate_limit=0.1,
        timeout=45.0,
        reliability=0.85,
        category="dns",
        description="Current DNS, subdomains and WHOIS age from SecurityTrails",
        homepage="https://securitytrails.com/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("SECURITYTRAILS_API_KEY not configured")
            return ctx.result
        domain = safe_domain(ctx.indicator.normalized)
        if not domain:
            ctx.partial("securitytrails needs a domain")
            return ctx.result
        res = await ctx.http.get_json(
            f"https://api.securitytrails.com/v1/domain/{domain}",
            headers={"APIKEY": key, "Accept": "application/json"},
            timeout=45.0, max_bytes=3_000_000,
            cache_key=f"st:{domain}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"securitytrails unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        current = first(data, "current_dns", default={})
        if not isinstance(current, dict):
            current = {}
        for section, relation in (("a", "resolves-to"), ("aaaa", "resolves-to"), ("mx", "mail-exchanger")):
            block = current.get(section)
            values = as_list(first(block, "values", default=[])) if isinstance(block, dict) else []
            for row in values[:20]:
                if not isinstance(row, dict):
                    continue
                raw = text(row.get("ip") or row.get("hostname") or row.get("value"))
                ip = safe_ip(raw)
                if ip:
                    ctx.emit("ip", ip, relation, SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, tags=["securitytrails", section])
                    continue
                host = safe_domain(raw)
                if host:
                    ctx.emit("domain", host, relation, SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, tags=["securitytrails", section])
        ns_block = current.get("ns")
        for row in as_list(first(ns_block, "values", default=[]))[:20] if isinstance(ns_block, dict) else []:
            host = safe_domain(row.get("nameserver") if isinstance(row, dict) else row)
            if host:
                ctx.emit("nameserver", host, "nameserver", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["securitytrails"])
        for sub in as_list(data.get("subdomains"))[:300]:
            label = text(sub)
            if label and "." not in label:
                ctx.emit("domain", f"{label}.{domain}", "subdomain", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["securitytrails"])
        whois = first(data, "whois", default={})
        if isinstance(whois, dict) and (whois.get("registrar") or whois.get("createdDate")):
            ctx.emit(
                "domain", domain, "registered-with", SelectorStrength.WEAK,
                evidence_id=res.evidence_id, tags=["securitytrails", "registrar"],
                meta={"registrar": text(whois.get("registrar")),
                      "created": text(whois.get("createdDate"))},
                context_only=True,
            )
        return ctx.result


# --------------------------------------------------------------------------- #
# AlienVault OTX
# --------------------------------------------------------------------------- #
class AlienVaultOTXProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="alienvault_otx",
        phase="B",
        accepts=("domain", "ip", "url", "file_hash"),
        emits=("domain", "ip", "url", "asn"),
        api_keys=("OTX_API_KEY",),
        rate_limit=0.2,
        timeout=45.0,
        reliability=0.8,
        category="threat-intel",
        description="AlienVault OTX pulses and passive DNS for an indicator",
        homepage="https://otx.alienvault.com/",
        cache_ttl=1800.0,
    )

    _SECTIONS = {"domain": "domain", "ip": "IPv4", "url": "url", "file_hash": "file"}

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("OTX_API_KEY not configured")
            return ctx.result
        indicator = ctx.indicator
        section = self._SECTIONS.get(indicator.type)
        if not section:
            ctx.partial(f"otx does not handle {indicator.type}")
            return ctx.result
        from urllib.parse import quote

        res = await ctx.http.get_json(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(indicator.normalized, safe='')}/general",
            headers={"X-OTX-API-KEY": key, "Accept": "application/json"},
            timeout=45.0, max_bytes=4_000_000,
            cache_key=f"otx:{section}:{indicator.normalized}", cache_ttl=1800.0,
        )
        if not res.ok:
            ctx.partial(f"otx unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        pulses = first(first(data, "pulse_info", default={}), "pulses", default=[])
        pulse_rows = [row for row in as_list(pulses) if isinstance(row, dict)]
        tags: set[str] = set()
        families: set[str] = set()
        for pulse in pulse_rows[:30]:
            for tag in as_list(pulse.get("tags"))[:20]:
                tags.add(text(tag).lower())
            for family in as_list(pulse.get("malware_families"))[:5]:
                families.add(text(family))
            if len(pulse_rows) <= 10:
                ctx.event(
                    parse_timestamp(pulse.get("created") or pulse.get("modified")),
                    kind="ti-pulse",
                    label=f"OTX pulse: {text(pulse.get('name'))[:120]}",
                    detail="adversary=" + text(pulse.get("adversary")) if pulse.get("adversary") else None,
                    url=f"https://otx.alienvault.com/pulse/{text(pulse.get('id'))}",
                    evidence_id=res.evidence_id, precision="day",
                    indicator_value=indicator.normalized,
                    meta={"tags": [text(tag) for tag in as_list(pulse.get("tags"))][:10]},
                )
        ctx.event(
            ctx.now(), kind="ti-coverage",
            label=f"OTX: {len(pulse_rows)} pulse(s) reference this indicator",
            detail=("tags=" + ",".join(sorted(tags)[:15])) if tags else None,
            evidence_id=res.evidence_id, precision="day", indicator_value=indicator.normalized,
            meta={"pulses": len(pulse_rows), "tags": sorted(tags)[:30],
                  "malware_families": sorted(families)[:10]},
        )
        for row in as_list(first(data, "passive_dns", default=[]))[:60]:
            if not isinstance(row, dict):
                continue
            ip = safe_ip(row.get("address"))
            host = safe_domain(row.get("hostname"))
            when = parse_timestamp(row.get("first") or row.get("last"))
            if ip:
                ctx.emit("ip", ip, "passive-dns", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, observed_at=when, tags=["otx", "passive-dns"])
            if host:
                ctx.emit("domain", host, "passive-dns", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, observed_at=when, tags=["otx", "passive-dns"])
        for row in as_list(first(data, "url_list", default=[]))[:40]:
            if isinstance(row, dict):
                url = text(row.get("url"))
                if url.startswith(("http://", "https://")):
                    ctx.emit("url", url, "url-observed", SelectorStrength.MEDIUM,
                             evidence_id=res.evidence_id, observed_at=parse_timestamp(row.get("date")),
                             tags=["otx"])
        return ctx.result


# --------------------------------------------------------------------------- #
# AbuseIPDB
# --------------------------------------------------------------------------- #
class AbuseIPDBProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="abuseipdb",
        phase="B",
        accepts=("ip",),
        emits=("domain",),
        api_keys=("ABUSEIPDB_API_KEY",),
        rate_limit=0.2,
        timeout=30.0,
        reliability=0.8,
        category="reputation",
        description="Abuse confidence, report volume and ISP for an IP from AbuseIPDB",
        homepage="https://www.abuseipdb.com/",
        cache_ttl=1800.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("ABUSEIPDB_API_KEY not configured")
            return ctx.result
        ip = safe_ip(ctx.indicator.normalized)
        if not ip:
            ctx.partial("abuseipdb needs an IP address")
            return ctx.result
        res = await ctx.http.get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90", "verbose": "false"},
            headers={"Key": key, "Accept": "application/json"},
            timeout=30.0, max_bytes=1_000_000,
            cache_key=f"abuseipdb:{ip}", cache_ttl=1800.0,
        )
        if not res.ok:
            ctx.partial(f"abuseipdb unavailable: {result_error(res)}")
            return ctx.result
        data = first(res.data if isinstance(res.data, dict) else {}, "data", default={})
        if not isinstance(data, dict):
            ctx.partial("abuseipdb response had no data object")
            return ctx.result
        score = as_int(data.get("abuseConfidenceScore"))
        reports = as_int(data.get("totalReports"))
        ctx.event(
            parse_timestamp(data.get("lastReportedAt")),
            kind="reputation-check",
            label=f"AbuseIPDB: abuse confidence {score}% across {reports} report(s)",
            detail=f"isp={text(data.get('isp'))} usage={text(data.get('usageType'))}",
            url=f"https://www.abuseipdb.com/check/{ip}",
            evidence_id=res.evidence_id, precision="hour", indicator_value=ip,
            meta={"abuse_confidence": score, "reports": reports,
                  "country": text(data.get("countryCode")),
                  "isp": text(data.get("isp")), "usage_type": text(data.get("usageType")),
                  "is_public": data.get("isPublic"), "domain": text(data.get("domain"))},
        )
        domain = safe_domain(data.get("domain"))
        if domain:
            ctx.emit(
                "domain", domain, "hosted-on", SelectorStrength.WEAK,
                evidence_id=res.evidence_id, tags=["abuseipdb"], context_only=True,
                meta={"isp": text(data.get("isp"))},
            )
        for hostname in as_list(data.get("hostnames"))[:10]:
            host = safe_domain(hostname)
            if host:
                ctx.emit("domain", host, "reverse-dns-hostname", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["abuseipdb"])
        return ctx.result


# --------------------------------------------------------------------------- #
# GreyNoise
# --------------------------------------------------------------------------- #
class GreyNoiseProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="greynoise",
        phase="B",
        accepts=("ip",),
        emits=(),
        api_keys=("GREYNOISE_API_KEY",),
        rate_limit=0.3,
        timeout=30.0,
        reliability=0.75,
        category="reputation",
        description="Internet-noise classification and RIOT benign-service flag from GreyNoise",
        homepage="https://www.greynoise.io/",
        cache_ttl=1800.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("GREYNOISE_API_KEY not configured")
            return ctx.result
        ip = safe_ip(ctx.indicator.normalized)
        if not ip:
            ctx.partial("greynoise needs an IP address")
            return ctx.result
        res = await ctx.http.get_json(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": key, "Accept": "application/json"},
            timeout=30.0, max_bytes=1_000_000,
            cache_key=f"greynoise:{ip}", cache_ttl=1800.0,
        )
        if not res.ok:
            if res.status == 404:
                # The community endpoint answers 404 for any IP it has never
                # observed; that is a "no record" answer, not a broken key.
                ctx.result.notes.append("greynoise: no observation record for this IP")
                return ctx.result
            ctx.partial(f"greynoise unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        classification = text(data.get("classification")) or "unknown"
        riot = bool(data.get("riot"))
        ctx.event(
            parse_timestamp(data.get("last_seen")),
            kind="reputation-check",
            label=f"GreyNoise: {classification}" + (" (RIOT: known benign service)" if riot else ""),
            detail=f"name={text(data.get('name'))} link={text(data.get('link'))}",
            evidence_id=res.evidence_id, precision="hour", indicator_value=ip,
            meta={"classification": classification, "noise": bool(data.get("noise")),
                  "riot": riot, "name": text(data.get("name")),
                  "last_seen": text(data.get("last_seen"))},
        )
        if riot:
            # A shared CDN or scanner must never be treated as attacker infra.
            ctx.emit(
                "ip", ip, "known-benign-service", SelectorStrength.WEAK,
                evidence_id=res.evidence_id, tags=["greynoise", "riot", "stoplist"],
                context_only=True,
                meta={"service": text(data.get("name"))},
                note="GreyNoise RIOT: shared benign service; do not attribute",
            )
        return ctx.result


# --------------------------------------------------------------------------- #
# Hybrid Analysis
# --------------------------------------------------------------------------- #
class HybridAnalysisProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="hybrid_analysis",
        phase="B",
        accepts=("file_hash", "domain", "url", "ip"),
        emits=("file_hash", "domain", "url"),
        api_keys=("HYBRID_ANALYSIS_API_KEY",),
        rate_limit=0.1,
        timeout=45.0,
        reliability=0.8,
        category="sandbox",
        description="Sandbox reports and related samples from Hybrid Analysis",
        homepage="https://www.hybrid-analysis.com/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("HYBRID_ANALYSIS_API_KEY not configured")
            return ctx.result
        indicator = ctx.indicator
        headers = {"api-key": key, "Accept": "application/json",
                   "User-Agent": "Falcon Sandbox"}
        if indicator.type == "file_hash":
            # POST /search/hash was retired in API 2.35; the GET form is current.
            res = await ctx.http.request(
                "GET", "https://hybrid-analysis.com/api/v2/search/hash",
                params={"hash": indicator.normalized}, headers=headers,
                expect_json=True, timeout=45.0, max_bytes=4_000_000,
                cache_key=f"ha:hash:{indicator.normalized}", cache_ttl=3600.0,
            )
        else:
            res = await ctx.http.request(
                "POST", "https://www.hybrid-analysis.com/api/v2/search/terms",
                data={"domain": indicator.normalized} if indicator.type == "domain" else {"url": indicator.normalized},
                headers=headers, expect_json=True, timeout=45.0, max_bytes=4_000_000,
                cache_key=f"ha:term:{indicator.normalized}", cache_ttl=3600.0,
            )
        if not res.ok:
            if res.status == 404:
                ctx.result.notes.append("hybrid-analysis: no reports for this indicator")
                return ctx.result
            ctx.partial(f"hybrid-analysis unavailable: {result_error(res)}")
            return ctx.result
        payload = res.data if isinstance(res.data, dict) else {}
        if isinstance(res.data, list):
            rows = res.data
        elif isinstance(payload.get("reports"), list):
            rows = payload["reports"]          # GET /search/hash shape
        else:
            rows = as_list(first(payload, "result", default=[]))
        samples = [row for row in rows if isinstance(row, dict)]
        if not samples:
            ctx.partial("hybrid-analysis returned no reports")
            return ctx.result
        best = max(samples, key=lambda row: as_int(row.get("threat_score")))
        ctx.event(
            parse_timestamp(best.get("analysis_start_time") or best.get("last_file_scanned_at")),
            kind="sandbox-report",
            label=f"Hybrid Analysis: verdict {text(best.get('verdict')) or 'unknown'} "
                  f"(threat score {as_int(best.get('threat_score'))})",
            detail=f"family={text(best.get('vx_family'))} type={text(best.get('type'))}",
            url=f"https://www.hybrid-analysis.com/search?query={indicator.normalized}",
            evidence_id=res.evidence_id, precision="hour", indicator_value=indicator.normalized,
            meta={"samples": len(samples), "verdict": text(best.get("verdict")),
                  "threat_score": as_int(best.get("threat_score")),
                  "family": text(best.get("vx_family")),
                  "sha256": text(best.get("sha256"))},
        )
        for row in samples[:15]:
            sha = text(row.get("sha256")).lower()
            if len(sha) == 64 and all(ch in "0123456789abcdef" for ch in sha):
                ctx.emit(
                    "file_hash", sha, "sample-observed", SelectorStrength.MEDIUM,
                    evidence_id=res.evidence_id,
                    observed_at=parse_timestamp(row.get("analysis_start_time")),
                    tags=["hybrid-analysis"],
                    meta={"threat_score": as_int(row.get("threat_score")),
                          "family": text(row.get("vx_family"))},
                )
        return ctx.result


# --------------------------------------------------------------------------- #
# MalwareBazaar
# --------------------------------------------------------------------------- #
class MalwareBazaarProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="malwarebazaar",
        phase="B",
        accepts=("file_hash",),
        emits=("file_hash", "domain", "url"),
        api_keys=(),
        rate_limit=0.5,
        timeout=30.0,
        reliability=0.8,
        category="malware",
        description="Sample metadata and delivery URLs from abuse.ch MalwareBazaar (Auth-Key optional)",
        homepage="https://bazaar.abuse.ch/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        indicator = ctx.indicator
        if indicator.type != "file_hash":
            ctx.partial("malwarebazaar needs a file hash")
            return ctx.result
        key = ctx.config.api_key("MALWAREBAZAAR_API_KEY")
        headers = {"Accept": "application/json"}
        if key:
            headers["Auth-Key"] = key
        res = await ctx.http.request(
            "POST", "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": indicator.normalized},
            headers=headers, expect_json=True, timeout=30.0, max_bytes=2_000_000,
            cache_key=f"mb:{indicator.normalized}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"malwarebazaar unavailable: {result_error(res)}")
            return ctx.result
        data = res.data if isinstance(res.data, dict) else {}
        status = text(data.get("query_status")).lower()
        if status not in {"ok", "hash_not_found"}:
            ctx.partial(f"malwarebazaar query status: {status or 'unknown'}")
            return ctx.result
        rows = [row for row in as_list(data.get("data")) if isinstance(row, dict)]
        if not rows:
            ctx.partial("malwarebazaar has no record of this hash")
            return ctx.result
        row = rows[0]
        ctx.event(
            parse_timestamp(row.get("first_seen") or row.get("last_seen")),
            kind="malware-sample",
            label=f"MalwareBazaar: {text(row.get('signature')) or 'unclassified sample'}",
            detail=f"type={text(row.get('file_type_mime'))} reporter={text(row.get('reporter'))}",
            url=f"https://bazaar.abuse.ch/sample/{indicator.normalized}/",
            evidence_id=res.evidence_id, precision="hour", indicator_value=indicator.normalized,
            meta={"tags": [text(tag) for tag in as_list(row.get("tags"))][:20],
                  "delivery_method": text(row.get("delivery_method")),
                  "file_name": text(row.get("file_name")),
                  "imphash": text(row.get("imphash"))},
        )
        for tag in as_list(row.get("tags"))[:20]:
            value = safe_domain(str(tag))
            if value and "." in value:
                ctx.emit("domain", value, "sample-tag", SelectorStrength.WEAK,
                         evidence_id=res.evidence_id, tags=["malwarebazaar"], context_only=True)
        return ctx.result


# --------------------------------------------------------------------------- #
# WhoisXML
# --------------------------------------------------------------------------- #
class WhoisXmlProvider(_KeyedProvider):
    meta = ProviderMeta(
        name="whoisxml",
        phase="B",
        accepts=("domain",),
        emits=("domain", "nameserver", "email"),
        api_keys=("WHOISXML_API_KEY",),
        rate_limit=0.2,
        timeout=30.0,
        reliability=0.85,
        category="registration",
        description="WHOIS record, registrant country and name servers from WhoisXML API",
        homepage="https://whoisxmlapi.com/",
        cache_ttl=86400.0,
    )

    async def run(self, ctx):
        key = self.key(ctx.config)
        if not key:
            ctx.partial("WHOISXML_API_KEY not configured")
            return ctx.result
        domain = safe_domain(ctx.indicator.normalized)
        if not domain:
            ctx.partial("whoisxml needs a domain")
            return ctx.result
        res = await ctx.http.get_json(
            "https://www.whoisxmlapi.com/whoisserver/WhoisService",
            params={"apiKey": key, "domainName": domain, "outputFormat": "JSON"},
            timeout=30.0, max_bytes=2_000_000,
            cache_key=f"whoisxml:{domain}", cache_ttl=86400.0,
        )
        if not res.ok:
            ctx.partial(f"whoisxml unavailable: {result_error(res)}")
            return ctx.result
        record = first(res.data if isinstance(res.data, dict) else {}, "WhoisRecord", default={})
        if not isinstance(record, dict) or not record:
            ctx.partial("whoisxml returned no WhoisRecord")
            return ctx.result
        registry = record.get("registryData") if isinstance(record.get("registryData"), dict) else {}
        created = parse_timestamp(
            record.get("createdDate") or registry.get("createdDate") or registry.get("registrationTime")
        )
        registrant = record.get("registrant") if isinstance(record.get("registrant"), dict) else {}
        ctx.event(
            created, kind="domain-registered",
            label=f"WHOIS: {domain} created",
            detail=f"registrar={text(record.get('registrarName'))} "
                   f"country={text(registrant.get('country'))}",
            evidence_id=res.evidence_id, precision="day", indicator_value=domain,
            meta={"registrar": text(record.get("registrarName")),
                  "created": text(record.get("createdDate")),
                  "expires": text(record.get("expiresDate")),
                  "updated": text(record.get("updatedDate")),
                  "registrant_country": text(registrant.get("country")),
                  "registrant_org": text(registrant.get("organization")),
                  "domain_age_days": as_int(record.get("estimatedDomainAge"))},
        )
        nameservers = first(record, "nameServers", default={})
        for host in as_list(first(nameservers, "hostNames", default=[]))[:20]:
            value = safe_domain(host)
            if value:
                ctx.emit("nameserver", value, "nameserver", SelectorStrength.MEDIUM,
                         evidence_id=res.evidence_id, tags=["whoisxml"])
        contact_email = text(first(record, "contactEmail", default="") or registrant.get("email"))
        if "@" in contact_email and len(contact_email) < 320:
            ctx.emit(
                "email", contact_email.lower(), "registrant-contact", SelectorStrength.WEAK,
                evidence_id=res.evidence_id, tags=["whoisxml", "registrant"], context_only=True,
                note="WHOIS contact address; often a privacy proxy",
            )
        return ctx.result


__all__ = [
    "AbuseIPDBProvider",
    "AlienVaultOTXProvider",
    "CensysProvider",
    "GreyNoiseProvider",
    "HybridAnalysisProvider",
    "MalwareBazaarProvider",
    "SecurityTrailsProvider",
    "ShodanProvider",
    "VirusTotalProvider",
    "WhoisXmlProvider",
]
