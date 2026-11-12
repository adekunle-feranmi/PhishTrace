"""Certificate Transparency providers (crt.sh, Cert Spotter).

CT logs are the single best keyless source for finding sibling infrastructure:
phishing operators routinely request one certificate covering many look-alike
domains, and every issuance is public and timestamped.
"""

from __future__ import annotations

from urllib.parse import quote

from phishtrace.models import SelectorStrength
from phishtrace.providers._util import (
    as_int, first, indicator_host, iterate_dicts, parse_date, result_error, safe_domain, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta


class CrtShProvider(BaseProvider):
    meta = ProviderMeta(
        name="crt_sh",
        accepts=("domain",),
        emits=("domain",),
        rate_limit=0.4,
        timeout=90.0,
        reliability=0.92,
        category="certificates",
        description="Certificate Transparency search via crt.sh (keyless)",
        homepage="https://crt.sh/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        domain = indicator_host(ctx.indicator)
        if not domain:
            ctx.partial("crt.sh requires a domain or URL seed")
            return ctx.result
        url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
        res = await ctx.http.get_json(
            url, timeout=90.0, max_bytes=8_000_000,
            cache_key=f"crtsh:{domain}", cache_ttl=3600.0,
        )
        if not res.ok:
            ctx.partial(f"crt.sh unavailable: {result_error(res)}")
            return ctx.result
        rows = res.data if isinstance(res.data, list) else []
        if not rows:
            ctx.partial("crt.sh returned no certificates")
            return ctx.result

        seen: set[str] = set()
        earliest = None
        earliest_name = ""
        emitted = 0
        for row in iterate_dicts(rows, max_items=3000):
            names = text(first(row, "name_value", "common_name")).splitlines()
            not_before = parse_date(first(row, "not_before", "entry_timestamp"))
            issuer = text(first(row, "issuer_name"))
            for raw_name in names:
                host = safe_domain(raw_name)
                if not host or host in seen or host.endswith(".arpa"):
                    continue
                seen.add(host)
                if not_before and (earliest is None or not_before < earliest):
                    earliest, earliest_name = not_before, host
                if emitted >= 150 or host == domain:
                    continue
                emitted += 1
                ctx.emit(
                    "domain", host, "ct-san",
                    SelectorStrength.MEDIUM,
                    evidence_id=res.evidence_id,
                    observed_at=not_before,
                    tags=["certificate-transparency"],
                    meta={
                        "issuer": issuer,
                        "serial": text(first(row, "serial_number")),
                        "not_before": not_before.isoformat() if not_before else None,
                        "not_after": (parse_date(first(row, "not_after")).isoformat()
                                      if parse_date(first(row, "not_after")) else None),
                        "certificate_id": as_int(first(row, "id"), 0),
                    },
                )
            if not_before:
                ctx.event(
                    not_before,
                    kind="certificate-issuance",
                    label=f"Certificate issued covering {domain}",
                    detail=f"issuer={issuer}" if issuer else None,
                    url=f"https://crt.sh/?id={as_int(first(row, 'id'), 0)}",
                    evidence_id=res.evidence_id,
                    indicator_value=domain,
                    precision="exact",
                )
        if earliest:
            ctx.result.notes.append(
                f"earliest certificate for {earliest_name or domain} observed {earliest.isoformat()}"
            )
        if not emitted and not seen:
            ctx.partial("crt.sh response contained no usable names")
        return ctx.result


class CertSpotterProvider(BaseProvider):
    meta = ProviderMeta(
        name="certspotter",
        accepts=("domain",),
        emits=("domain",),
        rate_limit=0.5,
        timeout=45.0,
        reliability=0.88,
        category="certificates",
        description="Certificate Transparency via SSLMate Cert Spotter (keyless, optional key raises limits)",
        homepage="https://sslmate.com/certspotter/",
        cache_ttl=3600.0,
    )

    async def run(self, ctx):
        domain = indicator_host(ctx.indicator)
        if not domain:
            ctx.partial("certspotter requires a domain or URL seed")
            return ctx.result
        headers = {"Accept": "application/json"}
        token = ctx.config.api_key("CERTSPOTTER_API_KEY")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={quote(domain)}&include_subdomains=true&expand=dns_names&expand=not_before"
        )
        res = await ctx.http.get_json(url, headers=headers, timeout=45.0,
                                      cache_key=f"certspotter:{domain}", cache_ttl=3600.0)
        if not res.ok:
            ctx.partial(f"certspotter unavailable: {result_error(res)}")
            return ctx.result
        rows = res.data if isinstance(res.data, list) else []
        if not rows:
            ctx.partial("certspotter returned no issuances")
            return ctx.result

        seen: set[str] = set()
        for row in iterate_dicts(rows, max_items=500):
            not_before = parse_date(first(row, "not_before"))
            issuer = first(row, "issuer", default={})
            issuer_name = text(first(issuer, "name", "friendly_name")) if isinstance(issuer, dict) else text(issuer)
            for raw_name in content_list(first(row, "dns_names", default=[])):
                host = safe_domain(raw_name)
                if not host or host in seen or host == domain:
                    continue
                seen.add(host)
                ctx.emit(
                    "domain", host, "ct-san", SelectorStrength.MEDIUM,
                    evidence_id=res.evidence_id, observed_at=not_before,
                    tags=["certificate-transparency"],
                    meta={"issuer": issuer_name, "cert_id": text(first(row, "id"))},
                )
                if len(seen) >= 100:
                    break
            if not_before:
                ctx.event(
                    not_before, kind="certificate-issuance",
                    label=f"Certificate issued covering {domain}",
                    detail=issuer_name or None,
                    evidence_id=res.evidence_id, indicator_value=domain,
                )
            if len(seen) >= 100:
                break
        return ctx.result


def content_list(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, str)]
    return []
