"""Providers that wrap an installed command-line OSINT tool.

Each wrapper is opt-in: the tool must be on ``PATH`` (or ``options.path`` must
point at it) and the provider must be enabled in ``config.yaml``.  Output is
captured as evidence and only *selectors and dates* are extracted into the
graph; free-form personal data a tool may return is not persisted.

Tools are run through :class:`phishtrace.tools.runner.ToolRunner`, which keeps
argv shell-free, the environment minimal, and time/output bounded.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from phishtrace.models import SelectorStrength
from phishtrace.providers._util import (
    as_list, belongs_to_domain, iter_lines, safe_domain, safe_ip, text,
)
from phishtrace.providers.base import BaseProvider, ProviderMeta
from phishtrace.tools import ToolNotAvailable, ToolResult, ToolRunner, ToolTargetError, validate_target

#: SpiderFoot element names -> PhishTrace selector types.
_SPIDERFOOT_TYPES = {
    "ip address": "ip",
    "ipv6 address": "ip",
    "internet name": "domain",
    "domain name": "domain",
    "email address": "email",
    "url": "url",
    "phone number": "phone",
    "bitcoin address": "btc_address",
    "as owned netblock": "asn",
}


def _record(ctx, result: ToolResult) -> str | None:
    """Persist the tool's output as evidence (never the inherited environment)."""
    recorder = getattr(getattr(ctx, "http", None), "recorder", None)
    if recorder is None:
        return None
    body = (
        f"$ {' '.join(result.command)}\n"
        f"# exit={result.exit_code} duration_ms={result.duration_ms} "
        f"timed_out={result.timed_out} truncated={result.truncated}\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}\n"
    ).encode("utf-8", errors="replace")
    try:
        return recorder.record(
            provider=result.tool,
            request={"tool": result.tool, "argv": result.command},
            body=body,
            url=f"tool://{result.tool}",
            status_code=result.exit_code,
            content_type="text/plain",
        )
    except Exception:  # noqa: BLE001 - evidence capture must never break a run
        return None


class _ToolProvider(BaseProvider):
    """Shared plumbing: build the runner, record output, fail softly."""

    #: File the tool writes into its scratch directory, when it does not print.
    collects: tuple[str, ...] = ()
    #: Pick up any ``*.json`` report the tool leaves in the scratch directory.
    collect_json: bool = False

    def runner(self) -> ToolRunner:
        return ToolRunner(
            self.meta.requires_tool or self.meta.name,
            path=(self.options.get("path") or None),
            timeout=self.effective_timeout(),
            max_output=int(self.options.get("max_output") or 4_000_000),
        )

    async def invoke(
        self,
        ctx,
        args: list[str],
        *,
        timeout: float | None = None,
        collect: tuple[str, ...] | None = None,
    ) -> ToolResult:
        try:
            runner = self.runner()
        except ToolNotAvailable as exc:
            raise RuntimeError(str(exc)) from exc
        result = await runner.run(
            args,
            collect=self.collects if collect is None else collect,
            collect_json=self.collect_json,
            timeout=timeout,
        )
        result.evidence_id = _record(ctx, result)
        if not result.ok:
            ctx.partial(f"{self.meta.name}: {result.reason or 'tool failed'}")
        return result

    @staticmethod
    def _arg(value: Any, field: str = "target") -> str:
        try:
            return validate_target(value, field_name=field)
        except ToolTargetError as exc:
            raise ValueError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# Domain permutation
# --------------------------------------------------------------------------- #
class DnstwistProvider(_ToolProvider):
    meta = ProviderMeta(
        name="dnstwist",
        phase="C",
        accepts=("domain",),
        emits=("domain",),
        requires_tool="dnstwist",
        rate_limit=0.2,
        timeout=120.0,
        reliability=0.7,
        category="brand-protection",
        description="Registered lookalike/typosquat domains via dnstwist (local permutation + DNS)",
        homepage="https://github.com/elceef/dnstwist",
    )

    async def run(self, ctx):
        domain = safe_domain(ctx.indicator.normalized)
        if not domain:
            ctx.partial("dnstwist needs a registrable domain")
            return ctx.result
        result = await self.invoke(ctx, ["--format", "json", self._arg(domain, "domain")])
        rows = result.json_stdout() if result.ok else None
        if isinstance(rows, dict):
            rows = rows.get("domains") or []
        if not isinstance(rows, list):
            if result.ok:
                ctx.partial("dnstwist returned no parsable JSON")
            return ctx.result
        emitted = 0
        for row in rows:
            if not isinstance(row, dict):
                continue
            candidate = safe_domain(row.get("domain"))
            if not candidate or candidate == domain:
                continue
            addresses = [safe_ip(value) for value in as_list(row.get("dns_a"))]
            addresses = [value for value in addresses if value]
            if not addresses:
                # Unregistered permutations are noise for an investigation.
                continue
            fuzzer = text(row.get("fuzzer"))
            ctx.emit(
                "domain", candidate, "lookalike-domain", SelectorStrength.WEAK,
                evidence_id=result.evidence_id, tags=["dnstwist"] + ([f"fuzzer:{fuzzer}"] if fuzzer else []),
                meta={
                    "fuzzer": fuzzer,
                    "dns_a": addresses[:8],
                    "dns_mx": [text(value) for value in as_list(row.get("dns_mx"))][:4],
                    "dns_ns": [text(value) for value in as_list(row.get("dns_ns"))][:4],
                },
                context_only=True,
                note="registered lookalike from dnstwist; context until independently linked",
            )
            for address in addresses[:4]:
                ctx.emit(
                    "ip", address, "lookalike-resolves-to", SelectorStrength.WEAK,
                    evidence_id=result.evidence_id, tags=["dnstwist"], context_only=True,
                    meta={"lookalike": candidate},
                )
            emitted += 1
            if emitted >= 60:
                break
        if not emitted:
            ctx.partial("dnstwist found no registered permutations")
        return ctx.result


# --------------------------------------------------------------------------- #
# Username enumeration
# --------------------------------------------------------------------------- #
class _UsernameTool(_ToolProvider):
    """Common parsing for sherlock/maigret style ``site -> profile URL`` output."""

    def _emit_profile(self, ctx, site: str, url: str, *, evidence_id: str | None, tool: str) -> bool:
        from phishtrace.normalizer import normalize_indicator

        try:
            normal = normalize_indicator(url)
        except ValueError:
            return False
        if normal.type != "url":
            return False
        ctx.emit(
            "url", normal.normalized, "profile-on-platform", SelectorStrength.WEAK,
            evidence_id=evidence_id, tags=[tool, f"platform:{site.lower()[:32]}"],
            meta={"platform": site, "profile_url": normal.normalized},
            context_only=True,
            note=f"public profile URL reported by {tool}; existence is not identity",
        )
        return True


class SherlockProvider(_UsernameTool):
    meta = ProviderMeta(
        name="sherlock",
        phase="C",
        accepts=("username", "email"),
        emits=("url",),
        requires_tool="sherlock",
        rate_limit=0.1,
        timeout=240.0,
        reliability=0.6,
        category="social",
        description="Public username presence across sites via sherlock",
        homepage="https://github.com/sherlock-project/sherlock",
    )
    collect_json = True

    def _username(self, ctx) -> str:
        if ctx.indicator.type == "email":
            return ctx.indicator.normalized.split("@", 1)[0]
        return ctx.indicator.normalized

    async def run(self, ctx):
        username = self._username(ctx)
        args = ["--json", "--print-found", "--no-color", self._arg(username, "username")]
        result = await self.invoke(ctx, args, timeout=self.effective_timeout())
        payload = result.json_stdout()
        if payload is None and result.ok:
            # Older releases write <username>.json instead of printing.
            for name, raw in result.files.items():
                try:
                    payload = json.loads(raw)
                    break
                except ValueError:
                    continue
        if not isinstance(payload, dict):
            if result.ok:
                ctx.partial("sherlock produced no parsable JSON")
            return ctx.result
        found = 0
        for site, row in payload.items():
            if not isinstance(row, dict):
                continue
            status = row.get("status")
            state = text(status.get("status") if isinstance(status, dict) else status)
            if state.lower() not in {"claimed", "found"}:
                continue
            url = text(row.get("url_user") or (status.get("url") if isinstance(status, dict) else ""))
            if not url:
                continue
            if self._emit_profile(ctx, text(site), url, evidence_id=result.evidence_id, tool="sherlock"):
                found += 1
            if found >= 50:
                break
        if found:
            ctx.event(
                ctx.now(), kind="username-enumeration",
                label=f"sherlock found {found} public profile(s) for {username}",
                detail="Profiles are leads; a shared handle is not a shared person.",
                evidence_id=result.evidence_id, precision="day",
            )
        else:
            ctx.partial("sherlock found no public profiles")
        return ctx.result


class MaigretProvider(_UsernameTool):
    meta = ProviderMeta(
        name="maigret",
        phase="C",
        accepts=("username", "email"),
        emits=("url",),
        requires_tool="maigret",
        rate_limit=0.1,
        timeout=300.0,
        reliability=0.6,
        category="social",
        description="Public username presence with maigret (NDJSON output)",
        homepage="https://github.com/soxoj/maigret",
    )

    async def run(self, ctx):
        username = ctx.indicator.normalized.split("@", 1)[0] if ctx.indicator.type == "email" else ctx.indicator.normalized
        args = [
            "--json", "ndjson", "--no-progressbar", "--no-color",
            "--timeout", "15", self._arg(username, "username"),
        ]
        result = await self.invoke(ctx, args, timeout=self.effective_timeout())
        rows = [row for row in result.json_lines() if isinstance(row, dict)]
        if not rows:
            # maigret writes a report file even on partial network failure.
            for name, raw in result.files.items():
                for line in raw.decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            rows.append(json.loads(line))
                        except ValueError:
                            continue
        found = 0
        for row in rows:
            status = row.get("status")
            state = text(status.get("status") if isinstance(status, dict) else status).lower()
            url = text(row.get("url_user") or row.get("url"))
            if not url or state not in {"claimed", "found"}:
                continue
            site = text(row.get("sitename") or row.get("site_name") or "unknown")
            if self._emit_profile(ctx, site, url, evidence_id=result.evidence_id, tool="maigret"):
                found += 1
            if found >= 50:
                break
        if not found:
            ctx.partial("maigret found no claimed profiles")
        return ctx.result


class HoleheProvider(_ToolProvider):
    meta = ProviderMeta(
        name="holehe",
        phase="C",
        accepts=("email",),
        emits=("email",),
        requires_tool="holehe",
        rate_limit=0.1,
        timeout=180.0,
        reliability=0.55,
        category="identity",
        description="Services where an email is registered, via holehe (opt-in: generates reset probes)",
        homepage="https://github.com/megadose/holehe",
        passive=False,
        legal_note=(
            "holehe triggers account-recovery probes against third-party services; "
            "enable only for addresses inside your authorized scope"
        ),
    )

    async def run(self, ctx):
        email = ctx.indicator.normalized
        args = ["--only-used", "--no-color", "--no-clear", self._arg(email, "email")]
        result = await self.invoke(ctx, args, timeout=self.effective_timeout())
        services: list[str] = []
        for line in iter_lines(result.stdout, limit=500):
            match = re.match(r"^\[\+\]\s+([a-z0-9._-]{2,64})$", line.strip(), re.I)
            if match:
                services.append(match.group(1).lower())
        if not services:
            if result.ok:
                ctx.partial("holehe reported no registered services")
            return ctx.result
        ctx.emit(
            "email", email, "registered-on-services", SelectorStrength.WEAK,
            evidence_id=result.evidence_id, tags=["holehe"], context_only=True,
            meta={"services": sorted(set(services))[:60], "count": len(set(services))},
            note="account-existence signal only; no credentials or profile data",
        )
        ctx.event(
            ctx.now(), kind="email-registration",
            label=f"email registered on {len(set(services))} service(s) (holehe)",
            detail=", ".join(sorted(set(services))[:12]),
            evidence_id=result.evidence_id, precision="day",
        )
        return ctx.result


# --------------------------------------------------------------------------- #
# Domain harvesting
# --------------------------------------------------------------------------- #
class TheHarvesterProvider(_ToolProvider):
    meta = ProviderMeta(
        name="theharvester",
        phase="C",
        accepts=("domain",),
        emits=("email", "domain", "ip", "url"),
        requires_tool="theharvester",
        rate_limit=0.1,
        timeout=300.0,
        reliability=0.65,
        category="osint",
        description="Emails, hosts and URLs for a domain via theHarvester",
        homepage="https://github.com/laramies/theHarvester",
    )
    collects = ("harvest.json",)

    async def run(self, ctx):
        domain = safe_domain(ctx.indicator.normalized)
        if not domain:
            ctx.partial("theHarvester needs a registrable domain")
            return ctx.result
        sources = text(self.options.get("sources") or "crtsh,otx,urlscan,hackertarget")
        if not re.fullmatch(r"[a-z0-9_,.-]{1,200}", sources):
            ctx.partial("theHarvester sources option contains unexpected characters")
            return ctx.result
        limit = str(max(10, min(500, int(self.options.get("limit") or 200))))
        result = await self.invoke(
            ctx,
            ["-d", self._arg(domain, "domain"), "-b", sources, "-l", limit, "-f", "harvest"],
            timeout=self.effective_timeout(),
        )
        payload: Any = None
        raw = result.files.get("harvest.json")
        if raw:
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = None
        if payload is None:
            payload = {}
            # Some versions only print a human-readable summary; parse it.
            emails = set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", result.stdout))
            hosts = set(re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", result.stdout.lower()))
            payload = {"emails": sorted(emails), "hosts": sorted(hosts)}
        if not isinstance(payload, dict):
            ctx.partial("theHarvester output was not parsable")
            return ctx.result

        count = 0
        for email in as_list(payload.get("emails"))[:120]:
            email = text(email).lower()
            if "@" not in email or not belongs_to_domain(email.split("@", 1)[1], domain):
                continue
            ctx.emit(
                "email", email, "harvested-email", SelectorStrength.MEDIUM,
                evidence_id=result.evidence_id, tags=["theharvester"],
                meta={"domain": domain},
            )
            count += 1
        for host in as_list(payload.get("hosts"))[:200]:
            host = safe_domain(host)
            if not host or not belongs_to_domain(host, domain):
                continue
            ctx.emit(
                "domain", host, "subdomain", SelectorStrength.MEDIUM,
                evidence_id=result.evidence_id, tags=["theharvester"],
            )
            count += 1
        for address in as_list(payload.get("ips"))[:100]:
            address = safe_ip(address)
            if address:
                ctx.emit(
                    "ip", address, "harvested-ip", SelectorStrength.WEAK,
                    evidence_id=result.evidence_id, tags=["theharvester"],
                )
                count += 1
        for url in as_list(payload.get("urls"))[:100]:
            url = text(url)
            if url.startswith(("http://", "https://")):
                ctx.emit(
                    "url", url, "harvested-url", SelectorStrength.WEAK,
                    evidence_id=result.evidence_id, tags=["theharvester"],
                )
                count += 1
        if not count:
            ctx.partial("theHarvester returned no in-scope selectors")
        return ctx.result


# --------------------------------------------------------------------------- #
# SpiderFoot
# --------------------------------------------------------------------------- #
class SpiderfootProvider(_ToolProvider):
    meta = ProviderMeta(
        name="spiderfoot",
        phase="C",
        accepts=("domain", "ip", "email", "url", "phone", "username"),
        emits=("domain", "ip", "email", "url", "phone", "asn", "btc_address"),
        requires_tool="spiderfoot",
        rate_limit=0.05,
        timeout=600.0,
        reliability=0.6,
        category="osint",
        description="SpiderFoot module sweep with CSV output (scan is passive by module choice)",
        homepage="https://github.com/smicallef/spiderfoot",
    )

    def runner(self) -> ToolRunner:
        # ``cli_path`` is the pre-Phase-8 option name; keep it working.
        path = self.options.get("path") or self.options.get("cli_path") or None
        tool = self.meta.requires_tool or "spiderfoot"
        return ToolRunner(
            tool, path=path or None,
            timeout=self.effective_timeout(),
            max_output=int(self.options.get("max_output") or 8_000_000),
            env={"SPIDERFOOT_SILENT": "1"},
        )

    def can_run(self, config):
        ok, reason = super().can_run(config)
        if not ok:
            return ok, reason
        mode = text(self.options.get("mode") or "cli").lower()
        if mode not in {"cli", "rest"}:
            return False, f"unsupported spiderfoot mode '{mode}'"
        if mode == "rest":
            return False, "spiderfoot REST mode is not implemented; use mode: cli"
        return True, None

    async def run(self, ctx):
        target = self._arg(ctx.indicator.normalized)
        modules = text(self.options.get("modules") or "sfp_dnsresolve,sfp_crt,sfp_whois")
        if not re.fullmatch(r"[a-z0-9_,]{1,500}", modules):
            ctx.partial("spiderfoot modules option contains unexpected characters")
            return ctx.result
        result = await self.invoke(
            ctx,
            ["-s", target, "-m", modules, "-o", "csv", "-q", "-H"],
            timeout=self.effective_timeout(),
        )
        if not result.ok and not result.stdout.strip():
            return ctx.result
        counts: dict[str, int] = {}
        rows = csv.reader(io.StringIO(result.stdout))
        for row in rows:
            # SpiderFoot's stdout writer emits ``module,type,source,data``.
            # Older shapes (``type,value`` or ``type,value,source``) are still
            # accepted so hand-built fixtures keep working.
            if len(row) >= 4 and text(row[0]).startswith("sfp_"):
                kind = _SPIDERFOOT_TYPES.get(text(row[1]).lower())
                value = text(",".join(row[3:]))
            elif len(row) >= 2:
                kind = _SPIDERFOOT_TYPES.get(text(row[0]).lower())
                value = text(row[1])
            else:
                continue
            if not kind or not value:
                continue
            if kind == "domain":
                value = safe_domain(value) or ""
            elif kind == "ip":
                value = safe_ip(value) or ""
            if not value:
                continue
            counts[kind] = counts.get(kind, 0) + 1
            if counts[kind] > 150:
                continue
            ctx.emit(
                kind, value, "spiderfoot-finding",
                SelectorStrength.MEDIUM if kind in {"domain", "ip", "email"} else SelectorStrength.WEAK,
                evidence_id=result.evidence_id, tags=["spiderfoot"],
                context_only=kind in {"phone", "btc_address"},
            )
        if not counts:
            ctx.partial("spiderfoot produced no mapped findings")
        else:
            ctx.log("spiderfoot findings: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        return ctx.result


# --------------------------------------------------------------------------- #
# Phone
# --------------------------------------------------------------------------- #
class PhoneInfogaProvider(_ToolProvider):
    meta = ProviderMeta(
        name="phoneinfoga",
        phase="C",
        accepts=("phone",),
        emits=("phone",),
        requires_tool="phoneinfoga",
        rate_limit=0.1,
        timeout=120.0,
        reliability=0.6,
        category="identity",
        description="Carrier/region metadata for a phone number via phoneinfoga",
        homepage="https://github.com/sundowndev/phoneinfoga",
    )

    async def run(self, ctx):
        number = self._arg(ctx.indicator.normalized, "phone")
        result = await self.invoke(ctx, ["scan", "-n", number], timeout=self.effective_timeout())
        if not result.ok:
            return ctx.result
        fields: dict[str, str] = {}
        for line in iter_lines(result.stdout, limit=400):
            match = re.match(r"^[-*\s]*([A-Za-z][A-Za-z /]{2,30}):\s*(.+)$", line)
            if match:
                key = match.group(1).strip().lower()
                value = text(match.group(2))
                if key in {"international", "local", "e164", "country", "carrier", "carrier code", "line type"}:
                    fields[key] = value
        if not fields:
            ctx.partial("phoneinfoga returned no recognised fields")
            return ctx.result
        country = text(fields.get("country")).upper()
        tags = ["phoneinfoga"]
        if len(country) == 2 and country.isalpha():
            tags.append(f"region-{country}")
        ctx.emit(
            "phone", ctx.indicator.normalized, "phone-metadata", SelectorStrength.WEAK,
            evidence_id=result.evidence_id, tags=tags, context_only=True,
            meta={
                "carrier": fields.get("carrier"),
                "line_type": fields.get("line type"),
                "country": country if len(country) == 2 else None,
                "e164": fields.get("e164") or fields.get("international"),
            },
            note="number metadata only; carrier/locality is not an attribution",
        )
        return ctx.result


# --------------------------------------------------------------------------- #
# Google account (high sensitivity, disabled by default)
# --------------------------------------------------------------------------- #
class GhuntProvider(_ToolProvider):
    meta = ProviderMeta(
        name="ghunt",
        phase="C",
        accepts=("email",),
        emits=("email",),
        requires_tool="ghunt",
        rate_limit=0.05,
        timeout=180.0,
        reliability=0.5,
        category="identity",
        description=(
            "Google account existence and public service registrations via ghunt. "
            "Only existence signals are stored; names, photos and GAIA details are dropped."
        ),
        homepage="https://github.com/mxrch/GHunt",
        passive=False,
        legal_note=(
            "ghunt authenticates with operator Google cookies and returns personal data; "
            "keep it disabled unless the subject is inside your authorized scope"
        ),
    )
    collects = ("ghunt.json",)
    collect_json = True

    def can_run(self, config):
        ok, reason = super().can_run(config)
        if not ok:
            return ok, reason
        if not text(self.options.get("cookies") or ""):
            return False, "ghunt requires options.cookies (a Netscape cookie file for a Google account)"
        return True, None

    async def run(self, ctx):
        email = self._arg(ctx.indicator.normalized, "email")
        cookies = text(self.options.get("cookies"))
        cookie_flag = text(self.options.get("cookie_flag") or "--cookie-file")
        if not re.fullmatch(r"--[a-z][a-z0-9-]{1,30}", cookie_flag):
            ctx.partial("ghunt cookie_flag must look like --flag")
            return ctx.result
        args = ["email", email, "--json", "ghunt.json"]
        if cookies:
            args.extend([cookie_flag, cookies])
        result = await self.invoke(ctx, args, timeout=self.effective_timeout())
        payload: Any = None
        raw = result.files.get("ghunt.json")
        if raw:
            try:
                payload = json.loads(raw)
            except ValueError:
                payload = None
        if not isinstance(payload, dict):
            if result.ok:
                ctx.partial("ghunt produced no parsable JSON")
            return ctx.result
        # Deliberately narrow: existence + service names, never profile fields.
        services = sorted(str(key) for key in (payload.get("services") or {}) if str(key).strip())
        ctx.emit(
            "email", email, "google-account-exists", SelectorStrength.MEDIUM,
            evidence_id=result.evidence_id, tags=["ghunt", "google"], context_only=True,
            meta={"services": services[:40], "service_count": len(services)},
            note="existence signal only; profile content was discarded by policy",
        )
        return ctx.result


__all__ = [
    "DnstwistProvider",
    "GhuntProvider",
    "HoleheProvider",
    "MaigretProvider",
    "PhoneInfogaProvider",
    "SherlockProvider",
    "SpiderfootProvider",
    "TheHarvesterProvider",
]
