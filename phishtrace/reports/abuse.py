"""Abuse-report generator.

This module produces *drafts*, never sends them.  Recipients are only used when
an operator has explicitly configured an address for the role, ASN or
organisation.  Addresses are never invented from an organisation name, which
avoids sending a victim's or an innocent third party's data to a guessed inbox.

Each target gets a plain-text email and an optional machine-readable JSON
attachment.  The email uses defanged indicators in the body; exact indicators
stay in the attachment for blocking and correlation.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime, make_msgid, parseaddr
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from phishtrace import __version__
from phishtrace.config import ReportConfig
from phishtrace.models import iso, utcnow
from phishtrace.reports.context import deterministic_uuid, report_filename
from phishtrace.utils import slugify, to_jsonable

_EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


def _header_safe(value: Any, limit: int = 300) -> str:
    text = re.sub(r"[\r\n\t]+", " ", str(value or "")).strip()
    return text[:limit]


def _display_safe(value: Any, limit: int = 120) -> str:
    """Keep an address-book display name inert.

    A company string such as ``Acme\nBcc: attacker@example.org`` must never be
    able to introduce a header, an address, or an angle-addr pair of its own.
    """
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))
    text = re.sub(r"[:<>@\"\\\\;,]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip(" .")
    return text[:limit] or "PhishTrace"


def _valid_email(value: str | None) -> str | None:
    if not value:
        return None
    _, address = parseaddr(str(value))
    address = address.strip()
    if not _EMAIL_RE.match(address) or "\n" in address or "\r" in address:
        return None
    return address


def _domain_from_seed(seed: dict) -> str:
    value = str(seed.get("normalized") or seed.get("value") or "")
    if "://" in value:
        try:
            return (urlsplit(value).hostname or "").lower()
        except ValueError:
            return ""
    return value.lower().strip(".") if "." in value and " " not in value else ""


def _defang(value: str) -> str:
    text = str(value or "")
    text = re.sub(r"(?i)^http://", "hxxp://", text)
    text = re.sub(r"(?i)^https://", "hxxps://", text)
    text = text.replace(".", "[.]")
    text = text.replace("@", "[at]")
    return text


def _contact_map(settings: ReportConfig) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in (settings.hosting_contacts or {}).items():
        email = _valid_email(str(value))
        if email:
            values[str(key).strip().lower()] = email
    for key, value in (settings.abuse_contacts or {}).items():
        email = _valid_email(str(value))
        if email:
            values[f"role:{str(key).strip().lower()}"] = email
    for key, value in (settings.cert_contacts or {}).items():
        email = _valid_email(str(value))
        if email:
            values[f"cert:{str(key).strip().upper()}"] = email
    return values


def _hosting_contact(row: dict, contacts: dict[str, str]) -> str | None:
    candidates = [
        str(row.get("asn") or "").lower(),
        str(row.get("asn") or "").replace("as", "").lower(),
        str(row.get("organization") or "").lower(),
    ]
    for candidate in candidates:
        if candidate and candidate in contacts:
            return contacts[candidate]
    for key, value in contacts.items():
        if key.startswith("hosting:") and any(
            candidate and candidate == key.split(":", 1)[1] for candidate in candidates
        ):
            return value
    return None


def _target(
    *,
    role: str,
    organization: str,
    email: str | None,
    rationale: str,
    indicators: list[dict],
    asn: str | None = None,
    country: str | None = None,
) -> dict:
    identifier = deterministic_uuid("abuse-target", role, organization or email or "unknown", asn or "")
    return {
        "id": f"abuse-target--{identifier}",
        "role": role,
        "organization": organization or "manual lookup required",
        "email": email,
        "asn": asn,
        "country": country,
        "rationale": rationale,
        "indicators": indicators[:80],
        "manual": not bool(email),
    }


def build_abuse_targets(data: dict, settings: ReportConfig) -> list[dict]:
    """Derive hosting/registrar/CERT/platform targets from recorded evidence only."""
    contacts = _contact_map(settings)
    seed = data.get("seed") or {}
    domain = _domain_from_seed(seed)
    nodes = (data.get("graph") or {}).get("nodes") or []
    targets: list[dict] = []
    seen: set[tuple[str, str]] = set()

    registrar = ""
    cert_issuer = ""
    cert_values: list[dict] = []
    hosting: dict[str, dict] = {}
    platform_values: list[dict] = []
    for node in nodes:
        meta = node.get("meta") or {}
        kind = str(node.get("type") or "")
        value = str(node.get("normalized_value") or node.get("value") or "")
        # Stop-listed shared infrastructure (CDNs, mail providers, public
        # resolvers) is context, never an abuse recipient.
        if node.get("context_only"):
            continue
        if not registrar:
            registrar = str(meta.get("registrar") or meta.get("registrar_name") or meta.get("registrar_id") or "").strip()
        if kind in {"domain", "url", "nameserver", "ip", "asn"}:
            asn = str(meta.get("asn") or "").strip()
            org = str(meta.get("org") or meta.get("asn_name") or meta.get("organization") or "").strip()
            if asn or org:
                key = (asn or org).lower()
                entry = hosting.setdefault(
                    key,
                    {"asn": asn, "organization": org, "indicators": [], "country": str(meta.get("country") or "")},
                )
                if value and not any(item.get("value") == value for item in entry["indicators"]):
                    entry["indicators"].append({"type": kind, "value": value})
        if kind in {"cert_sha256"}:
            cert_issuer = cert_issuer or str(meta.get("issuer") or "").strip()
            cert_values.append({"type": kind, "value": value, "issuer": cert_issuer})
        if kind in {"telegram", "email", "username", "phone"} and value:
            platform_values.append({"type": kind, "value": value})

    if registrar:
        email = contacts.get("role:registrar")
        key = ("registrar", registrar.lower())
        if key not in seen:
            seen.add(key)
            targets.append(
                _target(
                    role="registrar",
                    organization=registrar,
                    email=email,
                    rationale="Registrar recorded in RDAP/WHOIS provider metadata.",
                    indicators=[] if not domain else [{"type": "domain", "value": domain}],
                    country=(data.get("country") or {}).get("code"),
                )
            )
    elif domain and domain.count(".") >= 1 and not re.fullmatch(r"[\d.]+", domain):
        key = ("registrar", "manual")
        if key not in seen:
            seen.add(key)
            targets.append(
                _target(
                    role="registrar",
                    organization="Registrar (lookup required)",
                    email=contacts.get("role:registrar"),
                    rationale="No registrar was returned; use RDAP/WHOIS before sending.",
                    indicators=[{"type": "domain", "value": domain}],
                    country=(data.get("country") or {}).get("code"),
                )
            )

    for entry in hosting.values():
        org = entry.get("organization") or ("AS" + str(entry.get("asn")).replace("AS", "") if entry.get("asn") else "Hosting provider")
        key = (entry.get("asn") or org).lower()
        if ("hosting", key) in seen:
            continue
        seen.add(("hosting", key))
        email = _hosting_contact(entry, contacts) or contacts.get("role:hosting")
        targets.append(
            _target(
                role="hosting",
                organization=org,
                email=email,
                rationale="ASN/organisation returned by an IP, DNS or scan provider.",
                indicators=entry.get("indicators") or [],
                asn=entry.get("asn") or None,
                country=entry.get("country") or (data.get("country") or {}).get("code"),
            )
        )

    cert_country = (data.get("country") or {}).get("code")
    if cert_values:
        # A certificate issuer and a national CERT are different organisations;
        # they never share one draft.
        key = ("certificate_authority", (cert_issuer or "unknown").lower())
        if key not in seen:
            seen.add(key)
            targets.append(
                _target(
                    role="certificate_authority",
                    organization=cert_issuer or "Certificate authority (lookup required)",
                    email=contacts.get("role:certificate_authority") or contacts.get("role:certificate-authority"),
                    rationale="Certificate issuer recorded in CT provider metadata.",
                    indicators=cert_values[:40],
                    country=cert_country,
                )
            )
    cert_email = contacts.get(f"cert:{cert_country}") if cert_country else None
    if cert_email:
        key = ("national_cert", str(cert_country))
        if key not in seen:
            seen.add(key)
            targets.append(
                _target(
                    role="national_cert",
                    organization=f"National CERT ({cert_country})",
                    email=cert_email,
                    rationale=(f"Operator configured a national CERT contact for the {cert_country} region lens."),
                    indicators=(
                        [{"type": "domain", "value": domain}] if domain else []
                    ) + cert_values[:20],
                    country=cert_country,
                )
            )

    if platform_values:
        key = ("platform", "configured")
        if key not in seen:
            seen.add(key)
            targets.append(
                _target(
                    role="platform",
                    organization="Platform abuse team",
                    email=contacts.get("role:platform"),
                    rationale="A public social/email/telegram selector was observed; platform policy applies.",
                    indicators=platform_values[:40],
                    country=(data.get("country") or {}).get("code"),
                )
            )

    default_email = contacts.get("role:default")
    if default_email and not any(target["email"] == default_email for target in targets):
        targets.append(
            _target(
                role="default",
                organization="Configured default abuse contact",
                email=default_email,
                rationale="Fallback mailbox configured by the operator.",
                indicators=[],
                country=(data.get("country") or {}).get("code"),
            )
        )
    return targets


def _target_indicators_text(target: dict, data: dict, limit: int = 80) -> str:
    rows = list(target.get("indicators") or [])
    if not rows:
        seed = data.get("seed") or {}
        if seed.get("normalized") or seed.get("value"):
            rows = [{"type": seed.get("type") or "indicator", "value": seed.get("normalized") or seed.get("value")}]
    return "\n".join(f"  - {_defang(str(row.get('value')))} ({row.get('type')})" for row in rows[:limit])


def render_abuse_body(data: dict, target: dict, settings: ReportConfig) -> str:
    seed = data.get("seed") or {}
    earliest = (data.get("earliest_observed") or {}).get("occurred_at") or "no dated event observed in covered sources"
    company = settings.company or "PhishTrace"
    lines = [
        f"To: {target.get('organization')} abuse team",
        "",
        f"We are reporting suspected phishing infrastructure for investigation. This message was prepared by {company} using PhishTrace.",
        "",
        f"Investigation: {data.get('report_id')}",
        f"Seed: {_defang(str(seed.get('normalized') or seed.get('value') or 'unknown'))}",
        f"Seed type: {seed.get('type') or 'unknown'}",
        f"Earliest observed by covered sources: {earliest}",
        f"Region lens: {(data.get('country') or {}).get('code') or 'not established'}",
        "",
        f"Relevant role: {target.get('role')}",
        f"Why this recipient: {target.get('rationale')}",
    ]
    if target.get("asn"):
        lines.append(f"ASN: {target.get('asn')}")
    lines.extend(
        [
            "",
            "Indicators associated with this target (defanged for safe display):",
            _target_indicators_text(target, data),
            "",
            "Requested action:",
            "  1. Review the indicators and preserve relevant logs for the investigation window.",
            "  2. If the content is confirmed malicious, suspend or sinkhole it under your policy.",
            "  3. Do not visit the page from a production account; use your isolated analysis environment.",
            "  4. Reply with a case/reference number if your process allows it.",
            "",
            "Evidence handling:",
            f"  - {data.get('counts', {}).get('evidence', 0)} capture(s) are referenced in the attached report metadata.",
            "  - Raw response bodies may contain victim-supplied data and are not attached to this message.",
            "  - The attached JSON contains exact (not defanged) indicators for blocking.",
            "",
            f"Limitations: {(data.get('limitations') or ['Coverage and confidence are reported in the attached assessment.'])[0]}",
            "",
            "This is a defensive notification, not an attribution or a legal demand. Please treat the indicators as leads until independently verified.",
            "",
            f"Regards,",
            f"{company} abuse-report desk",
        ]
    )
    return "\n".join(lines).strip() + "\n"


def render_eml(
    data: dict,
    target: dict,
    settings: ReportConfig,
    *,
    attachment: bytes | None = None,
    generated_at: datetime | None = None,
) -> bytes:
    """Render one RFC-5322 draft.  No network call is made."""
    generated = generated_at or utcnow()
    to_address = _valid_email(target.get("email"))
    if not to_address:
        raise ValueError("target has no valid configured email address")
    domain = str(data.get("seed", {}).get("normalized") or "investigation")
    subject = _header_safe(
        f"[PhishTrace] Phishing infrastructure report — {domain} — {data.get('report_id')}",
        240,
    )
    message = EmailMessage(policy=SMTP)
    from_address = _valid_email(settings.from_address) or "phishtrace@localhost"
    message["From"] = f"{_display_safe(settings.company)} <{from_address}>"
    message["To"] = to_address
    if settings.reply_to and _valid_email(settings.reply_to):
        message["Reply-To"] = _valid_email(settings.reply_to)
    message["Subject"] = subject
    message["Date"] = format_datetime(generated)
    message["Message-ID"] = make_msgid(idstring="phishtrace", domain="localhost")
    message["Auto-Submitted"] = "auto-generated"
    message["X-Mailer"] = f"PhishTrace/{__version__}"
    message["X-PhishTrace-Investigation"] = _header_safe(data.get("report_id"))
    message["X-PhishTrace-TLP"] = _header_safe(data.get("tlp") or "CLEAR")
    message.set_content(render_abuse_body(data, target, settings), subtype="plain", charset="utf-8")
    if settings.abuse_include_attachment and attachment:
        filename = report_filename(data, "json")
        message.add_attachment(
            attachment,
            maintype="application",
            subtype="json",
            filename=filename,
        )
    return message.as_bytes()


def build_abuse_package(
    data: dict,
    settings: ReportConfig,
    *,
    generated_at: datetime | None = None,
    json_attachment: bytes | None = None,
) -> dict:
    generated = generated_at or utcnow()
    if json_attachment is None and settings.abuse_include_attachment:
        # Lazy import keeps the module graph acyclic (render imports the
        # context and format builders, never this module).
        from phishtrace.reports.render import render_json

        json_attachment = render_json(data)
    targets = build_abuse_targets(data, settings)
    emails: list[dict] = []
    for target in targets:
        if not target.get("email"):
            continue
        try:
            raw = render_eml(data, target, settings, attachment=json_attachment, generated_at=generated)
        except ValueError:
            target["manual"] = True
            continue
        filename = f"{slugify(target['role'], 24)}-{slugify(target['organization'], 32)}-{target['id'].split('--')[-1][:8]}.eml"
        emails.append(
            {
                "target_id": target["id"],
                "to": target["email"],
                "subject": _header_safe(
                    f"[PhishTrace] Phishing infrastructure report — {data.get('seed', {}).get('normalized') or data.get('report_id')} — {data.get('report_id')}",
                    240,
                ),
                "filename": filename,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "_bytes": raw,
            }
        )
    manual = [target for target in targets if not target.get("email")]
    public_targets = [{k: v for k, v in target.items() if k != "_bytes"} for target in targets]
    public_emails = [{k: v for k, v in email.items() if k != "_bytes"} for email in emails]
    return {
        "schema": "phishtrace.abuse/1",
        "investigation_id": data.get("report_id"),
        "generated_at": iso(generated),
        "from": settings.from_address,
        "tlp": data.get("tlp"),
        "targets": public_targets,
        "emails": public_emails,
        "manual_review": manual,
        "note": (
            "Drafts only. No message was sent. Addresses are used only when explicitly configured; "
            "unmapped targets require manual verification."
        ),
        "_email_bytes": {email["filename"]: email["_bytes"] for email in emails},
        "_json": to_jsonable({k: v for k, v in {
            "targets": public_targets,
            "emails": public_emails,
            "manual_review": manual,
        }.items()}),
    }


def write_abuse_package(
    out_dir: str | Path,
    data: dict,
    settings: ReportConfig,
    *,
    generated_at: datetime | None = None,
    json_attachment: bytes | None = None,
) -> dict:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    package = build_abuse_package(data, settings, generated_at=generated_at, json_attachment=json_attachment)
    files: list[dict] = []
    for filename, raw in package.get("_email_bytes", {}).items():
        path = output / filename
        path.write_bytes(raw)
        files.append({"path": path.name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "kind": "email"})
    manifest = {key: value for key, value in package.items() if not key.startswith("_")}
    manifest["files"] = files
    manifest_path = output / "abuse-manifest.json"
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    manifest_path.write_bytes(manifest_bytes)
    files.append({"path": manifest_path.name, "size": len(manifest_bytes), "sha256": hashlib.sha256(manifest_bytes).hexdigest(), "kind": "manifest"})
    manifest["files"] = files
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest
