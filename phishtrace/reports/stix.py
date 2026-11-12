"""STIX 2.1 export for PhishTrace reports.

The bundle is deliberately conservative:

* standard SCO patterns are used for URL, domain, IP, email, ASN, user account,
  file hashes and X.509 certificate hashes;
* types with no standard STIX 2.1 observable use a custom SCO type named with
  the ``x-`` prefix (for example ``x-phone-number``) and keep the original
  PhishTrace type in a custom property;
* graph edges become ``relationship`` SROs, and the report object references
  every exported indicator and relationship;
* coverage is carried in a ``note`` and in custom properties so a STIX consumer
  cannot mistake an unavailable provider for a clean result.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any

from phishtrace.models import iso, parse_timestamp, utcnow
from phishtrace.reports.context import deterministic_uuid

STIX_VERSION = "2.1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
_HEX40 = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


def _escape(value: Any) -> str:
    """Escape a value for a STIX pattern string literal."""
    text = str(value or "")
    return text.replace("\\", "\\\\").replace("'", "\\'")


def _pattern(node: dict) -> tuple[str, str]:
    """Return ``(pattern, object_type)`` for a graph node."""
    kind = str(node.get("type") or "unknown").lower()
    value = str(node.get("normalized_value") or node.get("value") or "").strip()
    escaped = _escape(value)
    if kind == "url":
        return f"[url:value = '{escaped}']", "url"
    if kind in {"domain", "nameserver"}:
        return f"[domain-name:value = '{escaped}']", "domain-name"
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(value)
            key = "ipv6-addr" if ip.version == 6 else "ipv4-addr"
        except ValueError:
            key = "ipv4-addr"
        return f"[{key}:value = '{escaped}']", key
    if kind == "email":
        return f"[email-addr:value = '{escaped.lower()}']", "email-addr"
    if kind == "file_hash" and _HEX64.match(value):
        return f"[file:hashes.'SHA-256' = '{escaped.lower()}']", "file"
    if kind == "file_hash" and _HEX40.match(value):
        return f"[file:hashes.'SHA-1' = '{escaped.lower()}']", "file"
    if kind in {"file_hash", "cert_sha256"} and _HEX64.match(value):
        return f"[x509-certificate:hashes.'SHA-256' = '{escaped.lower()}']", "x509-certificate"
    if kind == "cert_sha256":
        return f"[x509-certificate:hashes.'SHA-256' = '{escaped.lower()}']", "x509-certificate"
    if kind == "asn":
        digits = re.sub(r"\D", "", value)
        if digits:
            return f"[autonomous-system:number = {int(digits)}]", "autonomous-system"
    if kind == "username":
        return f"[user-account:account_login = '{escaped}']", "user-account"
    custom = {
        "phone": "x-phone-number",
        "telegram": "x-telegram-account",
        "analytics_id": "x-analytics-id",
        "ja3": "x-ja3-fingerprint",
        "btc_address": "x-cryptocurrency-address",
        "unknown": "x-phishtrace-indicator",
    }.get(kind, "x-phishtrace-indicator")
    return f"[{custom}:value = '{escaped}']", custom


def _valid_from(data: dict, generated: datetime) -> str:
    earliest = data.get("earliest_observed") or {}
    if earliest.get("occurred_at"):
        parsed = parse_timestamp(earliest["occurred_at"])
        if parsed:
            return iso(parsed)
    return iso(parse_timestamp(data.get("started_at")) or generated)


def build_stix_bundle(data: dict, *, generated_at: datetime | None = None) -> dict:
    """Build a deterministic, standards-shaped STIX 2.1 bundle."""
    generated = generated_at or utcnow()
    created = iso(generated)
    investigation_id = str(data.get("report_id") or "unknown")
    company = str(data.get("company") or "PhishTrace")
    identity_id = f"identity--{deterministic_uuid('identity', company)}"
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": STIX_VERSION,
            "id": identity_id,
            "created": created,
            "modified": created,
            "name": company,
            "identity_class": "organization",
            "description": "Defensive phishing-infrastructure investigation produced by PhishTrace.",
        }
    ]

    indicators: list[dict] = []
    node_refs: dict[str, str] = {}
    valid_from = _valid_from(data, generated)
    for node in data.get("graph", {}).get("nodes", []):
        pattern, object_type = _pattern(node)
        kind = str(node.get("type") or "unknown").lower()
        value = str(node.get("normalized_value") or node.get("value") or "")
        indicator_id = f"indicator--{deterministic_uuid('stix-indicator', investigation_id, kind, value)}"
        node_refs[str(node.get("id"))] = indicator_id
        confidence = max(0, min(100, round(float(node.get("path_confidence") or 0.5) * 100)))
        labels = [kind, object_type]
        if node.get("context_only"):
            labels.append("context-only")
        labels.extend(str(tag)[:64] for tag in (node.get("tags") or [])[:8])
        indicator = {
            "type": "indicator",
            "spec_version": STIX_VERSION,
            "id": indicator_id,
            "created": created,
            "modified": created,
            "created_by_ref": identity_id,
            "name": f"{kind}: {value}"[:256],
            "description": (
                f"Indicator materialized in PhishTrace investigation {investigation_id}. "
                f"Graph depth {node.get('depth', 0)}; path confidence {node.get('path_confidence', 0)}. "
                "The earliest observed timestamp is a coverage observation, not proof of first activity."
            ),
            "indicator_types": ["anomalous-activity"] if node.get("context_only") else ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": valid_from,
            "confidence": confidence,
            "labels": labels,
            "x_phishtrace_investigation_id": investigation_id,
            "x_phishtrace_original_type": kind,
            "x_phishtrace_depth": int(node.get("depth") or 0),
            "x_phishtrace_context_only": bool(node.get("context_only")),
            "x_phishtrace_path_confidence": float(node.get("path_confidence") or 0),
        }
        if node.get("first_seen_in_run"):
            indicator["x_phishtrace_materialized_at"] = node["first_seen_in_run"]
        indicators.append(indicator)

    relationships: list[dict] = []
    for edge in data.get("graph", {}).get("edges", []):
        source = node_refs.get(str(edge.get("src")))
        target = node_refs.get(str(edge.get("dst")))
        if not source or not target or source == target:
            continue
        rel_id = f"relationship--{deterministic_uuid('stix-relationship', investigation_id, edge.get('id') or f'{source}|{edge.get('relation')}|{target}')}"
        relationships.append(
            {
                "type": "relationship",
                "spec_version": STIX_VERSION,
                "id": rel_id,
                "created": created,
                "modified": created,
                "created_by_ref": identity_id,
                "relationship_type": "related-to",
                "source_ref": source,
                "target_ref": target,
                "description": (
                    f"Provider {edge.get('provider')} reported relation '{edge.get('relation')}' "
                    f"with edge confidence {edge.get('confidence', 0)}."
                ),
                "confidence": max(0, min(100, round(float(edge.get("confidence") or 0) * 100))),
                "x_phishtrace_relation": edge.get("relation"),
                "x_phishtrace_provider": edge.get("provider"),
                "x_phishtrace_selector_strength": edge.get("selector_strength"),
                "x_phishtrace_evidence_id": edge.get("evidence_id"),
            }
        )

    coverage = data.get("coverage", {})
    report_id = f"report--{deterministic_uuid('stix-report', investigation_id)}"
    coverage_text = (
        f"Provider coverage: {len(coverage.get('ran', []))} ran, "
        f"{len(coverage.get('skipped', []))} skipped, {len(coverage.get('failed', []))} failed. "
        f"{coverage.get('note', '')}"
    )
    note_id = f"note--{deterministic_uuid('stix-coverage-note', investigation_id)}"
    objects.extend(indicators)
    objects.extend(relationships)
    objects.append(
        {
            "type": "note",
            "spec_version": STIX_VERSION,
            "id": note_id,
            "created": created,
            "modified": created,
            "created_by_ref": identity_id,
            "object_refs": [report_id],
            "content": coverage_text[:10000],
            "authors": [company],
            "x_phishtrace_coverage": coverage,
        }
    )
    objects.append(
        {
            "type": "report",
            "spec_version": STIX_VERSION,
            "id": report_id,
            "created": created,
            "modified": created,
            "created_by_ref": identity_id,
            "name": f"PhishTrace investigation: {data.get('seed', {}).get('normalized') or investigation_id}",
            "description": (
                f"Phishing infrastructure investigation {investigation_id}. "
                "Dates are the earliest observation by covered sources, not proof of first activity."
            ),
            "published": valid_from,
            "report_types": ["threat-report"],
            "object_refs": [indicator["id"] for indicator in indicators]
            + [relationship["id"] for relationship in relationships],
            "labels": ["phishing", "phishtrace"],
            "confidence": max(0, min(100, int(data.get("counts", {}).get("indicators", 0) > 0) * 60)),
            "external_references": [
                {
                    "source_name": "PhishTrace investigation",
                    "description": investigation_id,
                }
            ],
            "x_phishtrace_seed_type": data.get("seed", {}).get("type"),
            "x_phishtrace_earliest_observed": (data.get("earliest_observed") or {}).get("occurred_at"),
            "x_phishtrace_tlp": data.get("tlp"),
            "x_phishtrace_coverage_summary": {
                "ran": len(coverage.get("ran", [])),
                "skipped": len(coverage.get("skipped", [])),
                "failed": len(coverage.get("failed", [])),
            },
            "x_phishtrace_limitations": data.get("limitations", []),
        }
    )
    bundle_id = f"bundle--{deterministic_uuid('stix-bundle', investigation_id)}"
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": STIX_VERSION,
        "objects": objects,
    }
