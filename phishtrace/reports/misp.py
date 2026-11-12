"""MISP event export and an explicit, opt-in MISP push.

MISP is widely deployed, but its attribute vocabulary is narrower than
PhishTrace's graph.  Every graph node is therefore mapped to a documented MISP
attribute type, with a ``text`` fallback and a comment that preserves the
original selector type.  The export is importable without a PhishTrace plugin.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from phishtrace.models import iso, parse_timestamp, utcnow
from phishtrace.reports.context import deterministic_uuid

#: selector type -> (MISP attribute type, MISP category)
MISP_TYPES: dict[str, tuple[str, str]] = {
    "url": ("url", "Network activity"),
    "domain": ("domain", "Network activity"),
    "nameserver": ("domain", "Network activity"),
    "ip": ("ip-dst", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "file_hash": ("sha256", "Payload delivery"),
    "cert_sha256": ("sha256", "Network activity"),
    "phone": ("phone-number", "Other"),
    "telegram": ("text", "Social network"),
    "analytics_id": ("text", "Other"),
    "asn": ("AS", "Network activity"),
    "ja3": ("ja3-fingerprint-md5", "Network activity"),
    "username": ("text", "Social network"),
    "btc_address": ("text", "Financial fraud"),
}


class IntegrationError(RuntimeError):
    """A remote export failed without exposing credentials."""


def _attribute_type(kind: str, value: str) -> tuple[str, str]:
    kind = (kind or "unknown").lower()
    if kind == "file_hash":
        if re.fullmatch(r"[0-9a-fA-F]{64}", value or ""):
            return MISP_TYPES["file_hash"]
        if re.fullmatch(r"[0-9a-fA-F]{40}", value or ""):
            return ("sha1", "Payload delivery")
        if re.fullmatch(r"[0-9a-fA-F]{32}", value or ""):
            return ("md5", "Payload delivery")
        return ("text", "Other")
    if kind == "cert_sha256":
        return ("sha256", "Network activity")
    return MISP_TYPES.get(kind, ("text", "Other"))


def build_misp_event(data: dict, *, generated_at: datetime | None = None) -> dict:
    """Create a MISP 2.4-compatible event dict (not yet pushed)."""
    generated = generated_at or utcnow()
    investigation_id = str(data.get("report_id") or "unknown")
    seed = data.get("seed") or {}
    event_uuid = deterministic_uuid("misp-event", investigation_id)
    event_date = (iso(parse_timestamp(data.get("started_at")) or generated) or iso(generated) or "")[:10]
    timestamp = int(generated.timestamp())
    attributes: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for node in data.get("graph", {}).get("nodes", []):
        kind = str(node.get("type") or "unknown")
        value = str(node.get("normalized_value") or node.get("value") or "").strip()
        if not value:
            continue
        attr_type, category = _attribute_type(kind, value)
        key = (attr_type, value.lower())
        if key in seen:
            continue
        seen.add(key)
        confidence = float(node.get("path_confidence") or 0.0)
        attributes.append(
            {
                "uuid": deterministic_uuid("misp-attribute", investigation_id, attr_type, value),
                "type": attr_type,
                "category": category,
                "value": value,
                "to_ids": bool(not node.get("context_only") and confidence >= 0.25),
                "distribution": "5",
                "comment": (
                    f"PhishTrace {kind}; depth {node.get('depth', 0)}; "
                    f"path confidence {round(confidence, 3)}"
                    + ("; context-only stop-list node" if node.get("context_only") else "")
                )[:500],
                "timestamp": str(timestamp),
            }
        )

    # Keep the seed visible even if a provider never materialized a graph node.
    seed_value = str(seed.get("normalized") or seed.get("value") or "").strip()
    if seed_value:
        attr_type, category = _attribute_type(str(seed.get("type") or "unknown"), seed_value)
        if (attr_type, seed_value.lower()) not in seen:
            attributes.append(
                {
                    "uuid": deterministic_uuid("misp-attribute", investigation_id, "seed", seed_value),
                    "type": attr_type,
                    "category": category,
                    "value": seed_value,
                    "to_ids": False,
                    "distribution": "5",
                    "comment": "PhishTrace seed indicator; no provider edge was required.",
                    "timestamp": str(timestamp),
                }
            )

    return {
        "Event": {
            "uuid": event_uuid,
            "info": f"PhishTrace: {seed_value or investigation_id}",
            "date": event_date,
            "timestamp": str(timestamp),
            "published": False,
            "distribution": "0",
            "threat_level_id": "3",
            "analysis": "1",
            "Org": {"name": str(data.get("company") or "PhishTrace")},
            "Orgc": {"name": str(data.get("company") or "PhishTrace")},
            "Attribute": attributes,
            "Tag": [
                {"name": "PhishTrace"},
                {"name": f"tlp:{str(data.get('tlp') or 'clear').lower()}"},
                {"name": "phishing"},
            ],
            "EventReport": [
                {
                    "uuid": deterministic_uuid("misp-report", investigation_id),
                    "name": "PhishTrace assessment",
                    "content": (
                        f"Earliest observed: "
                        f"{(data.get('earliest_observed') or {}).get('occurred_at') or 'no dated event observed'}\n\n"
                        f"{data.get('coverage', {}).get('note', '')}\n\n"
                        + "\n".join(f"- {item}" for item in data.get("limitations", []))
                    )[:20000],
                    "distribution": "5",
                }
            ],
            "x_phishtrace": {
                "report_id": investigation_id,
                "generated_at": iso(generated),
                "coverage": {
                    "ran": len(data.get("coverage", {}).get("ran", [])),
                    "skipped": len(data.get("coverage", {}).get("skipped", [])),
                    "failed": len(data.get("coverage", {}).get("failed", [])),
                },
            },
        }
    }


def _misp_settings(settings: dict[str, Any]) -> dict[str, Any]:
    cfg = dict(settings or {})
    url = str(cfg.get("url") or "").strip().rstrip("/")
    if not url:
        raise IntegrationError("MISP is not configured: reports.misp.url is empty")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise IntegrationError("MISP URL must be an absolute http(s) URL")
    return cfg


async def push_misp(
    event: dict,
    settings: dict[str, Any],
    *,
    api_key: str | None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict:
    """Push an event to MISP.  Requires an explicit caller and configuration.

    TLS verification defaults to true.  The API key is sent only in the
    ``Authorization`` header and is never included in errors or returned data.
    """
    cfg = _misp_settings(settings)
    if not api_key:
        raise IntegrationError("MISP API key is not configured")
    url = f"{str(cfg['url']).rstrip('/')}/events"
    timeout = float(cfg.get("timeout") or 30)
    verify = bool(cfg.get("verify_tls", True))
    headers = {
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(verify=verify, timeout=timeout, transport=transport) as client:
            response = await client.post(url, headers=headers, json=event)
    except httpx.HTTPError as exc:
        raise IntegrationError(f"MISP request failed: {type(exc).__name__}") from exc
    if response.status_code >= 400:
        detail = response.text[:300].replace(api_key, "[REDACTED]")
        raise IntegrationError(f"MISP returned HTTP {response.status_code}: {detail}")
    try:
        payload = response.json()
    except ValueError:
        payload = {"raw": response.text[:500]}
    return {"status_code": response.status_code, "response": payload}
