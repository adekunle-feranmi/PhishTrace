"""Assemble a single, de-duplicated report context from durable records.

The renderers never query the database or the network.  They receive a plain
JSON-safe dict from this module, which keeps HTML, PDF, STIX, MISP, JSON and
CSV output consistent and makes the reporting layer straightforward to test.

Nothing in this module reads ``config.env``.  Only the explicitly selected
report settings and the already-redacted investigation snapshot are exposed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Iterable

from phishtrace import __version__
from phishtrace.config import ReportConfig
from phishtrace.core.roles import ROLE_LABELS
from phishtrace.core.timeline import TimelineMerger
from phishtrace.models import iso, utcnow
from phishtrace.utils import slugify, to_jsonable

STATUS_ORDER = {"ran": 0, "enabled": 1, "skipped": 2, "failed": 3}
MEDIA_TYPES = {
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "json": "application/json",
    "stix": "application/json",
    "stix2": "application/json",
    "misp": "application/json",
    "md": "text/markdown; charset=utf-8",
    "markdown": "text/markdown; charset=utf-8",
    "txt": "text/plain; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
}
EXTENSIONS = {
    "html": "html",
    "pdf": "pdf",
    "json": "json",
    "stix": "stix.json",
    "stix2": "stix.json",
    "misp": "misp.json",
    "md": "md",
    "markdown": "md",
    "txt": "txt",
    "csv": "csv",
}


class ReportNotFound(LookupError):
    """The investigation does not exist (or was purged)."""


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _node_label(node: dict) -> str:
    return str(node.get("value") or node.get("normalized_value") or "")


def _provider_rows(export: dict) -> list[dict]:
    """Merge static availability with per-run outcomes.

    A provider is never hidden because it was unavailable.  If the run recorded
    a status it wins; otherwise the static coverage block is used.  This is the
    data behind the mandatory Coverage section.
    """
    coverage = export.get("investigation", {}).get("coverage") or {}
    static = {str(row.get("name") or row.get("provider")): dict(row) for row in _as_list(coverage.get("providers")) if (row.get("name") or row.get("provider"))}
    runs = {str(row.get("provider")): dict(row) for row in _as_list(export.get("provider_runs")) if row.get("provider")}

    ran_names = {str(name) for name in _as_list(coverage.get("ran"))}
    skipped_names = {str(name) for name in _as_list(coverage.get("skipped"))}
    failed_names = {str(name) for name in _as_list(coverage.get("failed"))}

    rows: list[dict] = []
    for name in sorted(set(static) | set(runs)):
        row = static.get(name, {})
        run = runs.get(name, {})
        reason = run.get("reason") or row.get("reason") or row.get("error")
        errors = _as_list(run.get("errors"))
        if errors and not reason:
            reason = str(errors[0])
        status = str(run.get("status") or row.get("status") or "unknown").lower()
        # The run's own coverage lists are authoritative: a provider can ship
        # with ``enabled`` as its static status and still have been skipped.
        if name in ran_names:
            status = "ran"
        elif name in skipped_names:
            status = "skipped"
        elif name in failed_names:
            status = "failed"
        elif status in {"enabled", "unknown"}:
            declared = status
            if run.get("requests") or run.get("observations"):
                status = "ran"
            else:
                status = "skipped"
                reason = reason or (
                    "provider was available but the run recorded no request for it"
                    if declared == "enabled" else "no status was recorded for this provider"
                )
        rows.append(
            {
                "provider": name,
                "category": run.get("category") or row.get("category") or "",
                "phase": row.get("phase") or "A",
                "status": status,
                "reason": reason,
                "requests": int(run.get("requests") or row.get("requests") or 0),
                "observations": int(run.get("observations") or row.get("observations") or 0),
                "sightings": int(run.get("sightings") or row.get("sightings") or 0),
                "duration_ms": int(run.get("duration_ms") or row.get("duration_ms") or 0),
                "errors": errors,
            }
        )
    rows.sort(key=lambda r: (STATUS_ORDER.get(r["status"], 4), r["provider"]))
    return rows


def _coverage_summary(rows: Iterable[dict]) -> dict:
    rows = list(rows)
    return {
        "total": len(rows),
        "ran": [r["provider"] for r in rows if r["status"] in {"ran", "enabled"}],
        "skipped": [r["provider"] for r in rows if r["status"] == "skipped"],
        "failed": [r["provider"] for r in rows if r["status"] == "failed"],
        "note": (
            "Coverage records what was attempted, not what exists. A skipped provider "
            "means its selectors, key or capability were unavailable; it does not mean "
            "the provider found nothing."
        ),
    }


def _enrich_edges(graph: dict) -> list[dict]:
    nodes = {str(n.get("id")): n for n in _as_list(graph.get("nodes"))}
    edges: list[dict] = []
    for edge in _as_list(graph.get("edges")):
        item = dict(edge)
        src = nodes.get(str(edge.get("src")), {})
        dst = nodes.get(str(edge.get("dst")), {})
        item["src_value"] = edge.get("src_value") or _node_label(src)
        item["dst_value"] = edge.get("dst_value") or _node_label(dst)
        item["src_type"] = edge.get("src_type") or src.get("type")
        item["dst_type"] = edge.get("dst_type") or dst.get("type")
        item["confidence"] = round(float(item.get("confidence") or 0.0), 3)
        edges.append(to_jsonable(item))
    edges.sort(key=lambda e: (-(e.get("confidence") or 0), str(e.get("provider") or ""), str(e.get("relation") or "")))
    return edges


def _country(seed: dict, nodes: list[dict], default_region: str | None) -> tuple[str | None, str]:
    """Best-effort ISO-3166 alpha-2 lens for CERT selection.

    A contact selector (a phone number's region tag) describes where the actor
    is reachable; hosting/registrar metadata only describes where a box or a
    contract sits.  The contact signal therefore wins, then the metadata, then
    the operator's default.  Only alpha-2 codes are accepted because that is
    what the CERT contact map is keyed by.
    """

    def _region_from_tags(tags: Any) -> str | None:
        for tag in _as_list(tags):
            text = str(tag).lower()
            if text.startswith("region-") and len(text) == 9:
                return text.split("-", 1)[1].upper()
        return None

    region_tag = _region_from_tags(seed.get("tags"))
    if region_tag:
        return region_tag, "seed region tag"
    for node in nodes:
        if node.get("context_only"):
            continue
        region_tag = _region_from_tags(node.get("tags"))
        if region_tag:
            kind = str(node.get("type") or "indicator").lower()
            source = "phone number region" if kind == "phone" else f"region tag on {kind}"
            return region_tag, source
    for node in nodes:
        if node.get("context_only"):
            continue
        meta = node.get("meta") or {}
        value = str(meta.get("country") or "").strip()
        if len(value) == 2 and value.isalpha():
            return value.upper(), f"provider metadata on {node.get('type') or 'indicator'}"
    region = (default_region or "").strip().upper()
    if len(region) == 2 and region.isalpha():
        return region, "configured default region"
    return None, "unknown"


def _roles(sightings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for sighting in sightings:
        role = str(sighting.get("role") or "unknown")
        counts[role] = counts.get(role, 0) + 1
    return {
        "counts": counts,
        "labels": {role: ROLE_LABELS.get(role, role.replace("_", " ").title()) for role in counts},
        "note": "Roles are behavioural leads, not identification of a person.",
    }


def _sighting_view(sighting: dict) -> dict:
    item = dict(sighting)
    role = str(item.get("role") or "unknown")
    item["role_label"] = ROLE_LABELS.get(role, role.replace("_", " ").title())
    item.pop("dedupe_key", None)
    return to_jsonable(item)


def _evidence_view(evidence: dict) -> dict:
    item = dict(evidence)
    # Raw paths are server implementation details and may contain a username.
    item.pop("raw_response_path", None)
    item.pop("dedupe_key", None)
    item["download_ref"] = item.get("id")
    return to_jsonable(item)


def _kit_view(kit: dict) -> dict:
    item = dict(kit)
    item.pop("investigation_id", None)
    return to_jsonable(item)


def _safe_config_snapshot(export: dict, settings: ReportConfig) -> dict:
    snapshot = export.get("investigation", {}).get("config_snapshot") or {}
    return {
        "default_region": snapshot.get("default_region"),
        "retention_days": snapshot.get("retention_days"),
        "reports": {
            "company": settings.company,
            "tlp": settings.tlp,
            "abuse_contacts_configured": sorted(settings.abuse_contacts),
            "cert_contacts_configured": sorted(settings.cert_contacts),
        },
        "tool_version": __version__,
    }


def build_report_data(
    repo,
    investigation_id: str,
    *,
    settings: ReportConfig | None = None,
    default_region: str | None = "US",
    generated_at: datetime | None = None,
    gap_days: int = 90,
) -> dict:
    """Return a JSON-safe report context or raise :class:`ReportNotFound`."""
    export = repo.full_export(investigation_id)
    if not export or not export.get("investigation"):
        raise ReportNotFound(f"investigation {investigation_id!r} was not found")
    settings = settings or ReportConfig()
    generated = generated_at or utcnow()

    inv = export["investigation"]
    graph = export.get("graph") or {"nodes": [], "edges": []}
    nodes = [to_jsonable(n) for n in _as_list(graph.get("nodes"))]
    edges = _enrich_edges(graph)
    timeline = TimelineMerger(repo, investigation_id).build(gap_days=gap_days)
    timeline_data = to_jsonable(timeline.as_dict())
    sightings = [_sighting_view(s) for s in _as_list(export.get("sightings"))]
    evidence = [_evidence_view(e) for e in _as_list(export.get("evidence"))]
    kits = [_kit_view(k) for k in _as_list(export.get("kits"))]
    provider_rows = _provider_rows(export)
    coverage = _coverage_summary(provider_rows)
    seed = dict(inv.get("summary", {}).get("seed") or {})
    if not seed:
        seed = {
            "value": inv.get("seed"),
            "type": inv.get("seed_type"),
            "normalized": inv.get("seed_normalized"),
        }
    seed = to_jsonable(seed)
    country, country_source = _country(seed, nodes, default_region)
    counts = dict(export.get("counts") or {})
    counts.setdefault("sightings", len(sightings))
    counts.setdefault("events", len(timeline_data.get("events") or []))
    counts.setdefault("evidence", len(evidence))
    counts.setdefault("kits", len(kits))

    summary = inv.get("summary") or {}
    warnings = [str(w) for w in _as_list(summary.get("warnings"))]
    if timeline_data.get("coverage", {}).get("stages_missing"):
        warnings.append(
            "Timeline stages without a dated event: "
            + ", ".join(timeline_data["coverage"]["stages_missing"])
        )

    earliest = timeline_data.get("earliest_observed")
    stage_earliest = {
        stage: bucket.get("earliest_observed")
        for stage, bucket in (timeline_data.get("stages") or {}).items()
        if bucket.get("earliest_observed")
    }
    top_edges = edges[:12]
    kit_flags = []
    for kit in kits:
        bits = []
        if kit.get("credential_exposure_count"):
            bits.append(f"{kit['credential_exposure_count']} exposed credential artifact(s)")
        if kit.get("exfil_emails"):
            bits.append(f"{len(kit['exfil_emails'])} exfiltration email(s)")
        if kit.get("telegram_bots"):
            bits.append(f"{len(kit['telegram_bots'])} Telegram bot(s)")
        if bits:
            kit_flags.append({"url": kit.get("url"), "flags": bits})

    data = {
        "schema": "phishtrace.report/1",
        "report_id": str(inv.get("id") or investigation_id),
        "generated_at": iso(generated),
        "company": settings.company,
        "tlp": settings.tlp,
        "tool": {"name": "PhishTrace", "version": __version__},
        "investigation": to_jsonable(inv),
        "seed": seed,
        "country": {"code": country, "source": country_source},
        "counts": counts,
        "headline": summary.get("headline") or "",
        "status": inv.get("status") or "unknown",
        "owner": inv.get("owner") or "cli",
        "started_at": iso(inv.get("started_at")),
        "finished_at": iso(inv.get("finished_at")),
        "duration_ms": summary.get("duration_ms") or (inv.get("stats") or {}).get("duration_ms"),
        "graph": {"nodes": nodes, "edges": edges},
        "top_edges": top_edges,
        "timeline": timeline_data,
        "earliest_observed": earliest,
        "stage_earliest": stage_earliest,
        "sightings": sightings,
        "roles": _roles(sightings),
        "evidence": evidence,
        "kits": kits,
        "kit_flags": kit_flags,
        "coverage": {"rows": provider_rows, **coverage},
        "warnings": warnings,
        "stoplist_hits": summary.get("stoplist_hits") or (inv.get("stats") or {}).get("stoplist_hits") or 0,
        "truncated": bool(summary.get("truncated") or (inv.get("stats") or {}).get("truncated")),
        "limitations": [
            "All dates are the earliest observation PhishTrace could verify from covered sources; absence is not proof that activity did not occur.",
            "A graph edge records a provider observation with its own confidence. It is not an attribution to a person or organisation.",
            "Social roles are behavioural classifications, not identifications. No private account data is collected.",
            "Provider coverage and skipped reasons are listed in every report; unavailable sources can change the picture.",
            "This report is defensive intelligence. It does not assert criminal liability or ownership of infrastructure.",
        ],
        "config": _safe_config_snapshot(export, settings),
        "cert_contact": settings.cert_contacts.get(country) if country else None,
    }
    return to_jsonable(data)


def report_filename(data: dict, fmt: str) -> str:
    """Safe, deterministic attachment name with no user-controlled extension."""
    seed = data.get("seed") or {}
    host = slugify(str(seed.get("normalized") or seed.get("value") or "seed"), 48)
    report_id = str(data.get("report_id") or "report")[:32]
    extension = EXTENSIONS.get(fmt, slugify(fmt, 12) or "bin")
    return f"phishtrace-{host}-{report_id}.{extension}"


def deterministic_uuid(namespace: str, *parts: Any) -> str:
    joined = "\x1f".join(str(part) for part in parts)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://phishtrace.local/{namespace}/{joined}"))
