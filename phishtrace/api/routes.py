"""Investigation API routes.

Read routes are available immediately; starting a run creates the investigation
row before handing the slow work to :class:`RunManager`, so the console can
subscribe to live progress without racing the worker thread.
"""

from __future__ import annotations

import asyncio
import io
import json
import threading
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from phishtrace.analyzers.kit import KitAnalyzer
from phishtrace.api.auth import require_csrf
from phishtrace.api.deps import current_user
from phishtrace.api.runs import TERMINAL_STATUSES, RunError
from phishtrace.core.timeline import TimelineMerger
from phishtrace.models import iso
from phishtrace.normalizer import normalize_indicator, refang
from phishtrace.reports import (
    MEDIA_TYPES,
    SUPPORTED_FORMATS,
    IntegrationError,
    build_abuse_package,
    build_misp_event,
    build_report_data,
    build_stix_bundle,
    canonical_format,
    push_misp,
    push_stix_bundle,
    render_json,
    render_report,
    report_filename,
)
from phishtrace.utils import to_jsonable

router = APIRouter(prefix="/api", tags=["investigations"])

#: Serializes "reuse or create" so two browsers cannot start the same seed twice.
_START_LOCK = threading.Lock()


class StartRequest(BaseModel):
    seed: str = Field(min_length=1, max_length=2048)
    kind: str | None = Field(default=None, max_length=32)
    run_sightings: bool = True
    reuse: bool = True


class KitRequest(BaseModel):
    url: str = Field(min_length=4, max_length=4096)
    force: bool = False
    verdict: str | None = Field(default=None, max_length=64)
    max_probes: int = Field(default=12, ge=0, le=50)


def _get_inv(request: Request, investigation_id: str) -> dict:
    inv = request.app.state.repo.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="investigation not found")
    return inv


def _owned_inv(request: Request, investigation_id: str, user: dict) -> dict:
    inv = _get_inv(request, investigation_id)
    if not user.get("is_admin") and inv.get("owner") != user.get("username"):
        raise HTTPException(status_code=403, detail="not your investigation")
    return inv


def _confined_evidence_path(request: Request, raw_path: str) -> Path:
    """Resolve a stored evidence path and require it under a managed directory.

    Evidence rows are written by the server, but treating the database as
    trusted would turn a tampered row (or a future provider bug) into arbitrary
    file read through the evidence endpoints. Symlinks are resolved first, so a
    link inside the evidence directory cannot point outside it either.
    """
    config = request.app.state.config
    try:
        path = Path(raw_path).resolve(strict=False)
    except (OSError, RuntimeError):
        raise HTTPException(status_code=404, detail="evidence not found")
    roots = (config.evidence_dir.resolve(), config.archive_dir.resolve())
    if not any(path.is_relative_to(root) for root in roots):
        raise HTTPException(status_code=404, detail="evidence not found")
    return path


def _progress_payload(request: Request, inv: dict, *, after: int = 0) -> dict:
    """Merge durable investigation state with the bounded live event buffer."""
    investigation_id = inv["id"]
    repo = request.app.state.repo
    manager = getattr(request.app.state, "runs", None)
    live = manager.snapshot(investigation_id, after=after) if manager else None
    counts = repo.counts(investigation_id)
    provider_runs = repo.list_provider_runs(investigation_id)
    coverage = inv.get("coverage") or {}
    summary = inv.get("summary") or {}
    status = inv.get("status")
    terminal = status in TERMINAL_STATUSES
    provider_counts = {"total": len(provider_runs)}
    for run in provider_runs:
        key = str(run.get("status") or "unknown")
        provider_counts[key] = provider_counts.get(key, 0) + 1
    events = list((live or {}).get("events") or [])
    return {
        "investigation_id": investigation_id,
        "seed": inv.get("seed"),
        "seed_type": inv.get("seed_type"),
        "seed_normalized": inv.get("seed_normalized"),
        "status": status,
        "terminal": terminal,
        "stage": (live or {}).get("stage") or ("done" if terminal else "queued"),
        "running": bool((live or {}).get("running")),
        "live_channel": live is not None,
        "elapsed_ms": int((live or {}).get("elapsed_ms") or 0),
        "counts": counts,
        "coverage": {
            "total": len(coverage.get("providers") or []),
            "ran": len(coverage.get("ran") or []),
            "skipped": len(coverage.get("skipped") or []),
            "failed": len(coverage.get("failed") or []),
        },
        "providers": provider_counts,
        "events": events,
        "cursor": int((live or {}).get("cursor") or 0),
        "dropped": int((live or {}).get("dropped") or 0),
        "summary": {
            "headline": summary.get("headline"),
            "timeline": summary.get("timeline") or {},
            "warnings": (summary.get("warnings") or [])[:20],
        },
        "error": inv.get("error") or (live or {}).get("error"),
        "started_at": inv.get("started_at"),
        "finished_at": inv.get("finished_at"),
    }


@router.get("/investigations")
def list_investigations(
    request: Request,
    user: dict = Depends(current_user),
    limit: int = Query(default=100, ge=1, le=500),
):
    repo = request.app.state.repo
    items = repo.list_investigations(limit=limit)
    if not user.get("is_admin"):
        items = [item for item in items if item.get("owner") == user.get("username")]
    return {"investigations": items, "count": len(items)}


@router.post("/investigations", status_code=202)
def start_investigation(
    request: Request,
    body: StartRequest,
    response: Response,
    user: dict = Depends(current_user),
):
    """Start a new investigation, or attach to an existing one for the same seed."""
    if request.app.state.config.auth.enabled:
        require_csrf(request)
    try:
        seed = normalize_indicator(
            body.seed,
            kind=body.kind,
            default_region=getattr(request.app.state.config, "default_region", None) or "US",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"invalid seed: {exc}"[:300]) from exc
    repo = request.app.state.repo
    manager = getattr(request.app.state, "runs", None)
    if manager is None:
        raise HTTPException(status_code=503, detail="run manager unavailable")
    with _START_LOCK:
        existing = repo.latest_for_seed(seed.normalized)
        if existing and body.reuse:
            if existing.get("status") in TERMINAL_STATUSES and existing.get("status") != "failed":
                response.status_code = 200
                return {
                    "reused": True,
                    "investigation_id": existing["id"],
                    "investigation": existing,
                    "status": existing.get("status"),
                    "counts": repo.counts(existing["id"]),
                }
            live = manager.snapshot(existing["id"])
            if existing.get("status") == "running" and live and live.get("running"):
                response.status_code = 200
                return {
                    "reused": True,
                    "already_running": True,
                    "investigation_id": existing["id"],
                    "investigation": existing,
                    "status": "running",
                    "counts": repo.counts(existing["id"]),
                }
        investigation = repo.create_investigation(
            seed=str(body.seed)[:2048],
            seed_type=seed.type,
            seed_normalized=seed.normalized,
            config_snapshot=request.app.state.config.redacted(),
            owner=user.get("username") or "web",
        )
        try:
            manager.start(investigation, seed, run_sightings=body.run_sightings)
        except RunError as exc:
            repo.delete_investigation(investigation["id"])
            raise HTTPException(status_code=429, detail=str(exc)) from exc
    return {
        "reused": False,
        "investigation_id": investigation["id"],
        "investigation": investigation,
        "status": "running",
        "seed": {"type": seed.type, "normalized": seed.normalized, "display": seed.display},
        "counts": repo.counts(investigation["id"]),
    }


@router.get("/investigations/{investigation_id}/progress")
def progress(
    request: Request,
    investigation_id: str,
    user: dict = Depends(current_user),
    after: int = Query(default=0, ge=0),
):
    inv = _owned_inv(request, investigation_id, user)
    return _progress_payload(request, inv, after=after)


@router.get("/investigations/{investigation_id}/progress/stream")
async def progress_stream(
    request: Request,
    investigation_id: str,
    user: dict = Depends(current_user),
):
    """Server-sent progress stream with a polling fallback at ``/progress``."""
    _owned_inv(request, investigation_id, user)

    async def frames():
        cursor = 0
        yield "retry: 3000\n\n"
        for _ in range(900):
            if await request.is_disconnected():
                return
            try:
                inv = _get_inv(request, investigation_id)
                payload = _progress_payload(request, inv, after=cursor)
            except HTTPException:
                yield "event: error\ndata: {\"detail\": \"investigation removed\"}\n\n"
                return
            yield f"event: progress\ndata: {json.dumps(to_jsonable(payload), ensure_ascii=False)}\n\n"
            cursor = payload["cursor"]
            if payload["terminal"]:
                yield f"event: end\ndata: {json.dumps({'status': payload['status'], 'investigation_id': investigation_id})}\n\n"
                return
            await asyncio.sleep(1.0)
        yield "event: timeout\ndata: {}\n\n"

    return StreamingResponse(
        frames(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/investigations/{investigation_id}")
def get_investigation(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    inv = _owned_inv(request, investigation_id, user)
    repo = request.app.state.repo
    return {**inv, "counts": repo.counts(investigation_id)}


@router.get("/investigations/{investigation_id}/graph")
def graph(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _owned_inv(request, investigation_id, user)
    return request.app.state.repo.graph(investigation_id)


@router.get("/investigations/{investigation_id}/sightings")
def sightings(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _owned_inv(request, investigation_id, user)
    repo = request.app.state.repo
    rows = repo.list_sightings(investigation_id)
    return {"sightings": rows, "count": len(rows)}


@router.get("/investigations/{investigation_id}/timeline")
def timeline(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _owned_inv(request, investigation_id, user)
    merged = TimelineMerger(request.app.state.repo, investigation_id).build()
    return {"timeline": merged.rows, "merged": merged.as_dict()}


@router.get("/investigations/{investigation_id}/coverage")
def coverage(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    inv = _owned_inv(request, investigation_id, user)
    return {
        "coverage": inv.get("coverage") or {},
        "providers": request.app.state.repo.list_provider_runs(investigation_id),
    }


@router.get("/investigations/{investigation_id}/evidence")
def evidence_list(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _owned_inv(request, investigation_id, user)
    rows = request.app.state.repo.list_evidence(investigation_id)
    return {"evidence": rows, "count": len(rows)}


@router.get("/investigations/{investigation_id}/evidence/{evidence_id}")
def evidence_detail(request: Request, investigation_id: str, evidence_id: str,
                    user: dict = Depends(current_user)):
    _owned_inv(request, investigation_id, user)
    row = request.app.state.repo.get_evidence(investigation_id, evidence_id)
    if not row:
        raise HTTPException(status_code=404, detail="evidence not found")
    repo = request.app.state.repo
    preview = ""
    if repo.evidence_store:
        try:
            preview = repo.evidence_store.read_text(str(_confined_evidence_path(request, row["raw_response_path"])), limit=100_000)
        except OSError:
            preview = "[evidence file missing]"
    return {**row, "preview": preview}


@router.get("/investigations/{investigation_id}/evidence/{evidence_id}/raw")
def evidence_raw(request: Request, investigation_id: str, evidence_id: str,
                 user: dict = Depends(current_user)):
    _owned_inv(request, investigation_id, user)
    row = request.app.state.repo.get_evidence(investigation_id, evidence_id)
    if not row:
        raise HTTPException(status_code=404, detail="evidence not found")
    path = _confined_evidence_path(request, row["raw_response_path"])
    if not path.exists():
        raise HTTPException(status_code=410, detail="evidence file purged")
    return FileResponse(
        path,
        media_type=row.get("content_type") or "application/octet-stream",
        filename=f"evidence-{evidence_id}-{row['sha256'][:12]}.bin",
    )


@router.get("/investigations/{investigation_id}/kits")
def kits(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _owned_inv(request, investigation_id, user)
    return {"kits": request.app.state.repo.list_kits(investigation_id)}


@router.post("/investigations/{investigation_id}/kit")
async def analyze_kit(
    request: Request,
    investigation_id: str,
    body: KitRequest,
    user: dict = Depends(current_user),
):
    """Analyze one confirmed phishing page with the isolated fetcher.

    The analyzer's own gate refuses to touch the network unless active fetching
    is enabled and the page is either confirmed hostile or explicitly forced.
    """
    if request.app.state.config.auth.enabled:
        require_csrf(request)
    _owned_inv(request, investigation_id, user)
    candidate = refang(body.url).strip()
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise HTTPException(status_code=422, detail="kit URL must be an absolute http(s) URL")
    repo = request.app.state.repo
    analyzer = KitAnalyzer(
        request.app.state.config,
        repo=repo,
        investigation_id=investigation_id,
    )
    try:
        report = await analyzer.analyze(
            candidate,
            force=body.force,
            verdict=body.verdict,
            persist=True,
            investigation_id=investigation_id,
            max_probes=body.max_probes,
        )
    finally:
        await analyzer.close()
    payload = report.as_dict()
    return {"kit": payload, "persisted": bool(report.kit_id), "skipped": report.skipped}


def _report_data(request: Request, investigation_id: str) -> dict:
    config = request.app.state.config
    return build_report_data(
        request.app.state.repo,
        investigation_id,
        settings=config.reports,
        default_region=config.default_region,
    )


@router.get("/investigations/{investigation_id}/reports")
def report_formats(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _owned_inv(request, investigation_id, user)
    return {
        "formats": [
            {
                "format": fmt,
                "media_type": MEDIA_TYPES.get(fmt),
                "url": f"/api/investigations/{investigation_id}/report?format={fmt}",
            }
            for fmt in SUPPORTED_FORMATS
        ],
        "abuse_url": f"/api/investigations/{investigation_id}/abuse?download=true",
    }


@router.get("/investigations/{investigation_id}/report")
def download_report(
    request: Request,
    investigation_id: str,
    user: dict = Depends(current_user),
    format: str = Query(default="html", max_length=16),
    inline: bool = Query(default=False),
):
    """Render one report format from durable records. No network access."""
    _owned_inv(request, investigation_id, user)
    try:
        fmt = canonical_format(format)
        data = _report_data(request, investigation_id)
        content = render_report(data, fmt)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - HTTP boundary; details stay server-side
        raise HTTPException(status_code=500, detail="report rendering failed") from exc
    filename = report_filename(data, fmt)
    disposition = "inline" if inline and fmt in {"html", "pdf", "txt", "md"} else "attachment"
    headers = {
        "Content-Disposition": f'{disposition}; filename="{filename}"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    if fmt == "html" and disposition == "inline":
        headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        )
    return Response(content=content, media_type=MEDIA_TYPES.get(fmt, "application/octet-stream"), headers=headers)


@router.get("/investigations/{investigation_id}/abuse")
def abuse_package(
    request: Request,
    investigation_id: str,
    user: dict = Depends(current_user),
    download: bool = Query(default=False),
):
    """Draft abuse notifications. Addresses come only from explicit config."""
    _owned_inv(request, investigation_id, user)
    config = request.app.state.config
    try:
        data = _report_data(request, investigation_id)
        package = build_abuse_package(data, config.reports, json_attachment=render_json(data))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail="abuse package generation failed") from exc
    public = {key: value for key, value in package.items() if not key.startswith("_")}
    if not download:
        return public
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for filename, raw in package.get("_email_bytes", {}).items():
            archive.writestr(filename, raw)
        archive.writestr("abuse-manifest.json", json.dumps(public, indent=2, ensure_ascii=False))
        archive.writestr("report.json", render_json(data))
    filename = f"phishtrace-abuse-{investigation_id[:24]}.zip"
    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


class ExportPushRequest(BaseModel):
    push: bool = False


@router.post("/investigations/{investigation_id}/export/misp")
async def export_misp(
    request: Request,
    investigation_id: str,
    body: ExportPushRequest,
    user: dict = Depends(current_user),
):
    _owned_inv(request, investigation_id, user)
    data = _report_data(request, investigation_id)
    event = build_misp_event(data)
    if not body.push:
        return {"pushed": False, "event": event, "note": "Draft only. Set push=true to send it to the configured MISP."}
    if request.app.state.config.auth.enabled:
        require_csrf(request)
    settings = request.app.state.config.reports.misp
    if not settings.get("enabled"):
        raise HTTPException(status_code=409, detail="MISP push is disabled in reports.misp.enabled")
    api_key = request.app.state.config.api_key(str(settings.get("key_env") or "MISP_API_KEY"))
    try:
        result = await push_misp(event, settings, api_key=api_key)
    except IntegrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"pushed": True, "event_uuid": event["Event"]["uuid"], "result": result}


@router.post("/investigations/{investigation_id}/export/opencti")
async def export_opencti(
    request: Request,
    investigation_id: str,
    body: ExportPushRequest,
    user: dict = Depends(current_user),
):
    _owned_inv(request, investigation_id, user)
    data = _report_data(request, investigation_id)
    bundle = build_stix_bundle(data)
    if not body.push:
        return {"pushed": False, "bundle": bundle, "note": "Draft only. Set push=true to send it to the configured OpenCTI."}
    if request.app.state.config.auth.enabled:
        require_csrf(request)
    settings = request.app.state.config.reports.opencti
    if not settings.get("enabled"):
        raise HTTPException(status_code=409, detail="OpenCTI push is disabled in reports.opencti.enabled")
    token = request.app.state.config.api_key(str(settings.get("token_env") or "OPENCTI_TOKEN"))
    try:
        result = await push_stix_bundle(bundle, settings, token=token)
    except IntegrationError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"pushed": True, "bundle_id": bundle["id"], "result": result}


@router.get("/stats")
def stats(request: Request, user: dict = Depends(current_user)):
    repo = request.app.state.repo
    investigations = repo.list_investigations(limit=500)
    return {
        "investigations": len(investigations),
        "running": sum(1 for i in investigations if inv_status(i) == "running"),
        "completed": sum(1 for i in investigations if inv_status(i) == "completed"),
        "failed": sum(1 for i in investigations if inv_status(i) == "failed"),
        "generated_at": iso(datetime.now(timezone.utc)),
    }


def inv_status(item: dict) -> str:
    return str(item.get("status") or "")
