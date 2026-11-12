"""Investigation API routes.

Read routes are available immediately; the run/export routes are wired to the
orchestrator as it comes online.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse

from phishtrace.api.deps import current_user
from phishtrace.models import iso

router = APIRouter(prefix="/api", tags=["investigations"])


def _get_inv(request: Request, investigation_id: str) -> dict:
    inv = request.app.state.repo.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(status_code=404, detail="investigation not found")
    return inv


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


@router.get("/investigations/{investigation_id}")
def get_investigation(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    inv = _get_inv(request, investigation_id)
    if not user.get("is_admin") and inv.get("owner") != user.get("username"):
        raise HTTPException(status_code=403, detail="not your investigation")
    repo = request.app.state.repo
    return {**inv, "counts": repo.counts(investigation_id)}


@router.get("/investigations/{investigation_id}/graph")
def graph(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _get_inv(request, investigation_id)
    return request.app.state.repo.graph(investigation_id)


@router.get("/investigations/{investigation_id}/sightings")
def sightings(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _get_inv(request, investigation_id)
    repo = request.app.state.repo
    rows = repo.list_sightings(investigation_id)
    return {"sightings": rows, "count": len(rows)}


@router.get("/investigations/{investigation_id}/timeline")
def timeline(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _get_inv(request, investigation_id)
    return {"timeline": request.app.state.repo.list_timeline(investigation_id)}


@router.get("/investigations/{investigation_id}/coverage")
def coverage(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    inv = _get_inv(request, investigation_id)
    return {
        "coverage": inv.get("coverage") or {},
        "providers": request.app.state.repo.list_provider_runs(investigation_id),
    }


@router.get("/investigations/{investigation_id}/evidence")
def evidence_list(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _get_inv(request, investigation_id)
    rows = request.app.state.repo.list_evidence(investigation_id)
    return {"evidence": rows, "count": len(rows)}


@router.get("/investigations/{investigation_id}/evidence/{evidence_id}")
def evidence_detail(request: Request, investigation_id: str, evidence_id: str,
                    user: dict = Depends(current_user)):
    _get_inv(request, investigation_id)
    row = request.app.state.repo.get_evidence(investigation_id, evidence_id)
    if not row:
        raise HTTPException(status_code=404, detail="evidence not found")
    repo = request.app.state.repo
    preview = ""
    if repo.evidence_store:
        try:
            preview = repo.evidence_store.read_text(row["raw_response_path"], limit=100_000)
        except OSError:
            preview = "[evidence file missing]"
    return {**row, "preview": preview}


@router.get("/investigations/{investigation_id}/evidence/{evidence_id}/raw")
def evidence_raw(request: Request, investigation_id: str, evidence_id: str,
                 user: dict = Depends(current_user)):
    _get_inv(request, investigation_id)
    row = request.app.state.repo.get_evidence(investigation_id, evidence_id)
    if not row:
        raise HTTPException(status_code=404, detail="evidence not found")
    path = Path(row["raw_response_path"])
    if not path.exists():
        raise HTTPException(status_code=410, detail="evidence file purged")
    return FileResponse(
        path,
        media_type=row.get("content_type") or "application/octet-stream",
        filename=f"evidence-{evidence_id}-{row['sha256'][:12]}.bin",
    )


@router.get("/investigations/{investigation_id}/kits")
def kits(request: Request, investigation_id: str, user: dict = Depends(current_user)):
    _get_inv(request, investigation_id)
    return {"kits": request.app.state.repo.list_kits(investigation_id)}


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
