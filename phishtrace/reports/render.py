"""Render report contexts to HTML, PDF, JSON, STIX, MISP, Markdown, text and CSV."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit
from xml.sax.saxutils import escape as xml_escape

from jinja2 import Environment, PackageLoader, select_autoescape

from phishtrace.models import iso, utcnow
from phishtrace.reports.context import (
    MEDIA_TYPES,
    ReportNotFound,
    build_report_data,
    report_filename,
)
from phishtrace.reports.misp import build_misp_event
from phishtrace.reports.stix import build_stix_bundle

_FORMAT_ALIASES = {
    "markdown": "md",
    "stix2": "stix",
    "stix21": "stix",
    "text": "txt",
    "yaml": None,
}
SUPPORTED_FORMATS = ("html", "pdf", "json", "stix", "misp", "md", "txt", "csv")


def canonical_format(fmt: str) -> str:
    value = (fmt or "").strip().lower()
    value = _FORMAT_ALIASES.get(value, value)
    if value not in SUPPORTED_FORMATS:
        raise ValueError(f"unsupported report format {fmt!r}; choose from {', '.join(SUPPORTED_FORMATS)}")
    return value


def safe_url(value: Any) -> str:
    """Allow only absolute http(s) links in rendered reports."""
    text = str(value or "").strip()
    try:
        parsed = urlsplit(text)
    except ValueError:
        return "#"
    if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
        return text
    return "#"


def _env(autoescape: bool = True) -> Environment:
    env = Environment(
        loader=PackageLoader("phishtrace.reports", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "xml"), default=autoescape),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["safe_url"] = safe_url
    return env


def render_html(data: dict) -> bytes:
    template = _env().get_template("report.html.j2")
    return template.render(data=data).encode("utf-8")


def render_markdown(data: dict) -> bytes:
    # Markdown is escaped as HTML first; values are untrusted provider data.
    template = _env(autoescape=True).get_template("report.md.j2")
    return template.render(data=data).encode("utf-8")


def render_json(data: dict) -> bytes:
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False).encode("utf-8")


def render_stix(data: dict, *, generated_at: datetime | None = None) -> bytes:
    bundle = build_stix_bundle(data, generated_at=generated_at)
    return json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8")


def render_misp(data: dict, *, generated_at: datetime | None = None) -> bytes:
    event = build_misp_event(data, generated_at=generated_at)
    return json.dumps(event, indent=2, ensure_ascii=False).encode("utf-8")


def _txt_rows(data: dict) -> list[str]:
    seed = data.get("seed") or {}
    earliest = data.get("earliest_observed") or {}
    lines = [
        f"{data.get('company')} — PhishTrace investigation report",
        "=" * 78,
        f"Seed          : {seed.get('normalized') or seed.get('value') or 'unknown'}",
        f"Seed type     : {seed.get('type') or 'unknown'}",
        f"Investigation : {data.get('report_id')}",
        f"Status        : {data.get('status')} ({data.get('owner')})",
        f"Generated     : {data.get('generated_at')}",
        f"TLP           : {data.get('tlp')}",
        f"Region lens   : {(data.get('country') or {}).get('code') or 'not established'}",
        "",
        "EXECUTIVE SUMMARY",
        "-" * 78,
        str(data.get("headline") or ""),
        "",
        (
            f"Earliest observed: {earliest.get('occurred_at')} — {earliest.get('label') or earliest.get('stage')} "
            f"({earliest.get('stage')}, precision {earliest.get('precision')})"
            if earliest
            else "Earliest observed: no dated event was observed in covered sources. This is not evidence of no activity."
        ),
        "",
        "COUNTS",
        "-" * 78,
    ]
    counts = data.get("counts") or {}
    for key in ("indicators", "edges", "sightings", "evidence", "kits"):
        lines.append(f"{key.capitalize():<14}: {counts.get(key, 0)}")
    lines.append(f"Timeline events: {len((data.get('timeline') or {}).get('events') or [])}")
    lines.extend(["", "PROVIDER COVERAGE (MANDATORY)", "-" * 78, str((data.get("coverage") or {}).get("note") or "")])
    for row in (data.get("coverage") or {}).get("rows") or []:
        lines.append(
            f"{row.get('provider')}: {row.get('status')} — requests {row.get('requests', 0)}, "
            f"observations {row.get('observations', 0)}"
            + (f" — {row.get('reason')}" if row.get("reason") else "")
        )
    if not (data.get("coverage") or {}).get("rows"):
        lines.append("No provider coverage was recorded; absence of findings cannot be concluded.")
    lines.extend(["", "EARLIEST OBSERVED TIMELINE", "-" * 78])
    for row in (data.get("timeline") or {}).get("events") or []:
        lines.append(
            f"{row.get('occurred_at')}  {row.get('stage'):<12} {row.get('label')}"
            + (f" — {row.get('detail')}" if row.get("detail") else "")
        )
    if not (data.get("timeline") or {}).get("events"):
        lines.append("No dated events were observed.")
    lines.extend(["", "TOP GRAPH EDGES", "-" * 78])
    for edge in data.get("top_edges") or []:
        lines.append(
            f"{edge.get('src_type')}:{edge.get('src_value')} --{edge.get('relation')}--> "
            f"{edge.get('dst_type')}:{edge.get('dst_value')} [{edge.get('provider')}, "
            f"confidence {edge.get('confidence')}, evidence {edge.get('evidence_id') or '—'}]"
        )
    if not data.get("top_edges"):
        lines.append("No graph edges were materialized.")
    lines.extend(["", "SIGHTINGS", "-" * 78])
    for sighting in data.get("sightings") or []:
        lines.append(
            f"{sighting.get('posted_at') or 'unknown'} {sighting.get('platform')} "
            f"{sighting.get('author_handle') or 'unknown'} [{sighting.get('role_label')}]: "
            f"{sighting.get('text_excerpt')}"
        )
    if not data.get("sightings"):
        lines.append("No public sightings matched covered selectors.")
    lines.extend(["", "ASSESSMENT LIMITATIONS", "-" * 78])
    lines.extend(f"- {item}" for item in data.get("limitations") or [])
    lines.extend(["", f"{data.get('company')} · PhishTrace · {data.get('generated_at')} · {data.get('report_id')}"])
    return lines


def render_text(data: dict) -> bytes:
    return ("\n".join(_txt_rows(data)) + "\n").encode("utf-8")


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    # Prevent spreadsheet formula execution when an operator opens the export.
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        text = "'" + text
    return text


def render_csv(data: dict) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=["section", "type", "key", "value", "detail", "source", "confidence", "occurred_at", "url"],
        extrasaction="ignore",
    )
    writer.writeheader()

    def row(section: str, **kwargs: Any) -> None:
        writer.writerow({key: _csv_safe(value) for key, value in {"section": section, **kwargs}.items()})

    seed = data.get("seed") or {}
    row("investigation", type=seed.get("type"), key="seed", value=seed.get("normalized") or seed.get("value"),
        detail=data.get("headline"), occurred_at=data.get("started_at"), url="")
    row("investigation", type="status", key="status", value=data.get("status"), detail=data.get("report_id"),
        occurred_at=data.get("finished_at"), url="")
    for row_data in (data.get("coverage") or {}).get("rows") or []:
        row("coverage", type="provider", key=row_data.get("provider"), value=row_data.get("status"),
            detail=row_data.get("reason"), source=row_data.get("category"), confidence=row_data.get("duration_ms"))
    for node in (data.get("graph") or {}).get("nodes") or []:
        row("indicator", type=node.get("type"), key=node.get("id"), value=node.get("value"),
            detail=", ".join(node.get("tags") or []), confidence=node.get("path_confidence"),
            occurred_at=node.get("first_seen_in_run"), url="")
    for edge in (data.get("graph") or {}).get("edges") or []:
        row("edge", type=edge.get("relation"), key=edge.get("id"), value=edge.get("dst_value"),
            detail=f"{edge.get('src_value')} -> {edge.get('dst_value')}", source=edge.get("provider"),
            confidence=edge.get("confidence"), occurred_at=edge.get("observed_at"), url="")
    for event in (data.get("timeline") or {}).get("events") or []:
        row("timeline", type=event.get("stage"), key=event.get("kind") or "event", value=event.get("label"),
            detail=event.get("detail"), source=", ".join(event.get("sources") or []),
            occurred_at=event.get("occurred_at"), url=event.get("url"))
    for sighting in data.get("sightings") or []:
        row("sighting", type=sighting.get("role"), key=sighting.get("id"), value=sighting.get("post_url"),
            detail=sighting.get("text_excerpt"), source=sighting.get("platform"), occurred_at=sighting.get("posted_at"),
            url=sighting.get("post_url"))
    for capture in data.get("evidence") or []:
        row("evidence", type=capture.get("provider"), key=capture.get("id"), value=capture.get("sha256"),
            detail=capture.get("content_type"), source=capture.get("url"),
            occurred_at=capture.get("retrieved_at"), url=capture.get("url"))
    for kit in data.get("kits") or []:
        row("kit", type="kit", key=kit.get("id"), value=kit.get("url"),
            detail=kit.get("brand") or kit.get("notes"), source="kit_analyzer",
            confidence=kit.get("credential_exposure_count"), occurred_at=kit.get("created_at"), url=kit.get("url"))
    return ("\ufeff" + buffer.getvalue()).encode("utf-8")


def _register_pdf_font() -> str:
    """Register a Unicode-capable TTF when available; otherwise use Helvetica."""
    candidates = [
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    ]
    try:
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        for path in candidates:
            if Path(path).exists():
                pdfmetrics.registerFont(TTFont("PhishTraceSans", path))
                return "PhishTraceSans"
    except Exception:  # noqa: BLE001 - PDF must not break other formats
        pass
    return "Helvetica"


def _pdf_text(value: Any, limit: int = 4000) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return xml_escape(text)


def render_pdf(data: dict) -> bytes:
    """Create a compact, print-ready PDF without external services."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - dependency path
        raise RuntimeError("PDF generation requires reportlab") from exc

    font = _register_pdf_font()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=16 * mm,
        title=f"{data.get('company')} report {data.get('report_id')}",
        author=str(data.get("company") or "PhishTrace"),
        subject="Defensive phishing infrastructure investigation",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="PTTitle", parent=styles["Title"], fontName=font, fontSize=17, leading=21, spaceAfter=5))
    styles.add(ParagraphStyle(name="PTH", parent=styles["Heading2"], fontName=font, fontSize=12, leading=15, spaceBefore=9, spaceAfter=4))
    styles.add(ParagraphStyle(name="PT", parent=styles["BodyText"], fontName=font, fontSize=8.5, leading=11))
    styles.add(ParagraphStyle(name="PTSmall", parent=styles["BodyText"], fontName=font, fontSize=7, leading=9, textColor=colors.HexColor("#555555")))
    styles.add(ParagraphStyle(name="PTCell", parent=styles["BodyText"], fontName=font, fontSize=6.5, leading=8))
    styles.add(ParagraphStyle(name="PTCellSmall", parent=styles["BodyText"], fontName=font, fontSize=5.8, leading=7))

    story: list[Any] = []
    seed = data.get("seed") or {}
    story.append(Paragraph("PhishTrace investigation report", styles["PTTitle"]))
    story.append(Paragraph(_pdf_text(seed.get("normalized") or seed.get("value") or data.get("report_id")), styles["PT"]))
    story.append(Paragraph(
        _pdf_text(
            f"TLP:{data.get('tlp')} · report {data.get('report_id')} · generated {data.get('generated_at')} · "
            f"status {data.get('status')} · owner {data.get('owner')}"
        ),
        styles["PTSmall"],
    ))
    story.append(Spacer(1, 5))

    def section(title: str) -> None:
        story.append(Paragraph(_pdf_text(title), styles["PTH"]))

    def para(text: Any, style: str = "PT") -> None:
        story.append(Paragraph(_pdf_text(text), styles[style]))

    def table(headers: list[str], rows: Iterable[list[Any]], widths: list[float] | None = None) -> None:
        table_data = [[Paragraph(_pdf_text(h), styles["PTCell"]) for h in headers]]
        for row in rows:
            table_data.append([Paragraph(_pdf_text(cell, 800), styles["PTCellSmall"]) for cell in row])
        if len(table_data) == 1:
            return
        widget = Table(table_data, colWidths=widths, repeatRows=1)
        widget.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef3fa")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd6e2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 2),
            ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        story.append(widget)

    section("Executive summary")
    if data.get("headline"):
        para(data["headline"])
    earliest = data.get("earliest_observed") or {}
    if earliest:
        para(
            f"Earliest observed: {earliest.get('occurred_at')} — {earliest.get('label') or earliest.get('stage')} "
            f"({earliest.get('stage')}, precision {earliest.get('precision')}, "
            f"sources {', '.join(earliest.get('sources') or []) or 'unspecified'}). "
            "This is the earliest dated observation in covered sources, not proof of first activity."
        )
    else:
        para("Earliest observed: no dated event was observed in covered sources. This is not evidence that the activity did not occur.")
    counts = data.get("counts") or {}
    table(
        ["Indicators", "Edges", "Timeline events", "Sightings", "Captures"],
        [[counts.get("indicators", 0), counts.get("edges", 0), len((data.get("timeline") or {}).get("events") or []), counts.get("sightings", 0), counts.get("evidence", 0)]],
    )
    coverage = data.get("coverage") or {}
    para(
        f"Coverage: {len(coverage.get('ran') or [])} providers ran, "
        f"{len(coverage.get('skipped') or [])} skipped, {len(coverage.get('failed') or [])} failed. "
        f"{coverage.get('note') or ''}",
        "PTSmall",
    )

    section("Earliest observed timeline")
    timeline_rows = []
    for row in (data.get("timeline") or {}).get("events") or []:
        timeline_rows.append([
            row.get("occurred_at"), row.get("stage"), row.get("label"),
            row.get("detail") or row.get("indicator_value"), ", ".join(row.get("sources") or []), row.get("precision"),
        ])
    table(["Occurred (UTC)", "Stage", "Observation", "Detail", "Sources", "Precision"], timeline_rows,
          widths=[25 * mm, 22 * mm, 45 * mm, 55 * mm, 24 * mm, 16 * mm])
    if not timeline_rows:
        para("No dated events were observed. Absence from covered sources is not proof of no activity.")

    section("Top graph edges")
    edge_rows = []
    for edge in data.get("top_edges") or []:
        edge_rows.append([
            f"{edge.get('src_type')}: {edge.get('src_value')}", edge.get("relation"), f"{edge.get('dst_type')}: {edge.get('dst_value')}",
            edge.get("provider"), edge.get("selector_strength"), f"{edge.get('confidence')}",
            edge.get("evidence_id") or "—",
        ])
    table(["From", "Relation", "To", "Provider", "Strength", "Conf.", "Evidence"], edge_rows,
          widths=[45 * mm, 22 * mm, 45 * mm, 23 * mm, 16 * mm, 12 * mm, 22 * mm])
    if not edge_rows:
        para("No graph edges were materialized; no covered provider returned an observation in this run.")

    section("Public sightings")
    sighting_rows = [
        [row.get("posted_at"), row.get("platform"), row.get("author_handle"), row.get("role_label"), row.get("text_excerpt")]
        for row in data.get("sightings") or []
    ]
    table(["Posted", "Platform", "Author", "Role", "Excerpt"], sighting_rows,
          widths=[28 * mm, 22 * mm, 26 * mm, 27 * mm, 84 * mm])
    if not sighting_rows:
        para("No public sightings matched covered selectors.")

    section("Provider coverage (mandatory)")
    coverage_rows = [
        [row.get("provider"), row.get("category"), row.get("status"), row.get("requests"), row.get("observations"), row.get("reason")]
        for row in coverage.get("rows") or []
    ]
    table(["Provider", "Category", "Status", "Req.", "Obs.", "Reason / error"], coverage_rows,
          widths=[35 * mm, 30 * mm, 20 * mm, 12 * mm, 12 * mm, 78 * mm])
    if not coverage_rows:
        para("No provider coverage was recorded. This report cannot support an absence-of-evidence conclusion.")

    section("Assessment limitations")
    for item in data.get("limitations") or []:
        para(f"• {item}", "PTSmall")
    if data.get("warnings"):
        para("Run warnings: " + " | ".join(str(w) for w in data["warnings"][:20]), "PTSmall")

    def footer(canvas, doc_obj) -> None:
        canvas.saveState()
        canvas.setFont(font, 6.5)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawString(15 * mm, 9 * mm, f"{data.get('company')} · PhishTrace · {data.get('report_id')}")
        canvas.drawRightString(195 * mm, 9 * mm, f"Page {doc_obj.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def render_report(
    data: dict,
    fmt: str,
    *,
    generated_at: datetime | None = None,
) -> bytes:
    fmt = canonical_format(fmt)
    if fmt == "html":
        return render_html(data)
    if fmt == "pdf":
        return render_pdf(data)
    if fmt == "json":
        return render_json(data)
    if fmt == "stix":
        return render_stix(data, generated_at=generated_at)
    if fmt == "misp":
        return render_misp(data, generated_at=generated_at)
    if fmt == "md":
        return render_markdown(data)
    if fmt == "txt":
        return render_text(data)
    if fmt == "csv":
        return render_csv(data)
    raise ValueError(f"unsupported report format {fmt!r}")


def write_report_bundle(
    repo,
    investigation_id: str,
    *,
    settings,
    output_dir: str | Path | None = None,
    formats: Iterable[str] | None = None,
    default_region: str | None = "US",
    generated_at: datetime | None = None,
) -> dict:
    """Write selected formats and a SHA-256 manifest.  Returns the manifest."""
    generated = generated_at or utcnow()
    data = build_report_data(
        repo,
        investigation_id,
        settings=settings,
        default_region=default_region,
        generated_at=generated,
    )
    requested = list(formats or settings.formats or SUPPORTED_FORMATS)
    selected: list[str] = []
    for fmt in requested:
        canonical = canonical_format(fmt)
        if canonical not in selected:
            selected.append(canonical)
    if output_dir:
        output = Path(output_dir)
    elif getattr(repo, "evidence_store", None) is not None:
        output = Path(repo.evidence_store.root).parent / "reports" / investigation_id
    else:
        output = Path.cwd() / "reports" / investigation_id
    output.mkdir(parents=True, exist_ok=True)
    files: list[dict] = []
    errors: list[dict] = []
    for fmt in selected:
        try:
            content = render_report(data, fmt, generated_at=generated)
        except Exception as exc:  # noqa: BLE001 - one format must not hide the others
            errors.append({"format": fmt, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
            continue
        filename = report_filename(data, fmt)
        path = output / filename
        path.write_bytes(content)
        files.append(
            {
                "format": fmt,
                "filename": filename,
                "media_type": MEDIA_TYPES.get(fmt, "application/octet-stream"),
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    manifest = {
        "schema": "phishtrace.report-bundle/1",
        "investigation_id": investigation_id,
        "generated_at": iso(generated),
        "output_dir": os.fspath(output),
        "formats": selected,
        "files": files,
        "errors": errors,
    }
    # Atomic manifest write so a partially written bundle is not mistaken for complete.
    temp = output / ".manifest.json.tmp"
    temp.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, output / "manifest.json")
    return manifest
