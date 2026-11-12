"""Timeline merge: turn scattered observations into one ordered account.

Every event in PhishTrace is a *dated claim* about the campaign, each coming
from a different source with a different precision. This module:

* merges events that describe the same thing on the same day into one row that
  lists every contributing source (never discards corroboration, never shows
  the same fact three times);
* classifies each row into a campaign stage (registration, certificate, DNS,
  hosting, scan, feed, archive, social, exposure);
* computes the earliest observed activity overall and per stage;
* reports the gaps between phases, because a three-month silence between
  registration and first sighting is itself an analytic finding;
* carries an explicit ``precision`` per row so a date-only WHOIS record is
  never presented with second-level accuracy.

All wording is "earliest observed". Absence of an event is not evidence that
the activity did not happen: it only means no covered source reported it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from phishtrace.models import iso, parse_timestamp

STAGES = (
    "registration",
    "certificate",
    "passive_dns",
    "hosting",
    "scan",
    "feed",
    "archive",
    "social",
    "exposure",
    "other",
)

STAGE_LABELS = {
    "registration": "Domain registration",
    "certificate": "Certificate issuance",
    "passive_dns": "Passive DNS",
    "hosting": "Hosting / network",
    "scan": "URL scan",
    "feed": "Threat feed",
    "archive": "Web archive",
    "social": "Social media",
    "exposure": "Credential exposure",
    "other": "Other",
}

# Ordered by investigative usefulness: the first stages usually precede abuse.
STAGE_ORDER = {stage: index for index, stage in enumerate(STAGES)}

_KIND_STAGE = {
    "domain-registered": "registration",
    "domain-updated": "registration",
    "domain-expires": "registration",
    "domain-transfer": "registration",
    "rdap-updated": "registration",
    "certificate-issuance": "certificate",
    "archive-snapshot": "archive",
    "url-scan": "scan",
    "feed-submission": "feed",
    "threat-ioc-first-seen": "feed",
    "infostealer-exposure": "exposure",
    "social-mention": "social",
    "passive-dns": "passive_dns",
    "dns-record": "passive_dns",
    "hosting-change": "hosting",
}

_PREFIX_STAGE = (
    ("domain-", "registration"),
    ("cert", "certificate"),
    ("dns-", "passive_dns"),
    ("passive-", "passive_dns"),
    ("host", "hosting"),
    ("ip-", "hosting"),
    ("asn", "hosting"),
    ("scan", "scan"),
    ("feed", "feed"),
    ("archive", "archive"),
    ("social", "social"),
    ("exposure", "exposure"),
)


def stage_for(kind: str, source: str | None = None) -> str:
    """Map an event kind (and, failing that, its source) to a campaign stage."""
    key = (kind or "").strip().lower()
    if key in _KIND_STAGE:
        return _KIND_STAGE[key]
    for prefix, stage in _PREFIX_STAGE:
        if key.startswith(prefix):
            return stage
    src = (source or "").lower()
    if src in {"crtsh", "crt_sh", "certspotter"}:
        return "certificate"
    if src in {"rdap", "whois"}:
        return "registration"
    if src in {"wayback", "memento", "arquivo"}:
        return "archive"
    if src in {"urlscan"}:
        return "scan"
    if src in {"urlhaus", "threatfox", "openphish", "phishtank", "phishstats", "phishing_database"}:
        return "feed"
    if src in {"telegram_public", "bluesky", "reddit", "mastodon"}:
        return "social"
    return "other"


def _as_dt(value: Any) -> datetime | None:
    return parse_timestamp(value)


def _day(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")


def _merge_key(event: dict) -> tuple:
    """Events that assert the same fact on the same day are one row."""
    dt = _as_dt(event.get("occurred_at"))
    day = _day(dt) if dt else "unknown"
    indicator = (event.get("indicator_value") or "").strip().lower()
    kind = (event.get("kind") or "event").strip().lower()
    label = (event.get("label") or "").strip().lower()
    # registration/certificate labels embed the indicator; keep the value only
    return (kind, indicator, day, label)


def merge_events(events: Iterable[dict]) -> tuple[list[dict], int]:
    """Merge duplicate claims. Returns ``(rows, collapsed_count)``."""
    groups: dict[tuple, dict] = {}
    collapsed = 0
    for event in events:
        dt = _as_dt(event.get("occurred_at"))
        if dt is None:
            continue
        key = _merge_key(event)
        sources = [event.get("source") or "unknown"]
        row = groups.get(key)
        if row is None:
            groups[key] = {
                "occurred_at": iso(dt),
                "_dt": dt,
                "stage": stage_for(event.get("kind", ""), event.get("source")),
                "kind": event.get("kind") or "event",
                "label": event.get("label") or "",
                "detail": event.get("detail"),
                "url": event.get("url"),
                "indicator_value": event.get("indicator_value"),
                "precision": event.get("precision") or "exact",
                "sources": sources,
                "evidence_ids": [event["evidence_id"]] if event.get("evidence_id") else [],
                "ids": [event["id"]] if event.get("id") else [],
                "count": 1,
                "meta": dict(event.get("meta") or {}),
            }
        else:
            collapsed += 1
            if event.get("source") and event["source"] not in row["sources"]:
                row["sources"].append(event["source"])
            if event.get("evidence_id") and event["evidence_id"] not in row["evidence_ids"]:
                row["evidence_ids"].append(event["evidence_id"])
            if event.get("id") and event["id"] not in row["ids"]:
                row["ids"].append(event["id"])
            # a date-only claim makes the merged row date-precision
            if (event.get("precision") or "exact") != "exact":
                row["precision"] = event.get("precision")
            if not row.get("detail") and event.get("detail"):
                row["detail"] = event["detail"]
            if not row.get("url") and event.get("url"):
                row["url"] = event["url"]
            row["count"] += 1

    rows = sorted(groups.values(), key=lambda r: (r["_dt"], STAGE_ORDER.get(r["stage"], 99)))
    for row in rows:
        row.pop("_dt", None)
    return rows, collapsed


@dataclass
class Timeline:
    rows: list[dict] = field(default_factory=list)
    earliest_observed: dict | None = None
    stages: dict[str, dict] = field(default_factory=dict)
    days: list[dict] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    raw_events: int = 0
    collapsed: int = 0
    precision: str = "exact"
    coverage: dict = field(default_factory=dict)

    @property
    def wording(self) -> dict[str, str]:
        return {
            "timeline": "earliest observed",
            "note": (
                "Timestamps are the earliest observation PhishTrace could verify from the "
                "sources listed. Absence of an event only means no covered source reported "
                "it, not that the activity did not occur."
            ),
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "earliest_observed": self.earliest_observed,
            "events": self.rows,
            "event_count": len(self.rows),
            "raw_event_count": self.raw_events,
            "merged_duplicates": self.collapsed,
            "stages": self.stages,
            "days": self.days,
            "gaps": self.gaps,
            "precision": self.precision,
            "coverage": self.coverage,
            "wording": self.wording,
        }


def build_timeline(
    events: Iterable[dict],
    *,
    gap_days: int = 90,
    stage_coverage: dict[str, Any] | None = None,
) -> Timeline:
    """Merge, sort and summarise raw timeline rows."""
    raw = [dict(e) for e in events if _as_dt(e.get("occurred_at")) is not None]
    rows, collapsed = merge_events(raw)

    stages: dict[str, dict] = {}
    for row in rows:
        stage = row["stage"]
        bucket = stages.setdefault(
            stage,
            {
                "stage": stage,
                "label": STAGE_LABELS.get(stage, stage),
                "earliest_observed": row["occurred_at"],
                "count": 0,
                "sources": [],
                "first_event": row["label"],
            },
        )
        bucket["count"] += 1
        for source in row["sources"]:
            if source not in bucket["sources"]:
                bucket["sources"].append(source)

    by_day: dict[str, dict] = {}
    for row in rows:
        day = (row["occurred_at"] or "")[:10]
        bucket = by_day.setdefault(day, {"date": day, "count": 0, "stages": []})
        bucket["count"] += 1
        if row["stage"] not in bucket["stages"]:
            bucket["stages"].append(row["stage"])

    gaps: list[dict] = []
    for previous, current in zip(rows, rows[1:]):
        prev_dt = _as_dt(previous["occurred_at"])
        cur_dt = _as_dt(current["occurred_at"])
        if not prev_dt or not cur_dt:
            continue
        delta = (cur_dt - prev_dt).days
        if delta >= gap_days:
            gaps.append(
                {
                    "days": delta,
                    "from": previous["occurred_at"],
                    "to": current["occurred_at"],
                    "from_stage": previous["stage"],
                    "to_stage": current["stage"],
                }
            )

    precision = "exact"
    for row in rows:
        if (row.get("precision") or "exact") != "exact":
            precision = row.get("precision") or "day"
            break

    coverage = dict(stage_coverage or {})
    covered = [s for s in STAGES if s in stages]
    missing = [s for s in STAGES if s not in stages and s != "other"]
    coverage.update(
        {
            "stages_covered": covered,
            "stages_missing": missing,
            "events_considered": len(raw),
            "note": (
                "A missing stage means no covered provider reported a dated event for it; "
                "it does not mean the activity never happened."
            ),
        }
    )

    return Timeline(
        rows=rows,
        earliest_observed=rows[0] if rows else None,
        stages={k: stages[k] for k in sorted(stages, key=lambda s: STAGE_ORDER.get(s, 99))},
        days=[by_day[k] for k in sorted(by_day)],
        gaps=gaps,
        raw_events=len(raw),
        collapsed=collapsed,
        precision=precision,
        coverage=coverage,
    )


class TimelineMerger:
    """Load an investigation's events and build its merged timeline."""

    def __init__(self, repo, investigation_id: str):
        self.repo = repo
        self.investigation_id = investigation_id

    def build(self, *, extra_events: Iterable[dict] | None = None, gap_days: int = 90) -> Timeline:
        events = list(self.repo.list_timeline(self.investigation_id))
        if extra_events:
            events.extend(dict(e) for e in extra_events)
        investigation = self.repo.get_investigation(self.investigation_id) or {}
        coverage = dict(investigation.get("coverage") or {})
        stage_coverage = {
            "providers_skipped": coverage.get("skipped", []),
            "providers_failed": coverage.get("failed", []),
        }
        return build_timeline(events, gap_days=gap_days, stage_coverage=stage_coverage)

    def earliest(self) -> dict | None:
        return self.build().earliest_observed


def derive_events_from_sightings(sightings: Iterable[dict]) -> list[dict]:
    """One ``social-mention`` event per platform at its earliest post.

    This is derived from collected data (never invented): the date is the post's
    own timestamp and the source is the platform adapter that retrieved it.
    """
    earliest: dict[str, dict] = {}
    for sighting in sightings:
        posted = _as_dt(sighting.get("posted_at"))
        if not posted:
            continue
        platform = sighting.get("platform") or "social"
        current = earliest.get(platform)
        if current is None or posted < current["_dt"]:
            earliest[platform] = {
                "_dt": posted,
                "occurred_at": iso(posted),
                "source": platform,
                "kind": "social-mention",
                "label": f"Earliest observed public post on {platform}",
                "detail": (sighting.get("text_excerpt") or "")[:400] or None,
                "url": sighting.get("post_url"),
                "evidence_id": sighting.get("evidence_id"),
                "indicator_value": sighting.get("indicator_form_matched"),
                "precision": "exact",
                "meta": {
                    "author_handle": sighting.get("author_handle"),
                    "role": sighting.get("role"),
                    "derived_from": "sighting",
                },
            }
    rows = []
    for item in earliest.values():
        item = dict(item)
        item.pop("_dt", None)
        rows.append(item)
    return rows
