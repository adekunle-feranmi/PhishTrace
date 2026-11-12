"""Phase 4 tests: timeline merge, role classifier, sightings engine, archiver.

Everything here is offline: providers are fakes, HTTP goes through
``httpx.MockTransport``, and the archiver's local fetcher is a stub. No test
touches a live platform or the Internet Archive.
"""

from __future__ import annotations

import gzip
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from phishtrace.config import ArchiverConfig, FetcherConfig, LimitsConfig, ProviderSettings
from phishtrace.core.archiver import Archiver
from phishtrace.core.roles import (
    classify_author_cluster,
    classify_role,
    classify_sightings,
    handle_randomness,
    summarize_roles,
)
from phishtrace.core.sightings import SightingsEngine
from phishtrace.core.timeline import (
    TimelineMerger,
    build_timeline,
    derive_events_from_sightings,
    merge_events,
    stage_for,
)
from phishtrace.models import NormalizedIndicator, SightingDraft, parse_timestamp
from phishtrace.normalizer import normalize_indicator
from phishtrace.providers.base import BaseProvider, ProviderMeta
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository
from phishtrace.tests.conftest import make_config

UTC = timezone.utc


def event(
    kind: str,
    occurred_at: str,
    *,
    source: str = "test",
    label: str = "",
    indicator: str = "evil.example",
    precision: str = "exact",
    evidence_id: str | None = None,
) -> dict:
    return {
        "occurred_at": parse_timestamp(occurred_at),
        "source": source,
        "kind": kind,
        "label": label or kind,
        "indicator_value": indicator,
        "precision": precision,
        "evidence_id": evidence_id,
        "detail": None,
        "url": None,
        "meta": {},
    }


# ---------------------------------------------------------------- timeline tests
def test_merge_events_collapses_same_fact_and_keeps_every_source():
    events = [
        {"occurred_at": "2024-03-01T10:00:00Z", "source": "rdap", "kind": "domain-registered", "label": "Registered", "indicator_value": "evil.example"},
        {"occurred_at": "2024-03-01T18:30:00Z", "source": "whoisxml", "kind": "domain-registered", "label": "Registered", "indicator_value": "evil.example"},
        {"occurred_at": "2024-03-02T09:00:00Z", "source": "rdap", "kind": "domain-registered", "label": "Registered", "indicator_value": "evil.example"},
    ]
    rows, collapsed = merge_events(events)
    assert collapsed == 1
    assert len(rows) == 2
    assert rows[0]["sources"] == ["rdap", "whoisxml"]
    assert rows[0]["count"] == 2
    assert rows[0]["occurred_at"].startswith("2024-03-01T10:00:00")


@pytest.mark.parametrize(
    "kind,source,expected",
    [
        ("domain-registered", "rdap", "registration"),
        ("certificate-issuance", "crt_sh", "certificate"),
        ("archive-snapshot", "wayback", "archive"),
        ("url-scan", "urlscan", "scan"),
        ("social-mention", "bluesky", "social"),
        ("threat-ioc-first-seen", "threatfox", "feed"),
        ("infostealer-exposure", "hudsonrock", "exposure"),
        ("something-new", "urlhaus", "feed"),
        ("something-new", "telegram_public", "social"),
        ("totally-unknown", "nobody", "other"),
    ],
)
def test_stage_mapping(kind, source, expected):
    assert stage_for(kind, source) == expected


def test_build_timeline_orders_stages_and_reports_gaps_and_precision():
    events = [
        event("certificate-issuance", "2024-03-10T12:00:00Z", source="crt_sh", label="cert"),
        event("domain-registered", "2024-01-01T00:00:00Z", source="rdap", label="registered", precision="day"),
        event("social-mention", "2024-07-01T08:00:00Z", source="bluesky", label="first post"),
    ]
    timeline = build_timeline(events, gap_days=60)
    assert timeline.earliest_observed["occurred_at"].startswith("2024-01-01")
    assert timeline.earliest_observed["stage"] == "registration"
    assert [row["stage"] for row in timeline.rows] == ["registration", "certificate", "social"]
    assert timeline.precision == "day"
    assert len(timeline.gaps) == 2
    assert timeline.gaps[0]["days"] >= 69
    assert timeline.stages["registration"]["earliest_observed"].startswith("2024-01-01")
    assert timeline.stages["certificate"]["sources"] == ["crt_sh"]


def test_build_timeline_with_no_events_is_honest():
    timeline = build_timeline([])
    assert timeline.earliest_observed is None
    assert timeline.rows == []
    assert timeline.coverage["events_considered"] == 0
    assert "registration" in timeline.coverage["stages_missing"]
    assert timeline.wording["timeline"] == "earliest observed"


def test_timeline_merger_reads_repository(repo):
    investigation = repo.create_investigation(seed="evil.example", seed_type="domain", seed_normalized="evil.example", config_snapshot={}, owner="test")
    repo.add_event(
        investigation["id"],
        event("domain-registered", "2024-02-02T00:00:00Z", source="rdap", label="registered"),
    )
    repo.add_event(
        investigation["id"],
        event("certificate-issuance", "2024-02-03T00:00:00Z", source="crt_sh", label="certified"),
    )
    timeline = TimelineMerger(repo, investigation["id"]).build()
    assert len(timeline.rows) == 2
    assert timeline.earliest_observed["kind"] == "domain-registered"


def test_derive_social_events_uses_earliest_post_per_platform():
    sightings = [
        {"platform": "bluesky", "posted_at": "2024-05-02T00:00:00Z", "post_url": "https://bsky.app/x/2", "text_excerpt": "later", "evidence_id": "e2"},
        {"platform": "bluesky", "posted_at": "2024-05-01T00:00:00Z", "post_url": "https://bsky.app/x/1", "text_excerpt": "first", "evidence_id": "e1"},
        {"platform": "reddit", "posted_at": "2024-04-01T00:00:00Z", "post_url": "https://reddit.com/r/x/1", "text_excerpt": "reddit first"},
    ]
    events = derive_events_from_sightings(sightings)
    assert len(events) == 2
    bluesky = next(e for e in events if e["source"] == "bluesky")
    assert bluesky["occurred_at"].startswith("2024-05-01")
    assert bluesky["kind"] == "social-mention"
    assert bluesky["url"] == "https://bsky.app/x/1"


# ------------------------------------------------------------------ role tests
def test_victim_report_is_classified():
    assessment = classify_role(text="I just received this SMS saying my parcel is held. Is this a scam?")
    assert assessment.role == "victim_reporting"
    assert assessment.confidence >= 0.3
    assert any("receipt" in s or "scam" in s for s in assessment.signals)


def test_spanish_victim_report_is_classified():
    assessment = classify_role(text="Me llegó este mensaje, ¿es una estafa?")
    assert assessment.role == "victim_reporting"


def test_researcher_is_classified_from_ioc_language():
    assessment = classify_role(
        text="We analyzed a new phishing campaign. IOCs and SHA256 samples in the thread, reporting to the registrar.",
        author_handle="soc_research",
    )
    assert assessment.role == "researcher"
    assert assessment.confidence >= 0.4


def test_lure_copy_with_fresh_random_handle_is_actor():
    assessment = classify_role(
        text="URGENT: verify your account or it will be suspended. Claim your reward now.",
        author_handle="user84920311",
        posted_at="2024-05-10T00:00:00Z",
        author_created_at="2024-05-08T00:00:00Z",
    )
    assert assessment.role == "threat_actor"
    assert any("auto-generated" in s for s in assessment.signals)


def test_brand_warning_is_classified():
    assessment = classify_role(
        text="This is our official account. We never ask for your password. Beware of fake messages.",
        author_handle="RealBank",
        verified=True,
    )
    assert assessment.role == "brand"


def test_retweet_is_amplifier():
    assessment = classify_role(text="RT @someone: look at this phishing site", author_handle="reposter")
    assert assessment.role == "amplifier"


def test_neutral_post_stays_unknown():
    assessment = classify_role(text="Nice weather today", author_handle="someone")
    assert assessment.role == "unknown"
    assert assessment.confidence < 0.3


def test_author_cluster_with_many_domains_is_distributor():
    drafts = [
        SightingDraft(platform="bluesky", post_url=f"https://bsky.app/p/{i}", text=f"check https://evil{i}.example/login")
        for i in range(4)
    ]
    assessment = classify_author_cluster(drafts, handle=None)
    assert assessment.role == "distributor"
    assert any("distinct domains" in s for s in assessment.signals)


def test_classify_sightings_assigns_same_role_to_author_posts():
    drafts = [
        SightingDraft(platform="reddit", post_url="https://reddit.com/1", author_handle="victim_user", text="I received this text, is this a scam?"),
        SightingDraft(platform="reddit", post_url="https://reddit.com/2", author_handle="victim_user", text="They sent me the same thing again"),
        SightingDraft(platform="reddit", post_url="https://reddit.com/3", author_handle="other_user", text="Nice weather"),
    ]
    assessments = classify_sightings(drafts)
    assert drafts[0].role == drafts[1].role == "victim_reporting"
    assert drafts[2].role == "unknown"
    assert len(assessments) == 2


def test_handle_randomness_is_bounded():
    assert 0.0 <= handle_randomness(None) <= 1.0
    assert handle_randomness("user84920311") > handle_randomness("alice")


# ------------------------------------------------------------- sightings engine
class FakeStatus:
    def __init__(self, name: str, status: str = "enabled", reason: str | None = None):
        self.name = name
        self.status = status
        self.reason = reason
        self.requests = 0
        self.sightings = 0


class FakeRegistry:
    def __init__(self, providers, statuses: dict[str, FakeStatus] | None = None):
        self._providers = list(providers)
        self._statuses = statuses or {p.meta.name: FakeStatus(p.meta.name) for p in providers}

    def all_providers(self):
        return list(self._providers)

    def status(self, name):
        return self._statuses.get(name)

    def mark_ran(self, name, **kwargs):
        status = self._statuses.setdefault(name, FakeStatus(name))
        status.requests += int(kwargs.get("requests", 0))
        status.sightings += int(kwargs.get("sightings", 0))


class FakeSocialProvider(BaseProvider):
    meta = ProviderMeta(
        name="fake_social",
        accepts=("domain", "url", "email", "phone", "telegram"),
        supports_sightings=True,
        category="social",
    )

    def __init__(self, drafts: list[dict], settings: ProviderSettings | None = None):
        super().__init__(settings)
        self.drafts = drafts

    async def run(self, ctx):  # pragma: no cover - not used by the sights engine
        return ctx.result

    async def sightings(self, ctx, variants):
        for draft in self.drafts:
            ctx.sighting(**draft)
        return ctx.result


class ExplodingSocialProvider(BaseProvider):
    meta = ProviderMeta(name="boom_social", accepts=("domain",), supports_sightings=True, category="social")

    async def run(self, ctx):
        return ctx.result

    async def sightings(self, ctx, variants):
        raise RuntimeError("platform down")


def _repo(tmp_path: Path):
    config = make_config(tmp_path)
    _engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
    return config, Repository(factory, EvidenceStore(config.evidence_dir))


@pytest.mark.asyncio
async def test_sightings_engine_caps_to_earliest_and_assigns_roles(tmp_path):
    base = datetime(2024, 6, 1, tzinfo=UTC)
    drafts = [
        {
            "platform": "fake",
            "post_url": f"https://fake.example/p/{i}",
            "post_id": str(i),
            "author_handle": "victim_user",
            "posted_at": base + timedelta(days=i),
            "text": "I received this text, is this a scam?",
        }
        for i in range(5)
    ]
    provider = FakeSocialProvider(drafts)
    config, repo = _repo(tmp_path)
    config.limits.max_sightings = 3
    investigation = await _async_investigation(repo, "evil.example")

    engine = SightingsEngine(config, FakeRegistry([provider]), repo, investigation["id"])
    summary = await engine.collect(normalize_indicator("evil.example"))

    assert summary.collected == 5
    assert summary.stored == 3
    assert summary.suppressed == 2
    assert summary.capped is True
    assert summary.roles["victim_reporting"] == 3  # roles are counted over the stored (capped) posts
    stored = repo.list_sightings(investigation["id"])
    assert len(stored) == 3
    dates = sorted(row["posted_at"] for row in stored)
    assert dates[0].date().isoformat() == "2024-06-01"
    assert dates[-1].date().isoformat() == "2024-06-03"


@pytest.mark.asyncio
async def test_sightings_engine_is_idempotent(tmp_path):
    provider = FakeSocialProvider([
        {"platform": "fake", "post_url": "https://fake.example/1", "post_id": "1",
         "author_handle": "alice", "posted_at": "2024-06-01T00:00:00Z", "text": "hello"},
    ])
    config, repo = _repo(tmp_path)
    investigation = await _async_investigation(repo, "evil.example")
    engine = SightingsEngine(config, FakeRegistry([provider]), repo, investigation["id"])
    first = await engine.collect(normalize_indicator("evil.example"))
    second = await engine.collect(normalize_indicator("evil.example"))
    assert first.stored == 1
    assert second.stored == 0
    assert len(repo.list_sightings(investigation["id"])) == 1


@pytest.mark.asyncio
async def test_sightings_engine_survives_failing_provider(tmp_path):
    good = FakeSocialProvider([
        {"platform": "fake", "post_url": "https://fake.example/1", "posted_at": "2024-06-01T00:00:00Z", "text": "I got this"},
    ])
    config, repo = _repo(tmp_path)
    investigation = await _async_investigation(repo, "evil.example")
    engine = SightingsEngine(config, FakeRegistry([good, ExplodingSocialProvider()]), repo, investigation["id"])
    summary = await engine.collect(normalize_indicator("evil.example"))
    assert summary.stored == 1
    assert [item["provider"] for item in summary.providers_failed] == ["boom_social"]
    assert "fake_social" in summary.providers_ran


@pytest.mark.asyncio
async def test_sightings_engine_reports_skipped_provider(tmp_path):
    provider = FakeSocialProvider([])
    statuses = {"fake_social": FakeStatus("fake_social", "skipped", "missing API key(s): X")}
    config, repo = _repo(tmp_path)
    investigation = await _async_investigation(repo, "evil.example")
    engine = SightingsEngine(config, FakeRegistry([provider], statuses), repo, investigation["id"])
    summary = await engine.collect(normalize_indicator("evil.example"))
    assert summary.stored == 0
    assert summary.providers_skipped[0]["provider"] == "fake_social"


async def _async_investigation(repo, seed: str):
    return repo.create_investigation(seed=seed, seed_type="domain", seed_normalized=seed, config_snapshot={}, owner="test")


# ------------------------------------------------------------------ archiver
def _wayback_handler(payload: dict | None, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        if "archive.org/wayback/available" in str(request.url):
            return httpx.Response(status, json=payload or {})
        return httpx.Response(404, json={"error": "unexpected"})

    return handler


@pytest.mark.asyncio
async def test_archiver_finds_existing_snapshot(tmp_path):
    config, repo = _repo(tmp_path)
    investigation = repo.create_investigation(seed="evil.example", seed_type="domain", seed_normalized="evil.example", config_snapshot={}, owner="test")
    archiver = Archiver(config, repo, investigation["id"], transport=httpx.MockTransport(_wayback_handler({
        "archived_snapshots": {"closest": {"url": "https://web.archive.org/web/2024/https://evil.example/", "status": "200", "timestamp": "20240101"}}
    })))
    result = await archiver.lookup("https://evil.example/login")
    assert result.status == "existing"
    assert result.snapshot_url.startswith("https://web.archive.org/web/2024/")
    assert result.evidence_id
    assert len(repo.list_evidence(investigation["id"])) == 1
    await archiver.close()


@pytest.mark.asyncio
async def test_archiver_reports_missing_snapshot(tmp_path):
    config, repo = _repo(tmp_path)
    investigation = repo.create_investigation(seed="evil.example", seed_type="domain", seed_normalized="evil.example", config_snapshot={}, owner="test")
    archiver = Archiver(config, repo, investigation["id"], transport=httpx.MockTransport(_wayback_handler({"archived_snapshots": {}})))
    result = await archiver.lookup("https://evil.example/login")
    assert result.status == "unavailable"
    assert result.snapshot_url is None
    assert result.ok is False
    await archiver.close()


@pytest.mark.asyncio
async def test_local_snapshot_requires_active_fetch(tmp_path):
    config, repo = _repo(tmp_path)
    investigation = repo.create_investigation(seed="evil.example", seed_type="domain", seed_normalized="evil.example", config_snapshot={}, owner="test")
    archiver = Archiver(config, repo, investigation["id"], fetcher=object())
    result = await archiver.local_snapshot("https://evil.example/login")
    assert result.status == "denied"
    assert "active_fetch" in (result.reason or "")
    assert result.ok is False


class FakePage:
    def __init__(self, content: bytes, url: str):
        self.content = content
        self.status_code = 200
        self.content_type = "text/html"
        self.evidence_id = "ev-test"
        self.url = url


class FakeFetcher:
    def __init__(self, content: bytes):
        self.content = content
        self.calls = 0

    async def fetch(self, url, *, provider=None, note=None):
        self.calls += 1
        return FakePage(self.content, url)


@pytest.mark.asyncio
async def test_local_snapshot_is_deterministic_and_verified(tmp_path):
    body = b"<html><body>fake kit</body></html>"
    config = make_config(
        tmp_path,
        fetcher=FetcherConfig(active_fetch=True, allow_localhost=True),
        archiver=ArchiverConfig(enabled=True, local_snapshot=True),
    )
    _engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
    repo = Repository(factory, EvidenceStore(config.evidence_dir))
    investigation = repo.create_investigation(seed="evil.example", seed_type="domain", seed_normalized="evil.example", config_snapshot={}, owner="test")
    fetcher = FakeFetcher(body)
    archiver = Archiver(config, repo, investigation["id"], fetcher=fetcher)

    first = await archiver.local_snapshot("https://evil.example/login")
    second = await archiver.local_snapshot("https://evil.example/login")

    assert first.status == "archived"
    path = Path(first.local_path)
    assert path.exists()
    assert gzip.decompress(path.read_bytes()) == body
    assert first.sha256 == __import__("hashlib").sha256(body).hexdigest()
    assert second.local_path == first.local_path  # content-addressed, idempotent
    assert fetcher.calls == 2


@pytest.mark.asyncio
async def test_archive_sightings_attaches_snapshot(tmp_path):
    config, repo = _repo(tmp_path)
    investigation = repo.create_investigation(seed="evil.example", seed_type="domain", seed_normalized="evil.example", config_snapshot={}, owner="test")
    sighting, _ = repo.add_sighting(investigation["id"], {
        "platform": "fake",
        "post_url": "https://fake.example/1",
        "posted_at": datetime(2024, 6, 1, tzinfo=UTC),
    })
    archiver = Archiver(config, repo, investigation["id"], transport=httpx.MockTransport(_wayback_handler({
        "archived_snapshots": {"closest": {"url": "https://web.archive.org/web/1/https://fake.example/1", "status": "200"}}
    })))
    summary = await archiver.archive_sightings(repo.list_sightings(investigation["id"]))
    assert summary["existing"] == 1
    stored = repo.list_sightings(investigation["id"])
    assert stored[0]["archive_snapshot_url"].startswith("https://web.archive.org/")
