"""Phase 3: stop-lists, confidence scoring, pivot engine, orchestrator."""

from __future__ import annotations

import asyncio

import httpx
import pytest

from phishtrace.config import LimitsConfig
from phishtrace.core.orchestrator import InvestigationRunner, validate_provider_keys
from phishtrace.core.pivot import PivotEngine
from phishtrace.core.registry import Registry
from phishtrace.core.scoring import edge_confidence, path_confidence, should_expand
from phishtrace.core.stoplist import StopList, classify_indicator, is_stoplisted_ip
from phishtrace.normalizer import normalize_indicator
from phishtrace.providers.base import BaseProvider, ProviderMeta

from .conftest import make_config


# --------------------------------------------------------------------------- helpers
def provider_class(name, accepts, handler, *, api_keys=(), reliability=0.8, supports_sightings=False):
    """Build a deterministic fake provider.

    ``handler(ctx)`` returns a list of ``(type, value, relation, strength)``
    tuples. It may also raise to simulate an upstream outage.
    """

    class FakeProvider(BaseProvider):
        meta = ProviderMeta(
            name=name,
            accepts=tuple(accepts),
            emits=("domain", "ip", "email", "url"),
            api_keys=tuple(api_keys),
            rate_limit=1000.0,
            timeout=5.0,
            reliability=reliability,
            category="test",
            supports_sightings=supports_sightings,
        )
        calls: list[str] = []

        async def run(self, ctx):
            self.calls.append(ctx.indicator.normalized)
            for type_name, value, relation, strength in handler(ctx) or []:
                ctx.emit(type_name, value, relation, strength)
            return ctx.result

    FakeProvider.__name__ = f"Fake_{name}"
    return FakeProvider


def run_engine(config, repo, classes, seed_value, *, kind=None, stoplist=None, transport=None):
    registry = Registry(config, provider_classes=classes)
    seed = normalize_indicator(seed_value, kind=kind)
    investigation = repo.create_investigation(
        seed=seed_value,
        seed_type=seed.type,
        seed_normalized=seed.normalized,
        config_snapshot={},
    )
    engine = PivotEngine(config, registry, repo, investigation["id"], stoplist=stoplist, transport=transport)
    stats = asyncio.run(engine.run(seed))
    return engine, stats, investigation, registry


def limits(**overrides) -> LimitsConfig:
    base = {
        "max_depth": 3,
        "max_children_per_node": 25,
        "max_nodes": 100,
        "global_request_budget": 200,
        "per_provider_budget": 50,
        "max_retries": 0,
        "retry_backoff_seconds": 0.01,
    }
    base.update(overrides)
    return LimitsConfig(**base)


# ---------------------------------------------------------------------------- stop-list
def test_stoplist_recognises_shared_infrastructure():
    assert is_stoplisted_ip("104.16.132.229")  # Cloudflare
    assert is_stoplisted_ip("151.101.1.69")    # Fastly
    assert is_stoplisted_ip("8.8.8.8")         # Google resolver
    assert not is_stoplisted_ip("45.33.32.156")  # ordinary Linode address
    assert classify_indicator("ip", "10.1.2.3").role == "non-routable"
    assert classify_indicator("ip", "10.1.2.3").expand is False


def test_stoplist_matches_registrable_domains_and_platforms():
    cdn = classify_indicator("domain", "assets.cdn.jsdelivr.net")
    assert cdn.expand is False and cdn.role == "cdn-edge" and cdn.matched == "jsdelivr.net"
    mail = classify_indicator("email", "attacker@gmail.com")
    assert mail.expand is False and mail.role == "free-webmail"
    short = classify_indicator("url", "https://bit.ly/abc123")
    assert short.expand is False and short.role == "url-shortener"
    archive = classify_indicator("domain", "web.archive.org")
    assert archive.expand is False and archive.role == "archive"
    normal = classify_indicator("domain", "login-secure-example.com")
    assert normal.expand is True and normal.role == "attacker-infrastructure"
    assert classify_indicator("asn", "AS13335").expand is False


def test_stoplist_loads_operator_extensions(tmp_path):
    domains = tmp_path / "extra-domains.txt"
    domains.write_text("# operator additions\ntracker.example\n", encoding="utf-8")
    config = make_config(tmp_path, stoplists={"domains": str(domains)})
    stoplist = StopList.from_config(config)
    assert stoplist.classify("domain", "sub.tracker.example").expand is False
    assert stoplist.classify("domain", "sub.tracker.example").role == "shared-hosting"


def test_nameserver_pivots_are_context_only():
    decision = classify_indicator("nameserver", "ns-123.awsdns-45.com")
    assert decision.expand is False and decision.role == "dns-provider"
    assert classify_indicator("nameserver", "ns1.attacker-owned-dns.com").expand is True


# ------------------------------------------------------------------------------- scoring
def test_edge_confidence_is_monotonic_and_bounded():
    strong = edge_confidence("strong", 1.0)
    medium = edge_confidence("medium", 1.0)
    weak = edge_confidence("weak", 1.0)
    assert strong > medium > weak
    assert 0.85 <= strong <= 0.99
    assert edge_confidence("weak", 0.0) > 0
    assert edge_confidence("strong", 1.0, corroborations=3) > strong
    assert edge_confidence("strong", 1.0, hint=0.1) < strong
    assert edge_confidence("bogus", 1.0) == weak


def test_path_confidence_multiplies_and_expansion_rules():
    assert path_confidence(1.0, 0.5) == 0.5
    assert path_confidence(0.5, 0.5) == 0.25
    ok, _ = should_expand(
        strength="medium", path=0.5, depth=1, context_only=False, stop_expand=True,
        max_depth=3, expand_weak=False, path_floor=0.25,
    )
    assert ok
    weak, reason = should_expand(
        strength="weak", path=0.5, depth=1, context_only=False, stop_expand=True,
        max_depth=3, expand_weak=False, path_floor=0.25,
    )
    assert weak is False and "weak" in reason
    deep, _ = should_expand(
        strength="strong", path=0.5, depth=3, context_only=False, stop_expand=True,
        max_depth=3, expand_weak=True, path_floor=0.25,
    )
    assert deep is False
    low, _ = should_expand(
        strength="strong", path=0.1, depth=1, context_only=False, stop_expand=True,
        max_depth=3, expand_weak=True, path_floor=0.25,
    )
    assert low is False


# --------------------------------------------------------------------------- engine
def test_cloudflare_seed_does_not_mass_pivot(tmp_path, repo):
    ip_provider = provider_class(
        "fake_ip",
        ("ip",),
        lambda ctx: [
            ("domain", "one.example.com", "reverse-dns", "strong"),
            ("domain", "two.example.com", "reverse-dns", "strong"),
            ("domain", "three.example.com", "reverse-dns", "strong"),
        ],
    )
    domain_provider = provider_class(
        "fake_domain",
        ("domain",),
        lambda ctx: [("ip", "203.0.113.77", "resolves-to", "strong")],
    )
    config = make_config(tmp_path, limits=limits(max_nodes=50))
    engine, stats, investigation, _ = run_engine(
        config, repo, [ip_provider, domain_provider], "104.16.132.229", kind="ip"
    )
    graph = repo.graph(investigation["id"])

    assert stats.expanded == 1, "only the seed may be queried for a stop-listed address"
    assert domain_provider.calls == [], "children of a stop-listed node must never expand"
    assert stats.stoplist_hits >= 1
    assert all(node["depth"] <= 1 for node in graph["nodes"])
    assert all(node["context_only"] for node in graph["nodes"] if node["depth"] == 1)
    assert len(ip_provider.calls) == 1


def test_children_cap_is_honoured(tmp_path, repo):
    def children(ctx):
        if ctx.indicator.normalized != "caps-example.com":
            return []
        return [
            ("domain", f"child-{index}.caps-example.com", "subdomain", "strong")
            for index in range(30)
        ]

    grower = provider_class("fake_grower", ("domain",), children)
    config = make_config(tmp_path, limits=limits(max_children_per_node=3, max_nodes=100))
    _, stats, investigation, _ = run_engine(config, repo, [grower], "caps-example.com")

    graph = repo.graph(investigation["id"])
    assert len(graph["nodes"]) == 31, "all observed children are recorded"
    assert stats.children_capped == 27
    assert stats.expanded == 4, "seed plus three selected children"
    assert grower.calls[0] == "caps-example.com"
    assert len(grower.calls) == 4


def test_node_cap_is_honoured(tmp_path, repo):
    def children(ctx):
        if ctx.indicator.normalized != "nodecap-example.com":
            return []
        return [
            ("domain", f"n{index}.nodecap-example.com", "subdomain", "strong")
            for index in range(20)
        ]

    grower = provider_class("fake_grower", ("domain",), children)
    config = make_config(tmp_path, limits=limits(max_nodes=5, max_children_per_node=25))
    _, stats, investigation, _ = run_engine(config, repo, [grower], "nodecap-example.com")

    graph = repo.graph(investigation["id"])
    assert len(graph["nodes"]) == 5
    assert stats.nodes_capped == 16
    assert stats.truncated is None or "max_nodes" in (stats.truncated or "")


def test_depth_cap_stops_recursion(tmp_path, repo):
    def children(ctx):
        return [("domain", f"d{ctx.indicator.normalized.count('.')}-{ctx.indicator.normalized}",
                 "subdomain", "strong")]

    grower = provider_class("fake_grower", ("domain",), children)
    config = make_config(tmp_path, limits=limits(max_depth=1, max_children_per_node=5, max_nodes=50))
    _, stats, investigation, _ = run_engine(config, repo, [grower], "depth-example.com")

    assert stats.expanded == 1
    graph = repo.graph(investigation["id"])
    assert all(node["depth"] <= 1 for node in graph["nodes"])


def test_failing_provider_does_not_stop_the_run(tmp_path, repo):
    def boom(ctx):
        raise RuntimeError("upstream is down")

    failing = provider_class("fake_failing", ("domain",), boom)
    good = provider_class(
        "fake_good", ("domain",), lambda ctx: [("ip", "198.51.100.9", "resolves-to", "strong")]
    )
    config = make_config(tmp_path, limits=limits())
    registry = Registry(config, provider_classes=[failing, good])
    runner = InvestigationRunner(config, repo, registry)
    result = asyncio.run(runner.run_seed("https://login.failing-example.com/verify"))

    assert result["status"] in {"completed", "partial"}
    run_rows = {row["provider"]: row for row in repo.list_provider_runs(result["investigation_id"])}
    assert run_rows["fake_failing"]["status"] == "failed"
    assert run_rows["fake_good"]["status"] == "ran"
    assert run_rows["fake_good"]["observations"] >= 1
    assert any("fake_failing" in warning for warning in result["warnings"])
    graph = repo.graph(result["investigation_id"])
    assert any(node["type"] == "ip" and node["normalized_value"] == "198.51.100.9" for node in graph["nodes"])


def test_budget_exhaustion_truncates_gracefully(tmp_path, repo):
    def transport_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    class HttpProvider(BaseProvider):
        meta = ProviderMeta(
            name="fake_http", accepts=("domain",), emits=("domain",),
            rate_limit=1000.0, timeout=5.0, reliability=0.8, category="test",
        )
        calls: list[str] = []

        async def run(self, ctx):
            self.calls.append(ctx.indicator.normalized)
            await ctx.http.get_json("https://api.test/data")
            if ctx.indicator.normalized == "budget-example.com":
                ctx.emit("domain", "next.budget-example.com", "subdomain", "strong")
            return ctx.result

    config = make_config(
        tmp_path,
        limits=limits(global_request_budget=1, per_provider_budget=5),
    )
    engine, stats, _, _ = run_engine(
        config,
        repo,
        [HttpProvider],
        "budget-example.com",
        kind="domain",
        transport=httpx.MockTransport(transport_handler),
    )
    assert stats.expanded == 1
    assert stats.truncated is not None
    assert "budget" in stats.truncated.lower()
    assert stats.budget["global_used"] == 1


def test_engine_is_idempotent_within_one_investigation(tmp_path, repo):
    provider = provider_class(
        "fake_emit",
        ("domain",),
        lambda ctx: [("ip", "203.0.113.55", "resolves-to", "strong")],
    )
    config = make_config(tmp_path, limits=limits())
    registry = Registry(config, provider_classes=[provider])
    seed = normalize_indicator("idempotent-example.com")
    investigation = repo.create_investigation(
        seed="idempotent-example.com",
        seed_type=seed.type,
        seed_normalized=seed.normalized,
        config_snapshot={},
    )
    first = asyncio.run(PivotEngine(config, registry, repo, investigation["id"]).run(seed))
    counts_first = repo.counts(investigation["id"])
    second = asyncio.run(PivotEngine(config, registry, repo, investigation["id"]).run(seed))
    counts_second = repo.counts(investigation["id"])

    assert counts_first == counts_second
    assert first.nodes == 2 and second.nodes == 0, "the second run must create nothing"
    assert second.edges == 0
    assert counts_second["indicators"] == 2
    assert counts_second["edges"] == 1


# --------------------------------------------------------------------------- runner
def test_url_seed_derives_hostname_and_rerun_reuses(tmp_path, repo):
    provider = provider_class(
        "fake_domain",
        ("domain",),
        lambda ctx: [("ip", "203.0.113.88", "resolves-to", "strong")],
    )
    config = make_config(tmp_path, limits=limits())
    registry = Registry(config, provider_classes=[provider])
    runner = InvestigationRunner(config, repo, registry)

    first = asyncio.run(runner.run_seed("https://login.rerun-example.com/verify", reuse=True))
    second = asyncio.run(runner.run_seed("https://login.rerun-example.com/verify", reuse=True))

    assert first["reused"] is False
    assert second["reused"] is True
    assert first["investigation_id"] == second["investigation_id"]
    assert first["counts"] == second["counts"]
    assert provider.calls, "the derived hostname must be pivoted"
    assert "login.rerun-example.com" in provider.calls or "rerun-example.com" in provider.calls
    graph = repo.graph(first["investigation_id"])
    assert graph["nodes"][0]["type"] == "url"
    assert any(node["type"] == "domain" for node in graph["nodes"])


def test_runner_records_coverage_and_skipped_providers(tmp_path, repo):
    keyed = provider_class(
        "fake_keyed",
        ("domain",),
        lambda ctx: [],
        api_keys=("FAKE_PROVIDER_KEY",),
    )
    config = make_config(tmp_path, limits=limits(), env={})
    registry = Registry(config, provider_classes=[keyed])
    runner = InvestigationRunner(config, repo, registry)
    result = asyncio.run(runner.run_seed("coverage-example.com"))

    assert result["status"] == "completed"
    skipped = {item["provider"]: item["reason"] for item in result["skipped"]}
    assert "fake_keyed" in skipped and "missing API key" in skipped["fake_keyed"]
    assert isinstance(result["coverage"]["providers"], list)


def test_validate_provider_keys_reports_presence_without_leaking(tmp_path):
    keyed = provider_class(
        "fake_keyed",
        ("domain",),
        lambda ctx: [],
        api_keys=("FAKE_PROVIDER_KEY",),
    )
    config = make_config(tmp_path, env={"FAKE_PROVIDER_KEY": "super-secret-value"})
    registry = Registry(config, provider_classes=[keyed])
    results = asyncio.run(validate_provider_keys(config, registry))

    assert "fake_keyed" in results
    ok, message = results["fake_keyed"]
    assert ok is True
    assert "super-secret-value" not in message
