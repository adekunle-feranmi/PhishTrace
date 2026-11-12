from __future__ import annotations

import pytest

from phishtrace.config import Config, ProviderSettings
from phishtrace.core.registry import Registry
from phishtrace.models import ProviderResult, SelectorStrength
from phishtrace.providers.base import BaseProvider, ProviderMeta


class KeyedProvider(BaseProvider):
    meta = ProviderMeta(
        name="keyed_demo", accepts=("domain",), emits=("ip",), api_keys=("DEMO_KEY",),
        rate_limit=1, timeout=5, reliability=0.9,
    )

    async def run(self, ctx):
        return ctx.result


class KeylessProvider(BaseProvider):
    meta = ProviderMeta(name="keyless_demo", accepts=("url", "domain"), emits=("domain",))

    async def run(self, ctx):
        ctx.emit("domain", "example.org", "contains", SelectorStrength.MEDIUM)
        return ctx.result


def test_missing_key_skips_provider(tmp_path):
    config = Config(data_dir=tmp_path, providers={}, env={})
    registry = Registry(config, [KeyedProvider, KeylessProvider])
    statuses = {s.name: s for s in registry.statuses()}
    assert statuses["keyed_demo"].status == "skipped"
    assert "DEMO_KEY" in (statuses["keyed_demo"].reason or "")
    assert statuses["keyless_demo"].status == "enabled"
    assert [p.name for p in registry.available()] == ["keyless_demo"]


def test_present_key_enables_provider(tmp_path):
    config = Config(data_dir=tmp_path, providers={}, env={"DEMO_KEY": "secret"})
    registry = Registry(config, [KeyedProvider])
    assert registry.status("keyed_demo").status == "enabled"
    assert registry.get("keyed_demo").effective_weight() == pytest.approx(0.9)


def test_disabled_provider_is_skipped_with_reason(tmp_path):
    config = Config(data_dir=tmp_path, providers={"keyless_demo": ProviderSettings(enabled=False)}, env={})
    registry = Registry(config, [KeylessProvider])
    status = registry.status("keyless_demo")
    assert status.status == "skipped"
    assert "disabled" in (status.reason or "")


def test_provider_selection_by_type(tmp_path):
    config = Config(data_dir=tmp_path, providers={}, env={})
    registry = Registry(config, [KeyedProvider, KeylessProvider])
    assert [p.name for p in registry.for_indicator("url")] == ["keyless_demo"]
    assert [p.name for p in registry.for_indicator("email")] == []


def test_duplicate_provider_names_are_reported(tmp_path):
    class Duplicate(BaseProvider):
        meta = ProviderMeta(name="keyless_demo", accepts=("domain",))

        async def run(self, ctx):
            return ctx.result

    config = Config(data_dir=tmp_path, providers={}, env={})
    registry = Registry(config, [KeylessProvider, Duplicate])
    assert len(registry.providers) == 1
    assert any("duplicate provider name" in e.error for e in registry.load_errors)


def test_reliability_weight_and_rate_limit_overrides(tmp_path):
    config = Config(
        data_dir=tmp_path,
        providers={"keyless_demo": ProviderSettings(weight=0.5, rate_limit=3, timeout=9)},
        env={},
    )
    provider = Registry(config, [KeylessProvider]).get("keyless_demo")
    assert provider.effective_rate_limit() == 3
    assert provider.effective_timeout() == 9
    assert provider.effective_weight() == pytest.approx(0.4)


def test_legal_note_blocks_unacknowledged_provider(tmp_path):
    class BreachProvider(BaseProvider):
        meta = ProviderMeta(name="breach_demo", accepts=("email",), legal_note="breach data requires legal review")

        async def run(self, ctx):
            return ProviderResult()

    config = Config(data_dir=tmp_path, providers={}, env={})
    registry = Registry(config, [BreachProvider])
    assert registry.status("breach_demo").status == "skipped"
    assert "legal" in (registry.status("breach_demo").reason or "").lower()
