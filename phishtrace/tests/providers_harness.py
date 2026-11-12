"""Test harness for provider plugins.

Every provider test runs against ``httpx.MockTransport``.  No test ever touches
a live third-party service: that keeps the suite deterministic, fast, and
usable offline, and it prevents the test suite from becoming a scanner.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import httpx

from phishtrace.config import Config, ProviderSettings
from phishtrace.core.http import EvidenceRecorder, ProviderHTTP, TTLCache, make_client
from phishtrace.core.limits import Budget, RateLimiter
from phishtrace.normalizer import normalize_indicator
from phishtrace.providers.context import ProviderContext
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository
from phishtrace.tests.conftest import make_config


@dataclass
class ProviderRun:
    ctx: ProviderContext
    result: object
    repo: Repository
    investigation_id: str
    requests: list[httpx.Request] = field(default_factory=list)

    def observations(self, type_name: str | None = None) -> list:
        rows = self.result.observations
        if type_name:
            rows = [row for row in rows if row.type == type_name]
        return rows

    def values(self, type_name: str | None = None) -> set[str]:
        return {row.value for row in self.observations(type_name)}


def build_context(
    tmp_path: Path,
    provider_cls,
    seed: str,
    handler,
    *,
    env: dict[str, str] | None = None,
    options: dict | None = None,
    config: Config | None = None,
    seed_type: str | None = None,
) -> ProviderRun:
    """Create a fully wired ProviderContext backed by a mock transport."""
    config = config or make_config(tmp_path)
    if env:
        config.env = {**config.env, **env}
    settings = ProviderSettings(enabled=True, options=options or {})
    provider = provider_cls(settings)
    indicator = normalize_indicator(seed, kind=seed_type)

    engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
    store = EvidenceStore(config.evidence_dir)
    repo = Repository(factory, store)
    investigation = repo.create_investigation(
        seed=seed, seed_type=indicator.type, seed_normalized=indicator.normalized,
        config_snapshot={}, owner="test",
    )
    captured: list[httpx.Request] = []

    def recording_handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    client = make_client(config, transport=httpx.MockTransport(recording_handler))
    http = ProviderHTTP(
        provider=provider.meta.name,
        client=client,
        limiter=RateLimiter(10_000),
        budget=Budget(1000, 1000),
        recorder=EvidenceRecorder(store, repo, investigation["id"]),
        config=config,
        cache=TTLCache(max_items=8),
    )
    ctx = ProviderContext(
        provider=provider,
        config=config,
        http=http,
        indicator=indicator,
        variants=[dict(v) for v in indicator.variants],
        investigation_id=investigation["id"],
        options=dict(options or {}),
    )
    return ProviderRun(ctx=ctx, result=None, repo=repo, investigation_id=investigation["id"], requests=captured)


async def run_provider(
    tmp_path: Path,
    provider_cls,
    seed: str,
    handler,
    **kwargs,
) -> ProviderRun:
    run = build_context(tmp_path, provider_cls, seed, handler, **kwargs)
    run.result = await run.ctx.provider.run(run.ctx)
    await run.ctx.http.client.aclose()
    return run


async def run_sightings(
    tmp_path: Path,
    provider_cls,
    seed: str,
    handler,
    **kwargs,
) -> ProviderRun:
    run = build_context(tmp_path, provider_cls, seed, handler, **kwargs)
    run.result = await run.ctx.provider.sightings(run.ctx, run.ctx.variants)
    await run.ctx.http.client.aclose()
    return run


def json_response(payload, status: int = 200, *, headers: dict | None = None) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers or {})


def text_response(body: str, status: int = 200, *, content_type: str = "text/plain") -> httpx.Response:
    return httpx.Response(status, text=body, headers={"content-type": content_type})


def route(handler_map: dict[str, object], fallback_status: int = 404):
    """Build a handler that dispatches on a URL substring."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        for fragment, payload in handler_map.items():
            if fragment in url:
                if callable(payload):
                    return payload(request)
                if isinstance(payload, httpx.Response):
                    return payload
                if isinstance(payload, str):
                    return text_response(payload)
                return json_response(payload)
        return httpx.Response(fallback_status, json={"error": "unexpected url", "url": url})

    return handler
