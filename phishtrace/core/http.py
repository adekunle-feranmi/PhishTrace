"""Async HTTP with retries, backoff, per-provider rate limits, budgets and evidence."""

from __future__ import annotations

import asyncio
import json
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

from phishtrace.config import Config
from phishtrace.core.limits import Budget, BudgetExhausted, RateLimiter
from phishtrace.models import iso, utcnow
from phishtrace.storage.evidence import EvidenceStore


class TTLCache:
    """Small async TTL cache with per-key stampede protection."""

    def __init__(self, max_items: int = 64):
        self.max_items = max_items
        self._data: dict[str, tuple[float, Any]] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def get_or_set(self, key: str, factory, ttl: float = 300.0):
        now = time.monotonic()
        hit = self._data.get(key)
        if hit and hit[0] > now:
            return hit[1]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            hit = self._data.get(key)
            if hit and hit[0] > time.monotonic():
                return hit[1]
            value = await factory()
            if len(self._data) >= self.max_items:
                self._data.pop(next(iter(self._data)), None)
            self._data[key] = (time.monotonic() + ttl, value)
            return value


class EvidenceRecorder:
    """Persists evidence rows; degrades to file-only when no repository is bound."""

    def __init__(self, store: EvidenceStore, repo=None, investigation_id: str | None = None):
        self.store = store
        self.repo = repo
        self.investigation_id = investigation_id

    def record(
        self,
        *,
        provider: str,
        request: dict,
        body: bytes,
        url: str | None = None,
        status_code: int | None = None,
        content_type: str | None = None,
        retrieved_at: datetime | None = None,
    ) -> str:
        try:
            record = self.store.put(
                provider=provider,
                request=request,
                body=body,
                url=url,
                status_code=status_code,
                content_type=content_type,
                retrieved_at=retrieved_at,
            )
        except OSError:
            return ""
        if self.repo and self.investigation_id:
            try:
                evidence_id, _ = self.repo.add_evidence(self.investigation_id, record)
                return evidence_id
            except Exception:
                return record.id
        return record.id


@dataclass
class HttpResult:
    ok: bool
    status: int | None
    url: str
    text: str = ""
    data: Any = None
    evidence_id: str | None = None
    error: str | None = None
    headers: dict = field(default_factory=dict)
    elapsed_ms: int = 0
    attempts: int = 1
    content_type: str | None = None
    size: int = 0

    def json(self) -> Any:
        if self.data is not None:
            return self.data
        try:
            self.data = json.loads(self.text)
        except (ValueError, TypeError):
            return None
        return self.data


class ProviderHTTP:
    """Per-provider HTTP session. All responses are recorded as evidence."""

    def __init__(
        self,
        *,
        provider: str,
        client: httpx.AsyncClient,
        limiter: RateLimiter,
        budget: Budget,
        recorder: EvidenceRecorder | None,
        config: Config,
        cache: TTLCache | None = None,
    ):
        self.provider = provider
        self.client = client
        self.limiter = limiter
        self.budget = budget
        self.recorder = recorder
        self.config = config
        self.cache = cache
        self.requests = 0
        self.errors: list[str] = []

    @property
    def max_retries(self) -> int:
        return max(0, int(self.config.limits.max_retries))

    async def get_json(self, url: str, **kwargs) -> HttpResult:
        return await self.request("GET", url, expect_json=True, **kwargs)

    async def get_text(self, url: str, **kwargs) -> HttpResult:
        return await self.request("GET", url, expect_json=False, **kwargs)

    async def post_json(self, url: str, **kwargs) -> HttpResult:
        return await self.request("POST", url, expect_json=True, **kwargs)

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        data: dict | None = None,
        json_body: Any = None,
        headers: dict | None = None,
        expect_json: bool = False,
        timeout: float | None = None,
        max_bytes: int | None = None,
        allow_redirects: bool = True,
        cache_key: str | None = None,
        cache_ttl: float = 300.0,
    ) -> HttpResult:
        if cache_key and self.cache:
            return await self.cache.get_or_set(
                cache_key,
                lambda: self._request_with_retries(
                    method, url, params=params, data=data, json_body=json_body,
                    headers=headers, expect_json=expect_json, timeout=timeout,
                    max_bytes=max_bytes, allow_redirects=allow_redirects,
                ),
                ttl=cache_ttl,
            )
        return await self._request_with_retries(
            method, url, params=params, data=data, json_body=json_body,
            headers=headers, expect_json=expect_json, timeout=timeout,
            max_bytes=max_bytes, allow_redirects=allow_redirects,
        )

    async def _request_with_retries(self, method: str, url: str, **kwargs) -> HttpResult:
        last: HttpResult | None = None
        attempts = self.max_retries + 1
        for attempt in range(1, attempts + 1):
            try:
                await self.budget.consume(self.provider)
            except BudgetExhausted as exc:
                self.errors.append(str(exc))
                return HttpResult(False, None, url, error=str(exc), attempts=attempt)
            await self.limiter.acquire()
            started = time.monotonic()
            request_meta = {
                "method": method,
                "url": url,
                "params": kwargs.get("params"),
                "headers": kwargs.get("headers"),
                "body": kwargs.get("data") or kwargs.get("json_body"),
            }
            try:
                self.requests += 1
                response = await self.client.request(
                    method,
                    url,
                    params=kwargs.get("params"),
                    data=kwargs.get("data"),
                    json=kwargs.get("json_body"),
                    headers=kwargs.get("headers"),
                    timeout=kwargs.get("timeout") or self.config.limits.provider_timeout_seconds,
                    follow_redirects=kwargs.get("allow_redirects", True),
                )
            except (httpx.TimeoutException, httpx.TransportError, httpx.InvalidURL, httpx.TooManyRedirects) as exc:
                error = f"{type(exc).__name__}: {exc}"[:400]
                self.errors.append(error)
                last = HttpResult(False, None, url, error=error, attempts=attempt)
                if attempt < attempts:
                    await asyncio.sleep(self._backoff(attempt))
                    continue
                self._record_error(method, url, request_meta, error)
                return last
            elapsed_ms = int((time.monotonic() - started) * 1000)
            content_type = response.headers.get("content-type")
            body = response.content or b""
            limit = int(kwargs.get("max_bytes") or 8_000_000)
            if len(body) > limit:
                error = f"response too large ({len(body)} bytes > {limit})"
                self.errors.append(error)
                self._record(
                    request_meta, json.dumps({"error": error, "url": str(response.url)}).encode(),
                    str(response.url), response.status_code, "application/json", elapsed_ms,
                )
                return HttpResult(False, response.status_code, str(response.url), error=error, attempts=attempt)

            text = body.decode("utf-8", errors="replace")
            data = None
            if kwargs.get("expect_json"):
                try:
                    data = json.loads(text) if text else None
                except ValueError:
                    data = None
            evidence_id = self._record(
                request_meta, body, str(response.url), response.status_code, content_type, elapsed_ms
            )
            result = HttpResult(
                ok=200 <= response.status_code < 300,
                status=response.status_code,
                url=str(response.url),
                text=text,
                data=data,
                evidence_id=evidence_id,
                headers=dict(response.headers),
                elapsed_ms=elapsed_ms,
                attempts=attempt,
                content_type=content_type,
                size=len(body),
            )
            if response.status_code == 429 or response.status_code >= 500:
                result.error = f"HTTP {response.status_code}"
                self.errors.append(result.error)
                if attempt < attempts:
                    await asyncio.sleep(self._retry_after(response, attempt))
                    continue
            elif response.status_code >= 400:
                result.error = f"HTTP {response.status_code}"
                # 4xx other than 429 is not retried
                return result
            return result
        return last or HttpResult(False, None, url, error="unknown request failure")

    # ------------------------------------------------------------------ helpers
    def _backoff(self, attempt: int) -> float:
        base = max(0.05, float(self.config.limits.retry_backoff_seconds))
        return min(10.0, base * (2 ** (attempt - 1))) * (0.7 + random.random() * 0.6)

    @staticmethod
    def _retry_after(response: httpx.Response, attempt: int) -> float:
        header = response.headers.get("retry-after")
        if header:
            try:
                return min(30.0, max(0.5, float(header)))
            except ValueError:
                pass
        return min(10.0, 0.5 * (2 ** (attempt - 1)))

    def _record(self, request_meta: dict, body: bytes, url: str, status: int | None,
                content_type: str | None, elapsed_ms: int) -> str | None:
        if not self.recorder:
            return None
        request_meta = {**request_meta, "elapsed_ms": elapsed_ms}
        return self.recorder.record(
            provider=self.provider,
            request=request_meta,
            body=body,
            url=url,
            status_code=status,
            content_type=content_type,
            retrieved_at=utcnow(),
        )

    def _record_error(self, method: str, url: str, request_meta: dict, error: str) -> None:
        if not self.recorder:
            return
        self.recorder.record(
            provider=self.provider,
            request={**request_meta, "error": error},
            body=json.dumps({"transport_error": error, "url": url, "method": method}).encode(),
            url=url,
            status_code=None,
            content_type="application/json",
            retrieved_at=utcnow(),
        )



def make_client(config: Config, *, transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=8)
    kwargs: dict[str, Any] = {
        "timeout": httpx.Timeout(config.limits.provider_timeout_seconds, connect=10.0),
        "follow_redirects": True,
        "limits": limits,
        "headers": {
            "User-Agent": config.limits.user_agent,
            "Accept": "application/json, text/plain, */*",
        },
    }
    if transport is not None:
        kwargs["transport"] = transport
    return httpx.AsyncClient(**kwargs)


def evidence_summary(result: HttpResult) -> dict:
    return {
        "url": result.url,
        "status": result.status,
        "evidence_id": result.evidence_id,
        "retrieved_at": iso(utcnow()),
        "attempts": result.attempts,
        "error": result.error,
    }
