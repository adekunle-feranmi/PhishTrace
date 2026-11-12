"""Rate limiting and request budgets."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class BudgetExhausted(RuntimeError):
    """Raised when the investigation or provider request budget is spent."""


class Budget:
    """Global + per-provider request budget for one investigation."""

    def __init__(self, global_limit: int = 400, per_provider_limit: int = 60):
        self.global_limit = max(1, int(global_limit))
        self.per_provider_limit = max(1, int(per_provider_limit))
        self.global_used = 0
        self.provider_used: dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()

    async def consume(self, provider: str) -> None:
        async with self._lock:
            if self.global_used >= self.global_limit:
                raise BudgetExhausted(f"global request budget exhausted ({self.global_limit})")
            if self.provider_used[provider] >= self.per_provider_limit:
                raise BudgetExhausted(
                    f"provider request budget exhausted for {provider} ({self.per_provider_limit})"
                )
            self.global_used += 1
            self.provider_used[provider] += 1

    def snapshot(self) -> dict:
        return {
            "global_limit": self.global_limit,
            "global_used": self.global_used,
            "per_provider_limit": self.per_provider_limit,
            "per_provider_used": dict(self.provider_used),
            "remaining": max(0, self.global_limit - self.global_used),
        }


class RateLimiter:
    """Simple async token-bucket style limiter enforcing a minimum interval."""

    def __init__(self, rate_per_second: float, burst: int = 1):
        self.rate = max(0.01, float(rate_per_second))
        self.min_interval = 1.0 / self.rate
        self.burst = max(1, int(burst))
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0
        self._tokens = float(self.burst)

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if self._tokens >= 1 and now >= self._next_allowed:
                self._tokens -= 1
                self._next_allowed = max(self._next_allowed, now + self.min_interval)
                return
            wait = max(0.0, self._next_allowed - now)
            if wait:
                await asyncio.sleep(wait)
            self._next_allowed = time.monotonic() + self.min_interval
            self._tokens = float(self.burst - 1)
