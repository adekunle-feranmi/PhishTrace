"""Provider plugin contract.

Adding a provider is intentionally small:

    class MyProvider(BaseProvider):
        meta = ProviderMeta(
            name="my_provider", accepts=("domain",), emits=("ip", "email"),
            api_keys=("MY_API_KEY",), rate_limit=1.0, timeout=20,
            reliability=0.7, category="threat-intel",
        )
        async def run(self, ctx):
            data = await ctx.http.get_json("https://api.example/v1/domain/" + ctx.indicator.normalized)
            if data:
                ctx.emit("ip", data["ip"], "resolves-to", "weak", evidence_id=data.evidence_id)
            return ctx.result

See docs/ADDING_PROVIDERS.md for the full template and testing recipe.
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from phishtrace.config import Config, ProviderSettings
from phishtrace.models import ProviderResult


@dataclass(frozen=True)
class ProviderMeta:
    name: str
    accepts: tuple[str, ...]
    emits: tuple[str, ...] = ()
    api_keys: tuple[str, ...] = ()
    rate_limit: float = 1.0          # requests per second
    timeout: float = 25.0
    reliability: float = 0.8         # 0..1 provider trust weight
    category: str = "osint"
    passive: bool = True
    phase: str = "A"
    description: str = ""
    requires_tool: str | None = None
    supports_sightings: bool = False
    legal_note: str | None = None
    homepage: str | None = None
    cache_ttl: float = 0.0


class BaseProvider(ABC):
    meta: ProviderMeta

    def __init__(self, settings: ProviderSettings | None = None):
        self.settings = settings or ProviderSettings()

    # ------------------------------------------------------------------ config
    @property
    def name(self) -> str:
        return self.meta.name

    @property
    def options(self) -> dict:
        return self.settings.options or {}

    def effective_rate_limit(self) -> float:
        if self.settings.rate_limit is not None:
            return max(0.01, float(self.settings.rate_limit))
        return max(0.01, self.meta.rate_limit)

    def effective_timeout(self) -> float:
        if self.settings.timeout is not None:
            return max(1.0, float(self.settings.timeout))
        return max(1.0, self.meta.timeout)

    def effective_weight(self) -> float:
        return max(0.0, min(1.0, self.meta.reliability * float(self.settings.weight or 1.0)))

    def missing_keys(self, config: Config) -> list[str]:
        return [key for key in self.meta.api_keys if not config.has_key(key)]

    def tool_path(self) -> str | None:
        if not self.meta.requires_tool:
            return None
        configured = str(self.options.get("path") or "").strip()
        if configured and shutil.which(configured):
            return shutil.which(configured)
        if configured:
            import os
            if os.path.isfile(configured) and os.access(configured, os.X_OK):
                return configured
        return shutil.which(self.meta.requires_tool)

    def unavailable_reason(self, config: Config) -> str | None:
        """Return a human-readable reason when the provider cannot run at all."""
        if self.meta.requires_tool and not self.tool_path():
            return f"required tool '{self.meta.requires_tool}' is not installed"
        return None

    def can_run(self, config: Config) -> tuple[bool, str | None]:
        if not self.settings.enabled:
            return False, "disabled in config.yaml"
        missing = self.missing_keys(config)
        if missing:
            return False, "missing API key(s): " + ", ".join(missing)
        reason = self.unavailable_reason(config)
        if reason:
            return False, reason
        if self.meta.legal_note and not self.options.get("legal_acknowledged"):
            return False, "disabled pending legal acknowledgement: " + self.meta.legal_note
        return True, None

    # --------------------------------------------------------------- execution
    @abstractmethod
    async def run(self, ctx) -> ProviderResult:
        """Pivot from ctx.indicator and append results to ctx.result."""

    async def sightings(self, ctx, variants: list[dict]) -> ProviderResult:
        """Search social/web platforms for posts mentioning indicator variants."""
        return ctx.result

    async def healthcheck(self, ctx) -> tuple[bool, str]:
        """Harmless key validation used by `phishtrace doctor`."""
        return True, "no remote healthcheck implemented"

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} {self.meta.name}>"


@dataclass
class ProviderLoadError:
    module: str
    error: str
    phase: str = "load"
    extra: dict = field(default_factory=dict)
