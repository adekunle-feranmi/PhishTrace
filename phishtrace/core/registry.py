"""Provider discovery, key detection and availability status."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Iterable

import phishtrace.providers as providers_pkg
from phishtrace.config import Config
from phishtrace.models import ProviderStatus
from phishtrace.providers.base import BaseProvider, ProviderLoadError


def discover_providers(errors: list[ProviderLoadError] | None = None) -> list[type[BaseProvider]]:
    """Import every provider module and return BaseProvider subclasses.

    A broken provider module must never prevent the application from starting:
    import failures are recorded and the rest of the registry loads.
    """
    found: dict[str, type[BaseProvider]] = {}
    for info in pkgutil.iter_modules(providers_pkg.__path__):
        if info.name.startswith("_") or info.name in {"base", "context"}:
            continue
        module_name = f"{providers_pkg.__name__}.{info.name}"
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 - isolate plugin failures
            if errors is not None:
                errors.append(ProviderLoadError(module=module_name, error=f"{type(exc).__name__}: {exc}"))
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj is BaseProvider or not issubclass(obj, BaseProvider):
                continue
            if obj.__module__ != module.__name__:
                continue
            meta = getattr(obj, "meta", None)
            if meta is None:
                if errors is not None:
                    errors.append(ProviderLoadError(module=module_name, error=f"{obj.__name__} has no meta"))
                continue
            if meta.name in found:
                if errors is not None:
                    errors.append(ProviderLoadError(
                        module=module_name,
                        error=f"duplicate provider name {meta.name!r} (already loaded from {found[meta.name].__module__})",
                    ))
                continue
            found[meta.name] = obj
    return sorted(found.values(), key=lambda cls: cls.meta.name)


class Registry:
    def __init__(self, config: Config, provider_classes: Iterable[type[BaseProvider]] | None = None):
        self.config = config
        self.load_errors: list[ProviderLoadError] = []
        classes = list(provider_classes) if provider_classes is not None else discover_providers(self.load_errors)
        self.providers: dict[str, BaseProvider] = {}
        self._status: dict[str, ProviderStatus] = {}
        for cls in classes:
            name = cls.meta.name
            if name in self.providers:
                self.load_errors.append(ProviderLoadError(
                    module=cls.__module__,
                    error=f"duplicate provider name {name!r} (already loaded from {type(self.providers[name]).__module__})",
                ))
                continue
            settings = config.providers.get(name)
            provider = cls(settings)
            self.providers[name] = provider
            runnable, reason = provider.can_run(config)
            self._status[name] = ProviderStatus(
                name=name,
                category=provider.meta.category,
                status="enabled" if runnable else "skipped",
                reason=reason,
                requires_keys=list(provider.meta.api_keys),
                missing_keys=provider.missing_keys(config),
                accepts=list(provider.meta.accepts),
                emits=list(provider.meta.emits),
                rate_limit=provider.effective_rate_limit(),
                timeout=provider.effective_timeout(),
                reliability=provider.effective_weight(),
                passive=provider.meta.passive,
                phase=provider.meta.phase,
            )

    # ------------------------------------------------------------------ queries
    def all_providers(self) -> list[BaseProvider]:
        return [self.providers[name] for name in sorted(self.providers)]

    def available(self) -> list[BaseProvider]:
        return [p for p in self.all_providers() if self._status[p.meta.name].status == "enabled"]

    def skipped(self) -> list[ProviderStatus]:
        return [s for s in self.statuses() if s.status == "skipped"]

    def for_indicator(self, indicator_type: str) -> list[BaseProvider]:
        return [p for p in self.available() if indicator_type in p.meta.accepts]

    def sighting_providers(self) -> list[BaseProvider]:
        return [p for p in self.available() if p.meta.supports_sightings]

    def get(self, name: str) -> BaseProvider | None:
        return self.providers.get(name)

    def status(self, name: str) -> ProviderStatus | None:
        return self._status.get(name)

    def statuses(self) -> list[ProviderStatus]:
        return [self._status[name] for name in sorted(self._status)]

    def mark_failed(self, name: str, reason: str) -> None:
        status = self._status.get(name)
        if status:
            status.status = "failed"
            status.error = reason

    def mark_ran(self, name: str, *, requests: int = 0, observations: int = 0, sightings: int = 0,
                 duration_ms: int = 0, error: str | None = None) -> None:
        status = self._status.get(name)
        if not status:
            return
        status.requests += requests
        status.observations += observations
        status.sightings += sightings
        status.duration_ms += duration_ms
        if error:
            status.error = error

    def summary(self) -> dict:
        statuses = self.statuses()
        return {
            "total": len(statuses),
            "enabled": sum(1 for s in statuses if s.status == "enabled"),
            "skipped": sum(1 for s in statuses if s.status == "skipped"),
            "failed": sum(1 for s in statuses if s.status == "failed"),
            "load_errors": [{"module": e.module, "error": e.error} for e in self.load_errors],
        }

    def coverage_block(self) -> dict:
        """Coverage structure persisted with each investigation."""
        statuses = self.statuses()
        return {
            "providers": [status.model_dump() for status in statuses],
            "ran": [s.name for s in statuses if s.status == "enabled" and s.requests >= 0 and s.status != "failed"],
            "skipped": [{"provider": s.name, "reason": s.reason} for s in statuses if s.status == "skipped"],
            "failed": [{"provider": s.name, "reason": s.error or s.reason} for s in statuses if s.status == "failed"],
            "load_errors": [{"module": e.module, "error": e.error} for e in self.load_errors],
        }
