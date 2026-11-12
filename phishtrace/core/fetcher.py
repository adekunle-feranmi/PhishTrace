"""Isolated fetcher — the only component allowed to contact hostile infrastructure.

Threat model
------------
The fetcher exists so that "look at the phishing page" never means "let the
investigation host join the attacker's network". It defends against:

* **SSRF** — every hostname is resolved locally and *every* returned address is
  validated against private, loopback, link-local, CGNAT, reserved, multicast
  and documentation ranges. The connection is then pinned to the validated
  address (``Host`` header + TLS ``sni_hostname``), so a DNS-rebinding answer
  cannot move the connection to an internal host between check and use.
* **Redirect escape** — redirects are followed manually, and each hop is
  re-resolved and re-validated. A public page redirecting to ``127.0.0.1`` or
  ``169.254.169.254`` is refused.
* **Protocol abuse** — only ``http`` and ``https``; blocked ports (SSH, SMB,
  RDP, database, cache, mail) are refused even on public addresses.
* **Resource exhaustion** — total timeout, per-read size cap, global byte cap,
  bounded redirects, bounded concurrent connections.
* **Credential leakage** — no cookie jar, no auth headers, no URL userinfo, no
  client certificates. The fetcher arrives as an anonymous visitor.
* **Code execution** — nothing is executed or imported. Bodies are returned as
  bytes and are only ever parsed statically by the analyzers.

Proxy mode
----------
When ``fetcher.proxy`` is configured, DNS resolution and address validation are
delegated to the egress proxy (there is no local DNS answer to pin). The result
records ``ip_validation="delegated-to-proxy"`` so a report never implies a check
that did not happen. Run such a proxy on an isolated host — that is the whole
point of the setting.

Privilege separation
--------------------
The server process must already run as an unprivileged user (see the systemd
unit). For one-off CLI fetches started as root, :func:`drop_privileges_to`
permanently drops to the configured user before any socket is opened.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from phishtrace.config import Config
from phishtrace.models import utcnow
from phishtrace.normalizer import refang
from phishtrace.storage.evidence import EvidenceStore

ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS_HARD_CAP = 10


class FetchDenied(RuntimeError):
    """Raised when a URL is refused by policy (SSRF, port, scheme, size)."""

    def __init__(self, reason: str, *, url: str = "", rule: str = "policy"):
        super().__init__(reason)
        self.reason = reason
        self.url = url
        self.rule = rule

    def as_dict(self) -> dict:
        return {"url": self.url, "reason": self.reason, "rule": self.rule}


@dataclass
class FetchResult:
    url: str
    final_url: str = ""
    status_code: int | None = None
    content_type: str | None = None
    content: bytes = b""
    sha256: str = ""
    evidence_id: str | None = None
    headers: dict = field(default_factory=dict)
    elapsed_ms: int = 0
    redirects: list[dict] = field(default_factory=list)
    truncated: bool = False
    size_bytes: int = 0
    ip_validation: str = "pinned"
    resolved_ip: str | None = None
    error: str | None = None
    note: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.status_code and 200 <= self.status_code < 400 and not self.error)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url or self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "sha256": self.sha256,
            "evidence_id": self.evidence_id,
            "size_bytes": self.size_bytes,
            "content_length": len(self.content),
            "elapsed_ms": self.elapsed_ms,
            "redirects": list(self.redirects),
            "truncated": self.truncated,
            "ip_validation": self.ip_validation,
            "resolved_ip": self.resolved_ip,
            "error": self.error,
            "note": self.note,
        }

    # Compatibility with code that reads attribute-style page objects.
    @property
    def body(self) -> bytes:
        return self.content


def _host_display(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def normalize_target(raw: str) -> str:
    text = refang(raw).strip()
    if not text:
        raise FetchDenied("empty URL", rule="scheme")
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise FetchDenied(f"scheme {scheme!r} is not allowed (http/https only)", url=raw, rule="scheme")
    if "@" in parts.netloc:
        # Strip userinfo entirely: the fetcher never authenticates.
        netloc = parts.netloc.rsplit("@", 1)[-1]
        parts = parts._replace(netloc=netloc)
    if not parts.hostname:
        raise FetchDenied("URL has no host", url=raw, rule="host")
    return urlunsplit((scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _blocked_port(port: int, config: Config) -> str | None:
    if port in set(config.fetcher.blocked_ports):
        return f"port {port} is blocked by policy"
    allowed = list(config.fetcher.allowed_ports or [])
    if allowed and port not in allowed:
        return f"port {port} is not in fetcher.allowed_ports"
    return None


async def resolve_host(host: str, port: int) -> list[str]:
    """Resolve a hostname to addresses, without blocking the event loop."""
    loop = asyncio.get_running_loop()

    def _resolve() -> list[str]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return [info[4][0] for info in infos]

    try:
        return await asyncio.wait_for(loop.run_in_executor(None, _resolve), timeout=8.0)
    except (socket.gaierror, asyncio.TimeoutError, OSError) as exc:
        raise FetchDenied(f"DNS resolution failed: {type(exc).__name__}", url=host, rule="dns") from exc


def _address_allowed(address: str, config: Config) -> bool:
    """True only for a globally routable unicast address (or allowed loopback)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return _address_allowed(str(ip.ipv4_mapped), config)
    if ip.is_loopback:
        # The only exception, and only for the local kit-analyzer test server.
        return bool(config.fetcher.allow_localhost)
    if ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    if not ip.is_global:
        # Covers CGNAT 100.64.0.0/10, documentation, benchmarking, 0.0.0.0/8 and
        # other special-purpose ranges that ``is_private`` does not flag.
        return False
    return True


def drop_privileges_to(username: str) -> None:
    """Permanently drop to ``username`` (root only). Used by the CLI fetcher.

    Refuses silently when not root: the process is then already unprivileged,
    which is the desired end state.
    """
    if os.geteuid() != 0:
        return
    import pwd

    try:
        entry = pwd.getpwnam(username)
    except KeyError as exc:
        raise FetchDenied(f"restricted user {username!r} does not exist", rule="privilege") from exc
    os.setgroups([])
    os.setgid(entry.pw_gid)
    os.setuid(entry.pw_uid)


class IsolatedFetcher:
    """Bounded, SSRF-protected HTTP GET client for hostile infrastructure."""

    def __init__(
        self,
        config: Config,
        *,
        evidence_store: EvidenceStore | None = None,
        recorder: Any | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        provider: str = "fetcher",
    ):
        self.config = config
        self.settings = config.fetcher
        self.store = evidence_store
        #: Optional ``EvidenceRecorder``; when present fetched bodies also get a
        #: database row so the evidence browser can list them.
        self.recorder = recorder
        self.transport = transport
        self.provider = provider
        self.bytes_used = 0
        self.requests = 0
        self.denied: list[dict] = []
        self._client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------ lifecycle
    async def __aenter__(self) -> "IsolatedFetcher":
        self._client = self._build_client()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _build_client(self) -> httpx.AsyncClient:
        limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
        kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self.settings.timeout, connect=min(8.0, self.settings.timeout)),
            "limits": limits,
            "follow_redirects": False,  # redirects are validated hop by hop
            "cookies": httpx.Cookies(),  # never persist state
            "headers": {
                "User-Agent": self.config.limits.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
            },
        }
        if self.transport is not None:
            kwargs["transport"] = self.transport
        elif self.settings.proxy:
            kwargs["proxy"] = self.settings.proxy
        if self.settings.proxy or self.transport is not None:
            # Pinning is impossible through a proxy or an injected transport;
            # the destination has to be validated by that component instead.
            kwargs["verify"] = self.settings.verify_tls
        else:
            kwargs["verify"] = self.settings.verify_tls
        return httpx.AsyncClient(**kwargs)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -------------------------------------------------------------- validation
    async def validate(self, url: str) -> tuple[str, str | None]:
        """Validate one URL. Returns ``(normalized_url, pinned_ip_or_None)``.

        Raises :class:`FetchDenied` when the target is not permitted.
        """
        normalized = normalize_target(url)
        parts = urlsplit(normalized)
        host = (parts.hostname or "").lower().strip(".")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        port_error = _blocked_port(port, self.config)
        if port_error:
            raise FetchDenied(port_error, url=normalized, rule="port")

        # A literal IP address needs no DNS but still needs validation.
        try:
            literal = str(ipaddress.ip_address(host))
        except ValueError:
            literal = None
        if literal:
            if not _address_allowed(literal, self.config):
                raise FetchDenied(
                    f"{literal} is in a private, loopback or reserved range",
                    url=normalized,
                    rule="ssrf",
                )
            return normalized, literal

        if self.settings.proxy and self.transport is None:
            # The proxy resolves the name; local validation cannot happen.
            return normalized, None

        addresses = await resolve_host(host, port)
        if not addresses:
            raise FetchDenied("hostname did not resolve", url=normalized, rule="dns")
        for address in addresses:
            if not _address_allowed(address, self.config):
                raise FetchDenied(
                    f"{host} resolves to {address}, which is private, loopback or reserved",
                    url=normalized,
                    rule="ssrf",
                )
        preferred = next((a for a in addresses if ":" not in a), addresses[0])
        return normalized, preferred

    # -------------------------------------------------------------------- fetch
    async def fetch(
        self,
        url: str,
        *,
        provider: str | None = None,
        note: str = "",
        max_bytes: int | None = None,
        max_redirects: int | None = None,
        record: bool = True,
    ) -> FetchResult:
        """GET ``url`` with full validation, bounded size, and evidence capture.

        ``max_bytes`` and ``max_redirects`` lower (never raise) the configured
        limits for a single call — the kit analyzer uses that to probe paths
        cheaply without storing a body. ``record=False`` skips the evidence
        store, for probes that are not worth an artifact.
        """
        started = time.monotonic()
        provider_name = provider or self.provider
        result = FetchResult(url=url, note=note or None)
        if not self.settings.active_fetch:
            result.error = "active_fetch is disabled in config.yaml"
            result.note = "refused: passive mode"
            return result
        if self._client is None:
            self._client = self._build_client()

        current = url
        seen: set[str] = set()
        limit = self.settings.max_redirects if max_redirects is None else max_redirects
        max_redirects = min(MAX_REDIRECTS_HARD_CAP, max(0, int(limit)))
        for hop in range(max_redirects + 1):
            try:
                normalized, pinned = await self.validate(current)
            except FetchDenied as exc:
                self.denied.append(exc.as_dict())
                result.error = exc.reason
                result.final_url = current
                result.elapsed_ms = int((time.monotonic() - started) * 1000)
                return result
            if normalized in seen:
                result.error = "redirect loop detected"
                result.final_url = current
                return result
            seen.add(normalized)

            remaining = int(self.settings.max_total_bytes) - self.bytes_used
            if remaining <= 0:
                result.error = f"global byte cap reached ({self.settings.max_total_bytes} bytes)"
                result.final_url = current
                return result
            per_call = int(max_bytes) if max_bytes else int(self.settings.max_bytes)
            cap = max(1, min(per_call, remaining))

            try:
                response, body, truncated, sha256 = await self._request(normalized, pinned, cap)
            except FetchDenied as exc:
                self.denied.append(exc.as_dict())
                result.error = exc.reason
                result.final_url = current
                result.elapsed_ms = int((time.monotonic() - started) * 1000)
                return result
            except (httpx.HTTPError, OSError, asyncio.TimeoutError) as exc:
                result.error = f"{type(exc).__name__}: {exc}"[:300]
                result.final_url = current
                result.elapsed_ms = int((time.monotonic() - started) * 1000)
                return result

            location = response.headers.get("location")
            if response.status_code in {301, 302, 303, 307, 308} and location:
                nxt = urljoin_safe(str(response.url), location)
                result.redirects.append({"from": normalized, "to": nxt, "status": response.status_code})
                if hop >= max_redirects:
                    result.error = f"too many redirects (max {max_redirects})"
                    result.final_url = normalized
                    break
                if not nxt:
                    result.error = "invalid redirect target"
                    break
                current = nxt
                continue

            self.bytes_used += len(body)
            self.requests += 1
            result.final_url = normalized
            result.status_code = response.status_code
            result.content_type = response.headers.get("content-type")
            result.content = body
            result.size_bytes = len(body)
            result.truncated = truncated
            result.sha256 = sha256 or hashlib.sha256(body).hexdigest()
            result.headers = {
                key: value for key, value in response.headers.items()
                if key.lower() in {"content-type", "server", "location", "last-modified", "content-length"}
            }
            result.resolved_ip = pinned
            result.ip_validation = "delegated-to-proxy" if pinned is None else "pinned"
            if record:
                result.evidence_id = self._record(provider_name, normalized, body, response, note)
            result.elapsed_ms = int((time.monotonic() - started) * 1000)
            return result

        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        return result

    async def _request(self, normalized: str, pinned: str | None, cap: int):
        """Send one hop. Returns ``(response, body, truncated, sha256)``."""
        if self._client is None:
            # ``assert`` would disappear under ``python -O``; fail closed instead.
            raise FetchDenied("isolated fetcher is not open", rule="state")
        parts = urlsplit(normalized)
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        headers = {"Host": host if port in (80, 443) else f"{host}:{port}"}
        extensions: dict[str, Any] = {}
        target = normalized
        if pinned is not None:
            # Pin the connection to the validated address. TLS verification and
            # SNI still use the real hostname, so certificates stay checked.
            default_port = 443 if parts.scheme == "https" else 80
            authority = _host_display(pinned) + ("" if port == default_port else f":{port}")
            target = urlunsplit((parts.scheme, authority, parts.path or "/", parts.query, ""))
            extensions["sni_hostname"] = host
        request = self._client.build_request("GET", target, headers=headers, extensions=extensions)
        response = await self._client.send(request, stream=True)
        body = bytearray()
        truncated = False
        try:
            async for chunk in response.aiter_bytes():
                if not chunk:
                    continue
                body.extend(chunk)
                if len(body) >= cap:
                    del body[cap:]
                    truncated = True
                    break
        finally:
            await response.aclose()
            # httpx updates its cookie jar from Set-Cookie automatically; clear
            # it so no state can follow us from one hostile host to the next.
            if self._client is not None:
                self._client.cookies.clear()
        data = bytes(body)
        return response, data, truncated, hashlib.sha256(data).hexdigest()

    def _record(self, provider: str, url: str, body: bytes, response: httpx.Response, note: str) -> str | None:
        if self.recorder is not None:
            try:
                evidence_id = self.recorder.record(
                    provider=provider,
                    request={
                        "method": "GET",
                        "url": url,
                        "note": note,
                        "isolated_fetcher": True,
                        "ip_validation": "delegated-to-proxy" if self.settings.proxy else "pinned",
                    },
                    body=body,
                    url=url,
                    status_code=response.status_code,
                    content_type=response.headers.get("content-type"),
                    retrieved_at=utcnow(),
                )
                return evidence_id or None
            except Exception:  # noqa: BLE001 - evidence capture must never break a fetch
                return None
        if self.store is None:
            return None
        try:
            record = self.store.put(
                provider=provider,
                request={
                    "method": "GET",
                    "url": url,
                    "note": note,
                    "isolated_fetcher": True,
                    "ip_validation": "delegated-to-proxy" if self.settings.proxy else "pinned",
                },
                body=body,
                url=url,
                status_code=response.status_code,
                content_type=response.headers.get("content-type"),
                retrieved_at=utcnow(),
            )
        except OSError:
            return None
        return record.id


def urljoin_safe(base: str, location: str) -> str:
    """Resolve a redirect target, tolerating odd schemes and relative paths."""
    from urllib.parse import urljoin

    location = (location or "").strip()
    if not location:
        return ""
    joined = urljoin(base, location)
    parts = urlsplit(joined)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        return ""
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def fetcher_for(
    config: Config,
    repo=None,
    *,
    investigation_id: str | None = None,
    transport=None,
    provider: str = "fetcher",
) -> IsolatedFetcher:
    """Build a fetcher bound to a repository's evidence store, if present.

    Passing ``investigation_id`` also registers each fetched body as an evidence
    row, so kit captures show up in the evidence browser and report exports.
    """
    store = getattr(repo, "evidence_store", None) if repo is not None else None
    recorder = None
    if store is not None and repo is not None and investigation_id:
        from phishtrace.core.http import EvidenceRecorder

        recorder = EvidenceRecorder(store, repo, investigation_id)
    return IsolatedFetcher(
        config,
        evidence_store=store,
        recorder=recorder,
        transport=transport,
        provider=provider,
    )
