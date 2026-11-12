"""OpenCTI integration.

OpenCTI ingests STIX 2.1 bundles through its GraphQL API.  This module keeps the
network side small and explicit: a caller must enable the integration, provide
a URL and a bearer token from the environment, and request a push.  The same
bundle is always available as a file for manual import.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

import httpx

from phishtrace.reports.misp import IntegrationError

_PUSH_MUTATION = """
mutation PhishTracePush($bundle: String!) {
  stixBundlePush(bundle: $bundle)
}
""".strip()


def _settings(settings: dict[str, Any]) -> dict[str, Any]:
    cfg = dict(settings or {})
    if not cfg.get("enabled"):
        raise IntegrationError("OpenCTI push is disabled in reports.opencti.enabled")
    url = str(cfg.get("url") or "").strip().rstrip("/")
    if not url:
        raise IntegrationError("OpenCTI is not configured: reports.opencti.url is empty")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise IntegrationError("OpenCTI URL must be an absolute http(s) URL")
    return cfg


async def push_stix_bundle(
    bundle: dict,
    settings: dict[str, Any],
    *,
    token: str | None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict:
    """Push a STIX bundle to OpenCTI's GraphQL endpoint.

    The API token is sent as a bearer token and is never included in errors.
    TLS verification defaults to true; operators with a private CA should
    configure a trusted certificate rather than disabling verification.
    """
    cfg = _settings(settings)
    if not token:
        raise IntegrationError("OpenCTI token is not configured")
    url = f"{str(cfg['url']).rstrip('/')}/graphql"
    timeout = float(cfg.get("timeout") or 30)
    verify = bool(cfg.get("verify_tls", True))
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "query": _PUSH_MUTATION,
        "variables": {"bundle": json.dumps(bundle, ensure_ascii=False, separators=(",", ":"))},
    }
    try:
        async with httpx.AsyncClient(verify=verify, timeout=timeout, transport=transport) as client:
            response = await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        raise IntegrationError(f"OpenCTI request failed: {type(exc).__name__}") from exc
    if response.status_code >= 400:
        detail = response.text[:300].replace(token, "[REDACTED]")
        raise IntegrationError(f"OpenCTI returned HTTP {response.status_code}: {detail}")
    try:
        result = response.json()
    except ValueError as exc:
        raise IntegrationError("OpenCTI returned a non-JSON response") from exc
    if result.get("errors"):
        # Do not echo arbitrary upstream messages that might contain the token.
        messages = "; ".join(str(item.get("message", "GraphQL error"))[:200] for item in result["errors"][:3])
        raise IntegrationError(f"OpenCTI rejected the bundle: {messages.replace(token, '[REDACTED]')}")
    return {"status_code": response.status_code, "response": result}
