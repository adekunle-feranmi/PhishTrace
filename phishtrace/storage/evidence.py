"""Content-addressed evidence store.

Every provider response is preserved with:
  - raw bytes on disk (never rewritten)
  - SHA-256 of those bytes
  - retrieval timestamp (UTC)
  - provider name and request parameters (secrets redacted)
  - a metadata sidecar for the evidence browser

The store is intentionally append-only: identical bytes deduplicate by hash,
but each distinct request keeps its own metadata record.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from phishtrace.models import iso, utcnow

SENSITIVE_PARAMS = {
    "key", "api_key", "apikey", "api-key", "token", "access_token", "auth",
    "authorization", "x-apikey", "secret", "password", "passwd", "session",
}
REDACTED = "[REDACTED]"


def redact_mapping(data: Any) -> Any:
    """Recursively redact secret-looking keys from request metadata."""
    if isinstance(data, dict):
        out = {}
        for key, value in data.items():
            lk = str(key).lower()
            if any(s in lk for s in SENSITIVE_PARAMS):
                out[key] = REDACTED
            elif lk in {"headers", "header"} and isinstance(value, dict):
                out[key] = {
                    hk: (REDACTED if any(s in hk.lower() for s in SENSITIVE_PARAMS) else hv)
                    for hk, hv in value.items()
                }
            else:
                out[key] = redact_mapping(value)
        return out
    if isinstance(data, list):
        return [redact_mapping(item) for item in data]
    return data


def redact_url(url: str | None) -> str | None:
    """Return ``url`` with secret-looking query values replaced by ``[REDACTED]``.

    Providers that must authenticate through the query string (Shodan, WhoisXML)
    otherwise write the live key into the evidence table, where it outlives the
    request and is shown by the evidence browser.
    """
    if not url or "?" not in url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if not parts.query:
        return url
    rendered: list[str] = []
    for pair in parts.query.split("&"):
        if not pair:
            continue
        name = pair.partition("=")[0]
        if any(marker in name.lower() for marker in SENSITIVE_PARAMS):
            rendered.append(f"{name}={REDACTED}")
        else:
            rendered.append(pair)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(rendered), parts.fragment))


@dataclass
class EvidenceRecord:
    id: str
    provider: str
    request: dict
    raw_response_path: str
    sha256: str
    retrieved_at: datetime
    url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    size_bytes: int = 0
    dedupe_key: str = ""
    meta: dict = field(default_factory=dict)

    def to_row(self) -> dict:
        return {
            "id": self.id,
            "provider": self.provider,
            "request": self.request,
            "raw_response_path": self.raw_response_path,
            "sha256": self.sha256,
            "retrieved_at": self.retrieved_at,
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "dedupe_key": self.dedupe_key,
        }


class EvidenceStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _paths(self, sha: str) -> tuple[Path, Path]:
        directory = self.root / sha[:2]
        directory.mkdir(parents=True, exist_ok=True)
        return directory / f"{sha}.bin", directory / f"{sha}.meta.json"

    def put(
        self,
        *,
        provider: str,
        request: dict,
        body: bytes,
        url: str | None = None,
        status_code: int | None = None,
        content_type: str | None = None,
        retrieved_at: datetime | None = None,
        dedupe_extra: str = "",
    ) -> EvidenceRecord:
        import uuid

        retrieved = retrieved_at or utcnow()
        sha = hashlib.sha256(body).hexdigest()
        raw_path, meta_path = self._paths(sha)
        if not raw_path.exists():
            self._atomic_write(raw_path, body)
        safe_request = redact_mapping(request)
        safe_url = redact_url(url)
        meta = {
            "provider": provider,
            "request": safe_request,
            "url": safe_url,
            "status_code": status_code,
            "content_type": content_type,
            "sha256": sha,
            "size_bytes": len(body),
            "retrieved_at": iso(retrieved),
        }
        if not meta_path.exists():
            self._atomic_write(
                meta_path,
                json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8"),
            )
        request_key = json.dumps(safe_request, sort_keys=True, default=str)
        dedupe = hashlib.sha256(
            f"{provider}|{sha}|{request_key}|{dedupe_extra}".encode("utf-8")
        ).hexdigest()
        return EvidenceRecord(
            id=uuid.uuid4().hex,
            provider=provider,
            request=safe_request,
            raw_response_path=str(raw_path),
            sha256=sha,
            retrieved_at=retrieved,
            url=safe_url,
            status_code=status_code,
            content_type=content_type,
            size_bytes=len(body),
            dedupe_key=dedupe,
            meta=meta,
        )

    def put_text(self, **kwargs) -> EvidenceRecord:
        body = str(kwargs.pop("text", "")).encode("utf-8", errors="replace")
        return self.put(body=body, **kwargs)

    @staticmethod
    def _atomic_write(path: Path, body: bytes) -> None:
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def read(self, record_or_path: EvidenceRecord | str) -> bytes:
        path = record_or_path.raw_response_path if isinstance(record_or_path, EvidenceRecord) else record_or_path
        return Path(path).read_bytes()

    def read_text(self, record_or_path: EvidenceRecord | str, limit: int = 200_000) -> str:
        data = self.read(record_or_path)
        return data[:limit].decode("utf-8", errors="replace")

    def meta(self, record_or_path: EvidenceRecord | str) -> dict:
        if isinstance(record_or_path, EvidenceRecord):
            return record_or_path.meta
        path = Path(record_or_path)
        meta_path = path.with_suffix(".meta.json") if path.suffix == ".bin" else path
        if meta_path.exists():
            return json.loads(meta_path.read_text(encoding="utf-8"))
        return {}
