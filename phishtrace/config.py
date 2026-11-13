"""Configuration loading for PhishTrace.

Configuration is layered:
  1. built-in defaults (safe: loopback bind, auth enabled, passive only)
  2. config.yaml (non-secret settings)
  3. .env / process environment (secrets only, never written to reports)

API keys are ONLY read from the environment (or a .env file).  They are never
accepted from config.yaml, never logged, and never exported.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.yaml"
DEFAULT_ENV_PATH = BASE_DIR / ".env"


class ConfigError(RuntimeError):
    """Raised for invalid or unsafe configuration."""


def load_dotenv(path: Path, environ: dict[str, str] | None = None) -> dict[str, str]:
    """Minimal .env loader. Existing environment variables always win.

    Supports KEY=value, KEY="value", comments and blank lines.  Never logs values.
    """
    env = environ if environ is not None else os.environ
    if not path.exists():
        return env
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if value and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if key and key not in env:
                env[key] = value
    except OSError:
        pass
    return env


class AuthConfig(BaseModel):
    enabled: bool = True
    session_secret: str | None = None
    session_ttl_hours: int = 12
    cookie_name: str = "phishtrace_session"
    cookie_secure: bool = False
    csrf: bool = True
    login_max_attempts: int = 8
    login_window_seconds: int = 300
    allow_registration: bool = False


class LimitsConfig(BaseModel):
    max_depth: int = 3
    max_children_per_node: int = 25
    max_nodes: int = 500
    global_request_budget: int = 400
    per_provider_budget: int = 60
    path_confidence_floor: float = 0.25
    min_edge_confidence: float = 0.15
    expand_weak: bool = False
    expand_medium: bool = True
    max_retries: int = 2
    retry_backoff_seconds: float = 0.7
    investigation_timeout_seconds: float = 900.0
    provider_timeout_seconds: float = 45.0
    max_sightings: int = 20
    archive_sightings: bool = True
    max_archive_snapshots: int = 20
    user_agent: str = (
        "PhishTrace/1.0 (defensive anti-phishing research; "
        "contact: security@localhost) Python-httpx"
    )

    @field_validator("max_depth", "max_children_per_node", "max_nodes")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 0:
            raise ValueError("must be >= 0")
        return v


class FetcherConfig(BaseModel):
    """Isolated fetcher used for any contact with attacker infrastructure."""

    active_fetch: bool = False
    proxy: str | None = None
    timeout: float = 12.0
    max_bytes: int = 3_000_000
    max_total_bytes: int = 20_000_000
    max_redirects: int = 5
    verify_tls: bool = True
    drop_privileges: bool = True
    restricted_user: str = "nobody"
    allow_localhost: bool = False  # ONLY for local kit-analyzer tests
    allowed_ports: list[int] = Field(default_factory=list)  # empty = all except denylist
    blocked_ports: list[int] = Field(
        default_factory=lambda: [22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 9200, 11211]
    )
    kit_paths: list[str] = Field(
        default_factory=lambda: [
            # Ordered by investigative value: open logs and configuration
            # disclosure first, archives last (the analyzer also sorts archives
            # to the back so a small probe budget is never spent on them).
            "/", "/logs", "/logs/", "/results", "/results/", "/result",
            "/config.php", "/config", "/.env", "/admin",
            "/panel", "/kit", "/logs.txt", "/log.txt", "/results.txt",
            "/stolen", "/victims", "/data", "/db", "/uploads", "/temp", "/tmp",  # nosec B108 - URL path list, not a temp file
            "/backup", "/kit.zip", "/kit.rar", "/kit.7z", "/backup.zip",
        ]
    )
    max_assets: int = 25


class ArchiverConfig(BaseModel):
    """Snapshot policy for posts and pages referenced by an investigation.

    ``save_page_now`` is off by default: it asks the Internet Archive to fetch
    attacker infrastructure on our behalf and is rate-limited upstream. The
    lookup path (existing snapshots only) is always safe and always on.
    """

    enabled: bool = True
    save_page_now: bool = False
    max_snapshots: int = 20
    timeout: float = 20.0
    lookup_existing: bool = True
    local_snapshot: bool = True


class ProviderSettings(BaseModel):
    enabled: bool = True
    weight: float = 1.0
    rate_limit: float | None = None  # requests/second
    timeout: float | None = None
    options: dict[str, Any] = Field(default_factory=dict)


class ReportConfig(BaseModel):
    company: str = "PhishTrace"
    formats: list[str] = Field(default_factory=lambda: ["html", "pdf", "json", "stix", "md", "txt", "csv"])
    tlp: str = "CLEAR"
    opencti: dict[str, Any] = Field(default_factory=dict)
    misp: dict[str, Any] = Field(default_factory=dict)
    llm_classifier: dict[str, Any] = Field(default_factory=lambda: {"enabled": False})
    cert_contacts: dict[str, str] = Field(default_factory=dict)
    #: Role -> mailbox, e.g. {"registrar": "abuse@registrar.example"}. No address
    #: is ever guessed from an organisation name; unconfigured targets are shown
    #: as manual-review items in the abuse package.
    abuse_contacts: dict[str, str] = Field(default_factory=dict)
    #: ASN number or organisation name -> mailbox at the hosting provider.
    hosting_contacts: dict[str, str] = Field(default_factory=dict)
    from_address: str = "phishtrace@localhost"
    reply_to: str = ""
    #: Include a JSON attachment with the machine-readable findings in .eml files.
    abuse_include_attachment: bool = True


#: Field-name fragments whose values are never returned by ``Config.redacted()``.
_SECRET_FIELD_MARKERS = (
    "secret", "password", "passwd", "apikey", "api_key",
    "cookie", "credential", "authorization", "auth_key",
)
_SECRET_EXACT_FIELDS = {"key", "token", "cookies", "cookie", "secret", "credentials"}
_SECRET_SUFFIXES = ("_key", "_token", "_secret", "_password", "_cookie", "_cookies")


def _is_secret_field(name: str) -> bool:
    """True for credential-bearing field names, not for ``*_env`` pointers."""
    lowered = str(name).lower()
    if lowered.endswith(("_env", "_file", "_path", "_url", "_name")):
        return False
    if lowered in _SECRET_EXACT_FIELDS or lowered.endswith(_SECRET_SUFFIXES):
        return True
    return any(marker in lowered for marker in _SECRET_FIELD_MARKERS)


def _redact_secret_fields(data: Any) -> Any:
    """Recursively replace non-empty secret-looking values with a marker.

    Used for the operator-facing config snapshot. Provider options and report
    integrations can hold credentials (GHunt cookies, MISP/OpenCTI tokens) that
    are not part of ``env`` and would otherwise be returned by ``/api/config``.
    Booleans are left alone so presence flags survive redaction.
    """
    if isinstance(data, dict):
        cleaned: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                cleaned[key] = _redact_secret_fields(value)
            elif (
                not isinstance(value, bool)
                and value not in (None, "")
                and _is_secret_field(str(key))
            ):
                cleaned[key] = "[REDACTED]"
            else:
                cleaned[key] = value
        return cleaned
    if isinstance(data, list):
        return [_redact_secret_fields(item) for item in data]
    return data


class Config(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8088
    data_dir: Path = BASE_DIR / "data"
    database_url: str | None = None
    env_file: Path = DEFAULT_ENV_PATH
    auth: AuthConfig = Field(default_factory=AuthConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    fetcher: FetcherConfig = Field(default_factory=FetcherConfig)
    archiver: ArchiverConfig = Field(default_factory=ArchiverConfig)
    providers: dict[str, ProviderSettings] = Field(default_factory=dict)
    stoplists: dict[str, str] = Field(default_factory=dict)
    default_region: str = "US"  # ISO-3166 alpha-2 fallback for phone numbers without a country code
    retention_days: int = 180
    reports: ReportConfig = Field(default_factory=ReportConfig)
    watchlist_interval_minutes: int = 0
    log_level: str = "INFO"
    env: dict[str, str] = Field(default_factory=dict, exclude=True)

    # ------------------------------------------------------------------ paths
    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def archive_dir(self) -> Path:
        return self.data_dir / "archive"

    @property
    def report_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def sqlalchemy_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{self.data_dir / 'phishtrace.db'}"

    # ------------------------------------------------------------------ keys
    def api_key(self, name: str) -> str | None:
        value = self.env.get(name, "").strip()
        return value or None

    def has_key(self, name: str) -> bool:
        return bool(self.api_key(name))

    def key_presence(self) -> dict[str, bool]:
        names = {
            "VIRUSTOTAL_API_KEY", "CENSYS_API_TOKEN", "SHODAN_API_KEY", "SECURITYTRAILS_API_KEY",
            "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY", "MALWAREBAZAAR_API_KEY",
            "WHOISXML_API_KEY", "DOMAINTOOLS_API_KEY", "VALIDIN_API_KEY", "SILENTPUSH_API_KEY",
            "OTX_API_KEY", "HYBRID_ANALYSIS_API_KEY", "MDTI_TOKEN", "X_BEARER_TOKEN",
            "YOUTUBE_API_KEY", "TELEGRAM_API_ID", "SERPAPI_KEY", "BRAVE_API_KEY",
            "INTELX_API_KEY", "DEHASHED_API_KEY", "DEHASHED_EMAIL", "PHISHTANK_API_KEY",
            "REDDIT_CLIENT_ID", "ABUSECH_AUTH_KEY", "MASTODON_TOKEN",
            "NETLAS_API_KEY", "CRIMINALIP_API_KEY", "GOOGLE_CSE_API_KEY", "GOOGLE_CSE_CX",
        }
        return {name: self.has_key(name) for name in sorted(names)}

    # ---------------------------------------------------------------- safety
    def session_secret(self) -> str:
        if self.auth.session_secret:
            return self.auth.session_secret
        # Ephemeral secret for loopback development only; non-loopback binds
        # are rejected unless an explicit secret is configured.
        if not hasattr(self, "_ephemeral_secret"):
            object.__setattr__(self, "_ephemeral_secret", secrets.token_urlsafe(48))
        return str(self.__dict__["_ephemeral_secret"])

    def validate_bind(self) -> None:
        validate_bind(self.host, self.auth.enabled, self.auth.session_secret)

    def redacted(self) -> dict[str, Any]:
        """Config snapshot safe to persist with an investigation."""
        data = _redact_secret_fields(self.model_dump(mode="json", exclude={"env", "auth"}))
        auth = _redact_secret_fields(self.auth.model_dump())
        session_secret = auth.pop("session_secret", None)
        data["auth"] = {**auth, "session_secret_set": bool(self.auth.session_secret or self.auth.enabled)}
        data["api_keys_present"] = self.key_presence()
        return data


def is_loopback_host(host: str) -> bool:
    host = (host or "").strip().strip("[]")
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_bind(host: str, auth_enabled: bool, session_secret: str | None) -> None:
    """Refuse to bind a network-reachable address without authentication."""
    if not host:
        raise ConfigError("host must not be empty")
    if is_loopback_host(host):
        return
    if not auth_enabled:
        raise ConfigError(
            f"Refusing to bind {host!r}: non-loopback addresses require authentication. "
            "Set auth.enabled=true, run 'phishtrace create-admin', and provide "
            "PHISHTRACE_SESSION_SECRET in .env."
        )
    if not session_secret or len(session_secret) < 32:
        raise ConfigError(
            f"Refusing to bind {host!r}: authentication is enabled but no strong session secret "
            "is configured. Set PHISHTRACE_SESSION_SECRET to at least 32 characters."
        )


def _env_overrides(data: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    if env.get("PHISHTRACE_HOST"):
        data["host"] = env["PHISHTRACE_HOST"]
    if env.get("PHISHTRACE_PORT"):
        data["port"] = int(env["PHISHTRACE_PORT"])
    if env.get("PHISHTRACE_DATA_DIR"):
        data["data_dir"] = env["PHISHTRACE_DATA_DIR"]
    if env.get("PHISHTRACE_DATABASE_URL"):
        data["database_url"] = env["PHISHTRACE_DATABASE_URL"]
    if env.get("PHISHTRACE_SESSION_SECRET"):
        auth = dict(data.get("auth") or {})
        auth["session_secret"] = env["PHISHTRACE_SESSION_SECRET"]
        data["auth"] = auth
    if env.get("PHISHTRACE_AUTH_ENABLED"):
        auth = dict(data.get("auth") or {})
        auth["enabled"] = env["PHISHTRACE_AUTH_ENABLED"].lower() in {"1", "true", "yes", "on"}
        data["auth"] = auth
    return data


def load_config(
    path: str | Path | None = None,
    *,
    env_file: str | Path | None = None,
    overrides: dict[str, Any] | None = None,
    validate: bool = True,
) -> Config:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    data: dict[str, Any] = {}
    if config_path.exists():
        try:
            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise ConfigError(f"{config_path} must contain a YAML mapping")
            data = loaded
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {config_path}: {exc}") from exc

    env_path = Path(env_file) if env_file else Path(data.get("env_file") or DEFAULT_ENV_PATH)
    if not env_path.is_absolute():
        env_path = config_path.parent / env_path
    env = load_dotenv(env_path)
    data = _env_overrides(data, env)
    if overrides:
        for key, value in overrides.items():
            if value is not None:
                data[key] = value

    data.setdefault("env_file", env_path)
    config = Config(**data)
    config.env = dict(env)
    if validate:
        validate_bind(config.host, config.auth.enabled, data.get("auth", {}).get("session_secret") or env.get("PHISHTRACE_SESSION_SECRET"))
    return config


def ensure_dirs(config: Config) -> None:
    for path in (config.data_dir, config.evidence_dir, config.archive_dir, config.report_dir):
        path.mkdir(parents=True, exist_ok=True)
