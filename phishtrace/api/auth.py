"""Authentication, session cookies and CSRF protection.

- Passwords are hashed with Argon2id (argon2-cffi defaults).
- Sessions are signed, timestamped cookies (HttpOnly, SameSite=Lax, Secure optional).
- CSRF uses a per-session token returned by /api/session and required on mutations.
- Login attempts are rate limited in memory per client IP + username.
"""

from __future__ import annotations

import hmac
import re
import secrets
import time
from dataclasses import dataclass, field

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SESSION_SALT = "phishtrace.session.v1"
CSRF_COOKIE = "phishtrace_csrf"

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{3,64}$")


class PasswordPolicyError(ValueError):
    pass


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def validate_password(password: str, username: str = "") -> None:
    if len(password) < 12:
        raise PasswordPolicyError("password must be at least 12 characters")
    if username and username.lower() in password.lower():
        raise PasswordPolicyError("password must not contain the username")
    classes = sum(bool(re.search(pattern, password)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        raise PasswordPolicyError("password must use at least three character classes")


def validate_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username or ""))


class SessionManager:
    def __init__(
        self,
        secret: str,
        *,
        ttl_hours: int = 12,
        cookie_name: str = "phishtrace_session",
        cookie_secure: bool = False,
        csrf: bool = True,
    ):
        self.secret = secret
        self.ttl_seconds = max(60, int(ttl_hours * 3600))
        self.cookie_name = cookie_name
        self.cookie_secure = cookie_secure
        self.csrf_enabled = csrf
        self.serializer = URLSafeTimedSerializer(secret, salt=SESSION_SALT)

    def issue(self, user_id: str, username: str) -> dict:
        csrf = secrets.token_urlsafe(32)
        token = self.serializer.dumps({"uid": user_id, "u": username, "csrf": csrf})
        return {"token": token, "csrf": csrf, "max_age": self.ttl_seconds}

    def load(self, token: str | None) -> dict | None:
        if not token:
            return None
        try:
            data = self.serializer.loads(token, max_age=self.ttl_seconds)
        except (SignatureExpired, BadSignature, ValueError):
            return None
        if not isinstance(data, dict) or not data.get("uid"):
            return None
        return data

    def set_cookie(self, response, session: dict) -> None:
        response.set_cookie(
            self.cookie_name,
            session["token"],
            max_age=session["max_age"],
            httponly=True,
            samesite="lax",
            secure=self.cookie_secure,
            path="/",
        )

    def clear_cookie(self, response) -> None:
        response.delete_cookie(self.cookie_name, path="/")


@dataclass
class LoginThrottle:
    max_attempts: int = 8
    window_seconds: int = 300
    failures: dict[str, list[float]] = field(default_factory=dict)

    def _prune(self, key: str, now: float) -> list[float]:
        entries = [ts for ts in self.failures.get(key, []) if now - ts < self.window_seconds]
        self.failures[key] = entries
        return entries

    def blocked(self, key: str) -> bool:
        return len(self._prune(key, time.time())) >= self.max_attempts

    def fail(self, key: str) -> None:
        self._prune(key, time.time()).append(time.time())

    def success(self, key: str) -> None:
        self.failures.pop(key, None)

    def retry_after(self, key: str) -> int:
        entries = self._prune(key, time.time())
        if len(entries) < self.max_attempts:
            return 0
        return max(1, int(self.window_seconds - (time.time() - entries[0])))


def client_ip(request: Request) -> str:
    # Do not trust X-Forwarded-For unless a reverse proxy is documented; the
    # deployment guide sets a single trusted proxy that overwrites the header.
    return request.client.host if request.client else "unknown"


def csrf_ok(request: Request, session: dict) -> bool:
    token = request.headers.get("x-csrf-token") or request.headers.get("x-xsrf-token")
    expected = session.get("csrf")
    return bool(token and expected and hmac.compare_digest(str(token), str(expected)))


def get_session(request: Request) -> dict | None:
    manager: SessionManager = request.app.state.sessions
    return manager.load(request.cookies.get(manager.cookie_name))


def require_session(request: Request) -> dict:
    session = get_session(request)
    if not session:
        raise HTTPException(status_code=401, detail="authentication required")
    repo = request.app.state.repo
    user = repo.get_user_by_id(session["uid"])
    if not user or user.get("disabled"):
        raise HTTPException(status_code=401, detail="account disabled or removed")
    return {"session": session, "user": user}


def require_user(request: Request) -> dict:
    return require_session(request)["user"]


def require_csrf(request: Request) -> dict:
    ctx = require_session(request)
    if request.app.state.config.auth.csrf and not csrf_ok(request, ctx["session"]):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    return ctx


def issue_csrf_cookie() -> str:
    return secrets.token_urlsafe(32)
