"""FastAPI application factory."""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from phishtrace import __version__
from phishtrace.api.auth import (
    CSRF_COOKIE, LoginThrottle, SessionManager, client_ip, hash_password, issue_csrf_cookie,
    require_csrf, validate_password, validate_username, verify_password,
)
from phishtrace.api.deps import current_user
from phishtrace.config import Config, ensure_dirs, load_config
from phishtrace.core.registry import Registry
from phishtrace.models import iso, utcnow
from phishtrace.storage.db import init_db
from phishtrace.storage.evidence import EvidenceStore
from phishtrace.storage.repository import Repository

UI_DIR = Path(__file__).resolve().parent.parent / "ui"
TEMPLATES = Environment(
    loader=FileSystemLoader(str(UI_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)


def create_app(
    config: Config | None = None,
    *,
    repo: Repository | None = None,
    registry: Registry | None = None,
    sessions: SessionManager | None = None,
) -> FastAPI:
    config = config or load_config()
    ensure_dirs(config)
    if repo is None:
        engine, factory = init_db(config.sqlalchemy_url, config.data_dir)
        repo = Repository(factory, EvidenceStore(config.evidence_dir))
        config._engine = engine  # type: ignore[attr-defined]
    registry = registry or Registry(config)
    sessions = sessions or SessionManager(
        config.session_secret(),
        ttl_hours=config.auth.session_ttl_hours,
        cookie_name=config.auth.cookie_name,
        cookie_secure=config.auth.cookie_secure,
        csrf=config.auth.csrf,
    )

    app = FastAPI(
        title="PhishTrace",
        version=__version__,
        docs_url="/api/docs" if not config.auth.enabled else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if not config.auth.enabled else None,
    )
    app.state.config = config
    app.state.repo = repo
    app.state.registry = registry
    app.state.sessions = sessions
    app.state.throttle = LoginThrottle(
        max_attempts=config.auth.login_max_attempts,
        window_seconds=config.auth.login_window_seconds,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        if request.url.path.startswith("/api/") or request.url.path == "/health":
            response.headers.setdefault("Cache-Control", "no-store")
        if config.auth.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    # ------------------------------------------------------------------ health
    @app.get("/health")
    async def health():
        statuses = registry.statuses()
        return {
            "status": "ok",
            "app": "PhishTrace",
            "version": __version__,
            "time": iso(utcnow()),
            "auth_enabled": config.auth.enabled,
            "active_fetch": config.fetcher.active_fetch,
            "providers": {
                "total": len(statuses),
                "enabled": sum(1 for s in statuses if s.status == "enabled"),
                "skipped": sum(1 for s in statuses if s.status == "skipped"),
                "failed": sum(1 for s in statuses if s.status == "failed"),
            },
            "database": "ok" if repo.count_users() >= 0 else "error",
        }

    # -------------------------------------------------------------------- auth
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, error: str | None = None, next: str = "/"):
        if config.auth.enabled and request.cookies.get(config.auth.cookie_name):
            session = sessions.load(request.cookies.get(config.auth.cookie_name))
            if session:
                return RedirectResponse("/", status_code=303)
        csrf = issue_csrf_cookie()
        template = TEMPLATES.get_template("login.html")
        html = template.render(csrf_token=csrf, error=error, next_url=next,
                               app_version=__version__, auth_enabled=config.auth.enabled)
        response = HTMLResponse(html)
        response.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="strict",
                            secure=sessions.cookie_secure, max_age=1800, path="/")
        return response

    @app.post("/login")
    async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        csrf_token: str = Form(default=""),
        next_url: str = Form(default="/"),
    ):
        cookie_token = request.cookies.get(CSRF_COOKIE, "")
        if not csrf_token or not secrets.compare_digest(csrf_token, cookie_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
        if not config.auth.enabled:
            return RedirectResponse("/", status_code=303)
        ip = client_ip(request)
        key = f"{ip}|{username.lower()[:64]}"
        if app.state.throttle.blocked(key):
            retry = app.state.throttle.retry_after(key)
            raise HTTPException(status_code=429, detail=f"too many login attempts; retry in {retry}s",
                                headers={"Retry-After": str(retry)})
        user = repo.get_user(username)
        if not user or not verify_password(password, user["password_hash"] or ""):
            app.state.throttle.fail(key)
            repo.audit(actor=username[:64], action="login_failed", ip=ip)
            csrf = issue_csrf_cookie()
            template = TEMPLATES.get_template("login.html")
            response = HTMLResponse(
                template.render(csrf_token=csrf, error="Invalid username or password",
                                next_url=next_url, app_version=__version__, auth_enabled=True),
                status_code=401,
            )
            response.set_cookie(CSRF_COOKIE, csrf, httponly=False, samesite="strict",
                                secure=sessions.cookie_secure, max_age=1800, path="/")
            return response
        if user.get("disabled"):
            raise HTTPException(status_code=403, detail="account disabled")
        app.state.throttle.success(key)
        repo.touch_login(user["id"])
        repo.audit(actor=user["username"], action="login", ip=ip)
        session = sessions.issue(user["id"], user["username"])
        target = next_url if next_url.startswith("/") and not next_url.startswith("//") else "/"
        response = RedirectResponse(target, status_code=303)
        sessions.set_cookie(response, session)
        response.delete_cookie(CSRF_COOKIE, path="/")
        return response

    @app.post("/logout")
    async def logout(request: Request):
        ctx = require_csrf(request) if config.auth.enabled else None
        response = RedirectResponse("/login", status_code=303)
        sessions.clear_cookie(response)
        if ctx:
            repo.audit(actor=ctx["user"]["username"], action="logout", ip=client_ip(request))
        return response

    @app.get("/api/session")
    async def session_info(request: Request, user: dict = Depends(current_user)):
        session = sessions.load(request.cookies.get(sessions.cookie_name)) if config.auth.enabled else None
        return {
            "authenticated": True,
            "user": {"username": user.get("username"), "is_admin": user.get("is_admin", True)},
            "csrf": session.get("csrf") if session else "",
            "auth_enabled": config.auth.enabled,
            "version": __version__,
        }

    # --------------------------------------------------------------- providers
    @app.get("/api/providers")
    async def providers(request: Request, user: dict = Depends(current_user)):
        return {
            "summary": registry.summary(),
            "providers": [s.model_dump() for s in registry.statuses()],
            "active_fetch": config.fetcher.active_fetch,
        }

    @app.get("/api/audit")
    async def audit_log(request: Request, user: dict = Depends(current_user), limit: int = 200):
        if not user.get("is_admin", True):
            raise HTTPException(status_code=403, detail="admin required")
        return {"entries": repo.list_audit(limit=min(max(limit, 1), 1000))}

    @app.get("/api/config")
    async def safe_config(request: Request, user: dict = Depends(current_user)):
        """Redacted configuration for the coverage/settings panel."""
        return config.redacted()

    # ------------------------------------------------------------ investigation
    from phishtrace.api.routes import router as investigation_router
    app.include_router(investigation_router)

    # ------------------------------------------------------------------- static
    static_dir = UI_DIR / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        if config.auth.enabled:
            session = sessions.load(request.cookies.get(sessions.cookie_name))
            if not session:
                return RedirectResponse("/login", status_code=303)
            user = repo.get_user_by_id(session["uid"])
            if not user or user.get("disabled"):
                response = RedirectResponse("/login", status_code=303)
                sessions.clear_cookie(response)
                return response
        template = TEMPLATES.get_template("index.html")
        return HTMLResponse(template.render(app_version=__version__, auth_enabled=config.auth.enabled))

    @app.exception_handler(404)
    async def not_found(request: Request, exc):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "not found"}, status_code=404)
        return HTMLResponse("<h1>404</h1>", status_code=404)

    return app


def create_admin(config: Config, repo: Repository, username: str, password: str) -> dict:
    if not validate_username(username):
        raise ValueError("username must be 3-64 chars: letters, digits, . _ @ -")
    validate_password(password, username)
    result = repo.create_user(username, hash_password(password), is_admin=True)
    repo.audit(actor=username, action="create_admin", detail={"created": result["created"]})
    return result
