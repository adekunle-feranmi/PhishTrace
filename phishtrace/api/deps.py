"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from phishtrace.api.auth import require_user


def current_user(request: Request) -> dict:
    """Authenticated principal, or a local operator when auth is disabled."""
    if not request.app.state.config.auth.enabled:
        return {"id": "local", "username": "local", "is_admin": True}
    return require_user(request)


def admin_user(request: Request) -> dict:
    user = current_user(request)
    if not user.get("is_admin"):
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="admin required")
    return user
