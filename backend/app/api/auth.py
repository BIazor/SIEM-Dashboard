"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..models import User, utcnow
from ..schemas import LoginRequest, TokenResponse, UserOut
from ..security import (
    CurrentUser,
    client_ip,
    create_access_token,
    hash_password,
    login_limiter,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()

# Pre-computed hash so failed lookups take the same time as real ones.
_DUMMY_HASH = hash_password("not-a-real-password-placeholder")


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    ip = client_ip(request)
    limit = max(1, settings.login_rate_limit_per_minute)
    if not login_limiter.allow(f"ip:{ip}", limit):
        audit.record(
            db,
            action="auth.rate_limited",
            actor=payload.email,
            target="login",
            source_ip=ip,
            detail={"reason": "ip limit"},
            commit=True,
        )
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts. Try again in a minute.")
    if not login_limiter.allow(f"cred:{ip}:{payload.email}", limit):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many login attempts. Try again in a minute.")

    user = db.execute(select(User).where(User.email == payload.email)).scalars().first()
    password_ok = verify_password(payload.password, user.password_hash if user else _DUMMY_HASH)
    if user is None or not password_ok or not user.is_active:
        audit.record(
            db,
            action="auth.login_failed",
            actor=payload.email,
            target="login",
            source_ip=ip,
            detail={"reason": "invalid_credentials"},
            commit=True,
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")

    token, ttl_seconds = create_access_token(user)
    user.last_login_at = utcnow()
    audit.record(
        db,
        action="auth.login_success",
        actor=user.email,
        actor_role=user.role,
        target="login",
        source_ip=ip,
        commit=True,
    )
    return TokenResponse(access_token=token, expires_in=ttl_seconds, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)
