"""Authentication endpoints: login, logout, session introspection, password change."""

from __future__ import annotations

import contextlib

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..models import User, utcnow
from ..schemas import LoginRequest, LogoutResponse, PasswordChangeRequest, TokenResponse, UserOut
from ..security import (
    CurrentUser,
    clear_session_cookie,
    client_ip,
    create_access_token,
    decode_token,
    hash_password,
    login_limiter,
    mark_password_changed,
    revoke_token,
    set_session_cookie,
    token_from_request,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()

# Pre-computed hash so failed lookups take the same time as real ones.
_DUMMY_HASH = hash_password("not-a-real-password-placeholder")


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    ip = client_ip(request)
    limit = max(1, settings.login_rate_limit_per_minute)
    if not login_limiter.allow(db, f"ip:{ip}", limit):
        db.commit()
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
    if not login_limiter.allow(db, f"cred:{ip}:{payload.email}", limit):
        db.commit()
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
    set_session_cookie(response, token, ttl_seconds)
    audit.record(
        db,
        action="auth.login_success",
        actor=user.email,
        actor_role=user.role,
        target="login",
        source_ip=ip,
        detail={"cookie": True},
        commit=True,
    )
    return TokenResponse(access_token=token, expires_in=ttl_seconds, user=UserOut.model_validate(user))


@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request,
    response: Response,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> LogoutResponse:
    """Revoke the presented token and clear the session cookie."""
    token = token_from_request(request)
    if token:
        # An expired or already invalid token is still a successful logout.
        with contextlib.suppress(HTTPException):
            revoke_token(db, decode_token(token), reason="logout")
    clear_session_cookie(response)
    audit.record(
        db,
        action="auth.logout",
        actor=user.email,
        actor_role=user.role,
        target="logout",
        source_ip=client_ip(request),
        detail={},
        commit=True,
    )
    return LogoutResponse()


@router.post("/password", response_model=LogoutResponse)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    response: Response,
    user: CurrentUser,
    db: Session = Depends(get_db),
) -> LogoutResponse:
    """Change the caller's password and invalidate every token issued before it."""
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    if payload.new_password == payload.current_password:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "New password must differ from the current one")
    if len(payload.new_password) < max(1, settings.min_password_length):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"New password must be at least {settings.min_password_length} characters",
        )
    user.password_hash = hash_password(payload.new_password)
    mark_password_changed(user)
    clear_session_cookie(response)
    audit.record(
        db,
        action="auth.password_changed",
        actor=user.email,
        actor_role=user.role,
        target="password",
        source_ip=client_ip(request),
        detail={},
        commit=True,
    )
    return LogoutResponse()


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> UserOut:
    return UserOut.model_validate(user)
