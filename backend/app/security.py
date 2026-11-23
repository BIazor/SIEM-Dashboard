"""Authentication primitives: password hashing, JWT issuing, session cookies and RBAC."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from urllib.parse import urlsplit

import jwt
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import RevokedToken, User, utcnow
from .ratelimit import RateLimiter

_settings = get_settings()

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32

_bearer = HTTPBearer(auto_error=False)
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Kept for backwards compatibility with callers that import it from here.
login_limiter = RateLimiter()


def hash_password(password: str) -> str:
    """Hash a password with scrypt (memory-hard, available in the stdlib)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=64 * 1024 * 1024,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(digest_hex)),
            maxmem=64 * 1024 * 1024,
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


def create_access_token(user: User, ttl_minutes: int | None = None) -> tuple[str, int]:
    ttl = ttl_minutes or _settings.access_token_ttl_minutes
    now = datetime.now(UTC)
    expires = now + timedelta(minutes=ttl)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_urlsafe(16),
        "epoch": int(user.token_epoch or 0),
        "iss": _settings.jwt_issuer,
        "aud": _settings.jwt_audience,
    }
    token = jwt.encode(payload, _settings.resolved_secret_key(), algorithm=_settings.jwt_algorithm)
    return token, ttl * 60


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            _settings.resolved_secret_key(),
            algorithms=[_settings.jwt_algorithm],
            audience=_settings.jwt_audience,
            issuer=_settings.jwt_issuer,
            options={"require": ["exp", "sub", "iat", "jti"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials") from exc


def revoke_token(db: Session, payload: dict, reason: str = "logout") -> None:
    """Record a token identifier so it can never be used again."""
    jti = str(payload.get("jti") or "")
    if not jti:
        return
    expires = datetime.fromtimestamp(int(payload.get("exp", 0)), tz=UTC)
    if expires <= datetime.now(UTC):
        return
    existing = db.get(RevokedToken, jti)
    if existing is None:
        db.add(
            RevokedToken(
                jti=jti,
                user_id=int(payload.get("sub", 0) or 0),
                expires_at=expires,
                reason=reason[:40],
            )
        )


def assert_same_origin(request: Request) -> None:
    """Reject cross-site state changes that ride on the session cookie.

    Browsers send ``Origin`` on every non-GET request; requiring it to match either
    this host or a configured frontend origin blocks CSRF without a token dance.
    """
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Cross-site request rejected: missing Origin")
    host = urlsplit(origin).netloc.lower()
    request_host = (request.headers.get("host") or "").lower()
    allowed = {urlsplit(value).netloc.lower() for value in _settings.cors_origin_list}
    if host == request_host or host in allowed:
        return
    raise HTTPException(status.HTTP_403_FORBIDDEN, "Cross-site request rejected")


def token_from_request(request: Request) -> str | None:
    authorization = request.headers.get("authorization") or ""
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return request.cookies.get(_settings.session_cookie_name) or None


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    header_token = credentials.credentials if credentials and credentials.credentials else None
    cookie_token = request.cookies.get(_settings.session_cookie_name)
    token = header_token or cookie_token
    if not token:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if header_token is None and cookie_token and request.method.upper() in _UNSAFE_METHODS:
        # Cookie-authenticated mutations must prove they come from our own origin.
        assert_same_origin(request)

    payload = decode_token(token)
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        # A structurally valid token with a malformed subject must not 500.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials") from exc

    jti = str(payload.get("jti") or "")
    if not jti or db.get(RevokedToken, jti) is not None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session revoked")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account unavailable")

    if int(payload.get("epoch") or 0) != int(user.token_epoch or 0):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Password changed; sign in again")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: str) -> Callable[[User], User]:
    """Dependency factory enforcing role based access control."""

    def _guard(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions for this action")
        return user

    return _guard


def set_session_cookie(response: Response, token: str, max_age: int) -> None:
    response.set_cookie(
        key=_settings.session_cookie_name,
        value=token,
        max_age=max_age,
        httponly=True,
        secure=_settings.cookie_secure,
        samesite=_settings.cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=_settings.session_cookie_name,
        path="/",
        httponly=True,
        secure=_settings.cookie_secure,
        samesite=_settings.cookie_samesite,
    )


def mark_password_changed(user: User) -> None:
    """Invalidate every token minted under the previous epoch."""
    user.password_changed_at = utcnow()
    user.token_epoch = int(user.token_epoch or 0) + 1


def client_ip(request: Request) -> str:
    """Resolve the client address.

    ``X-Forwarded-For`` is attacker-controlled unless a proxy you operate overwrites
    it, so it is only honoured when ``TRUST_PROXY_HEADERS`` is explicitly enabled.
    """
    if _settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"
