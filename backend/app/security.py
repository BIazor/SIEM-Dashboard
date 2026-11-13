"""Authentication primitives: password hashing, JWT issuing and RBAC dependencies."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Annotated, Callable

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import User

_settings = get_settings()

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32

_bearer = HTTPBearer(auto_error=False)


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
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=ttl)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_urlsafe(16),
    }
    token = jwt.encode(payload, _settings.resolved_secret_key(), algorithm=_settings.jwt_algorithm)
    return token, ttl * 60


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            _settings.resolved_secret_key(),
            algorithms=[_settings.jwt_algorithm],
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials") from exc


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        # A structurally valid token with a malformed subject must not 500.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials") from exc
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account unavailable")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_roles(*roles: str) -> Callable[[User], User]:
    """Dependency factory enforcing role based access control."""

    def _guard(user: CurrentUser) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions for this action")
        return user

    return _guard


class RateLimiter:
    """Fixed-window limiter keyed by an arbitrary string (IP, IP+email).

    Keys are pruned periodically and the map is capped so an attacker cannot grow it
    without bound by cycling emails or source addresses.
    """

    def __init__(self, max_keys: int = 5000) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._max_keys = max_keys
        self._calls = 0

    def allow(self, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        now = time.monotonic()
        self._calls += 1
        if self._calls % 256 == 0 or len(self._hits) > self._max_keys:
            self._prune(now, window_seconds)
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        if len(self._hits) > self._max_keys:
            self._prune(now, window_seconds)
        return True

    def _prune(self, now: float, window_seconds: float) -> None:
        stale = [key for key, bucket in self._hits.items() if not bucket or now - bucket[-1] > window_seconds]
        for key in stale:
            self._hits.pop(key, None)
        overflow = len(self._hits) - self._max_keys
        if overflow > 0:
            oldest = sorted(self._hits.items(), key=lambda item: item[1][-1] if item[1] else 0.0)
            for key, _bucket in oldest[:overflow]:
                self._hits.pop(key, None)

    @property
    def size(self) -> int:
        return len(self._hits)

    def reset(self) -> None:
        self._hits.clear()
        self._calls = 0


login_limiter = RateLimiter()


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
