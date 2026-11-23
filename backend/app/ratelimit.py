"""Durable fixed-window rate limiting.

Counters live in the database rather than process memory so they survive restarts
and are shared by every uvicorn worker.  Each check is a single atomic upsert, so
two concurrent requests cannot both see "under the limit".
"""

from __future__ import annotations

import time

from sqlalchemy import text
from sqlalchemy.orm import Session

_UPSERT = text(
    """
    INSERT INTO rate_limit_buckets (key, window_start, count) VALUES (:key, :window, 1)
    ON CONFLICT(key) DO UPDATE SET
        count = CASE
            WHEN rate_limit_buckets.window_start = excluded.window_start
            THEN rate_limit_buckets.count + 1
            ELSE 1
        END,
        window_start = excluded.window_start
    RETURNING count
    """
)

_PRUNE_EXPIRED = text("DELETE FROM rate_limit_buckets WHERE window_start < :cutoff")
_KEY_COUNT = text("SELECT COUNT(*) FROM rate_limit_buckets")
_PRUNE_OLDEST = text(
    """
    DELETE FROM rate_limit_buckets WHERE key IN (
        SELECT key FROM rate_limit_buckets ORDER BY window_start ASC, key ASC LIMIT :overflow
    )
    """
)


class RateLimiter:
    """Fixed-window limiter keyed by an arbitrary string (IP, IP+email, user)."""

    def __init__(self, max_keys: int = 5000) -> None:
        self._max_keys = max_keys
        self._checks = 0

    def allow(self, db: Session, key: str, limit: int, window_seconds: float = 60.0) -> bool:
        if limit <= 0:
            return False
        window = int(time.time() // max(1.0, window_seconds))
        count = int(db.execute(_UPSERT, {"key": key[:200], "window": window}).scalar_one())
        self._checks += 1
        if self._checks % 64 == 0:
            self.prune(db, window_seconds)
        return count <= limit

    def prune(self, db: Session, window_seconds: float = 60.0) -> None:
        """Drop expired windows so the table cannot grow without bound."""
        cutoff = int(time.time() // max(1.0, window_seconds)) - 2
        db.execute(_PRUNE_EXPIRED, {"cutoff": cutoff})
        total = int(db.execute(_KEY_COUNT).scalar_one())
        if total > self._max_keys:
            db.execute(_PRUNE_OLDEST, {"overflow": total - self._max_keys})

    def size(self, db: Session) -> int:
        return int(db.execute(_KEY_COUNT).scalar_one())

    def reset(self, db: Session) -> None:
        db.execute(text("DELETE FROM rate_limit_buckets"))
        self._checks = 0
