"""Database engine, session management and base model."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
_settings.data_dir.mkdir(parents=True, exist_ok=True)

IS_SQLITE = _settings.database_url.startswith("sqlite")

_connect_args: dict = {}
if IS_SQLITE:
    _connect_args = {
        "check_same_thread": False,
        # Seconds to wait for a competing writer before raising "database is locked".
        "timeout": max(1.0, _settings.sqlite_busy_timeout_ms / 1000),
    }

engine = create_engine(_settings.database_url, connect_args=_connect_args, future=True)

if IS_SQLITE:

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _record):  # pragma: no cover - driver hook
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute(f"PRAGMA busy_timeout={int(_settings.sqlite_busy_timeout_ms)}")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def begin_immediate(db: Session) -> None:
    """Take SQLite's write lock before reading state that a write depends on.

    Ingest decides whether an alert or incident already exists and then inserts it;
    without an immediate transaction two concurrent batches can both pass the check.
    The lock is a no-op on other backends (they rely on row-level locking).
    """
    if not IS_SQLITE:
        return
    with contextlib.suppress(OperationalError):  # pragma: no cover - a transaction was already open
        db.execute(text("BEGIN IMMEDIATE"))


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)
    from .migrations import upgrade_schema

    upgrade_schema(engine)
