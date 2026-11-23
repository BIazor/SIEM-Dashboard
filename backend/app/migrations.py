"""Schema upgrades for databases created by an earlier release.

``Base.metadata.create_all`` creates missing tables and indexes but never alters a
table that already exists, so columns added later are applied here.  Every step is
idempotent and recorded in ``schema_versions`` so a database can be upgraded in
place without being dropped.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Engine, inspect, text

from .db import Base

SCHEMA_VERSION = 1


def _ensure_version_table(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS schema_versions ("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
        )
        conn.execute(
            text("INSERT OR IGNORE INTO schema_versions (version, applied_at) VALUES (:version, :applied_at)"),
            {"version": SCHEMA_VERSION, "applied_at": datetime.now(UTC).isoformat()},
        )


def _add_missing_columns(engine: Engine) -> list[str]:
    """Add columns that the model declares but an existing database lacks."""
    inspector = inspect(engine)
    added: list[str] = []
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                continue
            existing = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                type_sql = column.type.compile(dialect=engine.dialect)
                conn.execute(
                    text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {type_sql}')
                )
                added.append(f"{table.name}.{column.name}")
    return added


def _ensure_indexes(engine: Engine) -> list[str]:
    """create_all skips existing tables, so their later indexes are created here."""
    created: list[str] = []
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            inspector = inspect(conn)
            if not inspector.has_table(table.name):
                continue
            existing = {index["name"] for index in inspector.get_indexes(table.name)}
            for index in table.indexes:
                if index.name in existing:
                    continue
                index.create(bind=conn)
                created.append(index.name or f"{table.name}.index")
    return created


def upgrade_schema(engine: Engine) -> list[str]:
    """Bring an existing database up to the current schema. Returns applied changes."""
    changes = _add_missing_columns(engine)
    changes.extend(_ensure_indexes(engine))
    _ensure_version_table(engine)
    return changes


def schema_version(engine: Engine) -> int:
    """Highest applied schema version, or 0 when the bookkeeping table is absent."""
    inspector = inspect(engine)
    if not inspector.has_table("schema_versions"):
        return 0
    with engine.connect() as conn:
        value = conn.execute(text("SELECT MAX(version) FROM schema_versions")).scalar()
    return int(value or 0)
