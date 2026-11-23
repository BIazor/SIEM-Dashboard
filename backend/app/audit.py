"""Audit logging with a tamper-evident hash chain.

Every entry commits to the hash of the entry before it.  Editing or deleting a row
breaks the chain, which ``verify_chain`` reports without needing an external store.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .context import current_request_id
from .models import AuditLog, utcnow

GENESIS = "genesis"


def _canonical(
    *,
    prev_hash: str | None,
    ts_iso: str,
    actor: str,
    actor_role: str,
    action: str,
    target: str,
    source_ip: str | None,
    request_id: str | None,
    detail: dict[str, Any],
) -> str:
    return json.dumps(
        {
            "prev": prev_hash or GENESIS,
            "ts": ts_iso,
            "actor": actor,
            "actor_role": actor_role,
            "action": action,
            "target": target,
            "source_ip": source_ip,
            "request_id": request_id,
            "detail": detail,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _digest(**fields: Any) -> str:
    return hashlib.sha256(_canonical(**fields).encode("utf-8")).hexdigest()


def record(
    db: Session,
    *,
    action: str,
    actor: str = "system",
    actor_role: str = "system",
    target: str = "",
    source_ip: str | None = None,
    detail: dict[str, Any] | None = None,
    commit: bool = False,
    request_id: str | None = None,
) -> AuditLog:
    ts = utcnow()
    previous = db.execute(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1)).scalar()
    resolved_request_id = request_id if request_id is not None else current_request_id()
    entry = AuditLog(
        ts=ts,
        action=action,
        actor=actor,
        actor_role=actor_role,
        target=target[:200],
        source_ip=source_ip,
        request_id=resolved_request_id,
        detail=detail or {},
        prev_hash=previous,
        hash=_digest(
            prev_hash=previous,
            ts_iso=ts.isoformat(),
            actor=actor,
            actor_role=actor_role,
            action=action,
            target=target[:200],
            source_ip=source_ip,
            request_id=resolved_request_id,
            detail=detail or {},
        ),
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry


def verify_chain(db: Session) -> dict[str, Any]:
    """Recompute the chain. Returns ok, checked count and the first broken row."""
    rows = list(db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars())
    hashed = [row for row in rows if row.hash]
    previous: str | None = None
    checked = 0
    for row in hashed:
        expected = _digest(
            prev_hash=row.prev_hash,
            ts_iso=row.ts.isoformat(),
            actor=row.actor,
            actor_role=row.actor_role,
            action=row.action,
            target=row.target,
            source_ip=row.source_ip,
            request_id=row.request_id,
            detail=row.detail or {},
        )
        if row.prev_hash != previous or expected != row.hash:
            return {
                "ok": False,
                "checked": checked,
                "broken_entry_id": row.id,
                "reason": "hash chain mismatch",
                "total_entries": len(rows),
            }
        previous = row.hash
        checked += 1
    return {
        "ok": True,
        "checked": checked,
        "broken_entry_id": None,
        "legacy_entries": len(rows) - len(hashed),
        "total_entries": len(rows),
    }
