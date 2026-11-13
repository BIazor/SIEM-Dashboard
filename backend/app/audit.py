"""Audit logging helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .models import AuditLog


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
) -> AuditLog:
    entry = AuditLog(
        action=action,
        actor=actor,
        actor_role=actor_role,
        target=target[:200],
        source_ip=source_ip,
        detail=detail or {},
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    return entry
