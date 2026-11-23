"""Audit trail access (admin only), including chain verification."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..models import AuditLog, User
from ..schemas import AuditOut, AuditVerification
from ..security import require_roles

router = APIRouter(prefix="/api/audit", tags=["audit"])

ADMIN = require_roles("admin")


@router.get("", response_model=list[AuditOut])
def list_audit(
    user: Annotated[User, Depends(ADMIN)],
    db: Session = Depends(get_db),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    action: Annotated[str | None, Query(max_length=80)] = None,
) -> list[AuditOut]:
    stmt = select(AuditLog).order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    return [AuditOut.model_validate(entry) for entry in db.execute(stmt).scalars()]


@router.get("/verify", response_model=AuditVerification)
def verify_audit(
    user: Annotated[User, Depends(ADMIN)],
    db: Session = Depends(get_db),
) -> AuditVerification:
    """Recompute the hash chain and report the first entry that does not match."""
    return AuditVerification(**audit.verify_chain(db))
