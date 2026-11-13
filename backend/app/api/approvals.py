"""Human approval workflow for proposed actions.

Agents can only *propose*; nothing is executed without an approver decision, and the
execution itself is a dry-run record (no real network or endpoint changes).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..models import Incident, ProposedAction, User
from ..schemas import ApprovalOut, DecisionRequest
from ..security import CurrentUser, client_ip, require_roles

router = APIRouter(prefix="/api/approvals", tags=["approvals"])

APPROVER = require_roles("admin", "approver")


@router.get("", response_model=list[ApprovalOut])
def list_approvals(
    user: CurrentUser,
    db: Session = Depends(get_db),
    approval_status: Annotated[str | None, Query(alias="status", max_length=20)] = "pending",
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[ApprovalOut]:
    stmt = select(ProposedAction, Incident).join(Incident, ProposedAction.incident_id == Incident.id)
    if approval_status:
        stmt = stmt.where(ProposedAction.status == approval_status)
    stmt = stmt.order_by(ProposedAction.requested_at.desc()).limit(limit)
    rows = db.execute(stmt).all()
    results = []
    for action, incident in rows:
        item = ApprovalOut.model_validate(
            {
                **{c.name: getattr(action, c.name) for c in action.__table__.columns},
                "incident_title": incident.title,
                "incident_severity": incident.severity,
            }
        )
        results.append(item)
    return results


@router.post("/{action_id}/decision", response_model=ApprovalOut)
def decide(
    action_id: int,
    payload: DecisionRequest,
    request: Request,
    user: Annotated[User, Depends(APPROVER)],
    db: Session = Depends(get_db),
) -> ApprovalOut:
    action = db.get(ProposedAction, action_id)
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Proposed action not found")
    if action.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Action already {action.status}")

    incident = db.get(Incident, action.incident_id)
    action.status = "approved" if payload.decision == "approve" else "rejected"
    action.decided_by_id = user.id
    action.decided_at = datetime.now(timezone.utc)
    action.decision_note = payload.note or None
    if incident is not None and action.status == "approved":
        incident.status = "contained"
        incident.updated_at = datetime.now(timezone.utc)

    audit.record(
        db,
        action=f"action.{action.status}",
        actor=user.email,
        actor_role=user.role,
        target=f"incident:{action.incident_id}:{action.action_type}:{action.target}"[:200],
        source_ip=client_ip(request),
        detail={
            "action_id": action.id,
            "note": payload.note,
            "execution": "dry-run" if action.status == "approved" else "none",
        },
    )
    db.commit()
    db.refresh(action)
    if incident is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Action has no incident")
    return ApprovalOut.model_validate(
        {
            **{c.name: getattr(action, c.name) for c in action.__table__.columns},
            "incident_title": incident.title,
            "incident_severity": incident.severity,
        }
    )
