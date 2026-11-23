"""Human approval workflow for proposed actions.

Agents can only *propose*; nothing is executed without an approver decision, and the
execution itself is a dry-run record (no real network or endpoint changes).  An
approver may not decide on an action they proposed themselves, and one approval no
longer closes an incident that still has actions waiting.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..models import Incident, ProposedAction, User
from ..schemas import ApprovalOut, DecisionRequest
from ..security import CurrentUser, client_ip, require_roles

router = APIRouter(prefix="/api/approvals", tags=["approvals"])

APPROVER = require_roles("admin", "approver")

DRY_RUN_NOTE = "Dry run recorded: no network or endpoint change was performed."


def expire_stale_actions(db: Session, now: datetime | None = None) -> int:
    """Mark pending actions past their deadline as expired so queues stay honest."""
    now = now or datetime.now(UTC)
    result = db.execute(
        update(ProposedAction)
        .where(ProposedAction.status == "pending")
        .where(ProposedAction.expires_at.is_not(None))
        .where(ProposedAction.expires_at < now)
        .values(status="expired", execution_status="none", decision_note="Expired without a decision")
    )
    if result.rowcount:
        db.commit()
    return int(result.rowcount or 0)


def _approval_payload(action: ProposedAction, incident: Incident) -> ApprovalOut:
    values = {column.name: getattr(action, column.name) for column in action.__table__.columns}
    values.update({"incident_title": incident.title, "incident_severity": incident.severity})
    return ApprovalOut.model_validate(values)


def _containment_state(db: Session, incident: Incident) -> None:
    """Contain an incident only once nothing is left waiting for a decision."""
    pending = db.execute(
        select(ProposedAction.id)
        .where(ProposedAction.incident_id == incident.id)
        .where(ProposedAction.status == "pending")
    ).first()
    if pending is not None:
        return
    approved = db.execute(
        select(ProposedAction.id)
        .where(ProposedAction.incident_id == incident.id)
        .where(ProposedAction.status == "approved")
    ).first()
    if approved is not None and incident.status != "closed":
        incident.status = "contained"
        incident.updated_at = datetime.now(UTC)


@router.get("", response_model=list[ApprovalOut])
def list_approvals(
    user: CurrentUser,
    db: Session = Depends(get_db),
    approval_status: Annotated[str | None, Query(alias="status", max_length=20)] = "pending",
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
) -> list[ApprovalOut]:
    expire_stale_actions(db)
    stmt = select(ProposedAction, Incident).join(Incident, ProposedAction.incident_id == Incident.id)
    if approval_status:
        stmt = stmt.where(ProposedAction.status == approval_status)
    stmt = stmt.order_by(ProposedAction.requested_at.desc()).limit(limit)
    return [
        _approval_payload(action, incident) for action, incident in db.execute(stmt).all()
    ]


@router.post("/{action_id}/decision", response_model=ApprovalOut)
def decide(
    action_id: int,
    payload: DecisionRequest,
    request: Request,
    user: Annotated[User, Depends(APPROVER)],
    db: Session = Depends(get_db),
) -> ApprovalOut:
    expire_stale_actions(db)
    action = db.get(ProposedAction, action_id)
    if action is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Proposed action not found")
    if action.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, f"Action already {action.status}")
    if action.proposed_by_id is not None and action.proposed_by_id == user.id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Segregation of duties: an approver cannot decide on their own proposal",
        )

    incident = db.get(Incident, action.incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Action has no incident")

    now = datetime.now(UTC)
    decision = "approved" if payload.decision == "approve" else "rejected"
    values = {
        "status": decision,
        "decided_by_id": user.id,
        "decided_at": now,
        "decision_note": payload.note or None,
        "execution_status": "dry_run" if decision == "approved" else "none",
        "execution_note": DRY_RUN_NOTE if decision == "approved" else None,
        "executed_at": now if decision == "approved" else None,
    }
    # Conditional update: two approvers clicking at once cannot both decide.
    result = db.execute(
        update(ProposedAction)
        .where(ProposedAction.id == action_id)
        .where(ProposedAction.status == "pending")
        .values(**values)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Action was already decided")

    db.refresh(action)
    if decision == "approved":
        _containment_state(db, incident)

    audit.record(
        db,
        action=f"action.{decision}",
        actor=user.email,
        actor_role=user.role,
        target=f"incident:{action.incident_id}:{action.action_type}:{action.target}"[:200],
        source_ip=client_ip(request),
        detail={
            "action_id": action.id,
            "note": payload.note,
            "execution": values["execution_status"],
            "proposed_by": action.proposed_by,
            "proposal_owner_id": action.proposed_by_id,
        },
    )
    db.commit()
    db.refresh(action)
    return _approval_payload(action, incident)
