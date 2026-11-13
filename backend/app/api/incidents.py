"""Incident endpoints, including the investigation trigger."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .. import audit
from ..agents.orchestrator import run_investigation
from ..db import get_db
from ..models import Incident, ProposedAction, User
from ..schemas import (
    ActionCreate,
    ActionOut,
    IncidentDetail,
    IncidentOut,
    IncidentStatusUpdate,
    InvestigationOut,
)
from ..security import CurrentUser, client_ip, require_roles

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

ANALYST = require_roles("admin", "analyst")


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    user: CurrentUser,
    db: Session = Depends(get_db),
    incident_status: Annotated[str | None, Query(alias="status", max_length=24)] = None,
    severity: Annotated[str | None, Query(max_length=16)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> list[IncidentOut]:
    conditions: list = []
    if incident_status:
        conditions.append(Incident.status == incident_status)
    if severity:
        conditions.append(Incident.severity == severity)
    if q:
        needle = q.replace("%", "").replace("_", "")
        conditions.append(or_(Incident.title.ilike(f"%{needle}%"), Incident.entity.ilike(f"%{needle}%")))
    stmt = (
        select(Incident)
        .where(*conditions)
        .order_by(Incident.priority.asc(), Incident.last_seen.desc())
        .limit(limit)
        .offset(offset)
    )
    return [IncidentOut.model_validate(i) for i in db.execute(stmt).scalars()]


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, user: CurrentUser, db: Session = Depends(get_db)) -> IncidentDetail:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return IncidentDetail.model_validate(incident)


@router.get("/{incident_id}/investigations", response_model=list[InvestigationOut])
def list_investigations(
    incident_id: int, user: CurrentUser, db: Session = Depends(get_db)
) -> list[InvestigationOut]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return [InvestigationOut.model_validate(i) for i in incident.investigations]


@router.post("/{incident_id}/investigate", response_model=IncidentDetail)
def investigate(
    incident_id: int,
    request: Request,
    user: Annotated[User, Depends(ANALYST)],
    db: Session = Depends(get_db),
) -> IncidentDetail:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    run_investigation(
        db,
        incident,
        actor_label=user.email,
        actor_role=user.role,
        source_ip=client_ip(request),
    )
    db.refresh(incident)
    return IncidentDetail.model_validate(incident)


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    request: Request,
    user: Annotated[User, Depends(ANALYST)],
    db: Session = Depends(get_db),
) -> IncidentOut:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    if payload.status == "contained" and user.role not in ("admin", "approver"):
        # Containment is an outcome of an approved action, not an analyst toggle.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Recording containment requires an approver decision",
        )
    previous = incident.status
    incident.status = payload.status
    incident.updated_at = datetime.now(timezone.utc)
    audit.record(
        db,
        action="incident.status_changed",
        actor=user.email,
        actor_role=user.role,
        target=f"incident:{incident.id}",
        source_ip=client_ip(request),
        detail={"from": previous, "to": payload.status},
        commit=True,
    )
    db.refresh(incident)
    return IncidentOut.model_validate(incident)


@router.post("/{incident_id}/actions", response_model=ActionOut, status_code=status.HTTP_201_CREATED)
def propose_action(
    incident_id: int,
    payload: ActionCreate,
    request: Request,
    user: Annotated[User, Depends(ANALYST)],
    db: Session = Depends(get_db),
) -> ActionOut:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    action = ProposedAction(
        incident_id=incident.id,
        action_type=payload.action_type,
        target=payload.target,
        rationale=payload.rationale,
        risk_level=payload.risk_level,
        status="pending",
        proposed_by=user.email,
    )
    db.add(action)
    if incident.status == "investigating":
        incident.status = "awaiting_approval"
    audit.record(
        db,
        action="action.proposed",
        actor=user.email,
        actor_role=user.role,
        target=f"incident:{incident.id}:{payload.action_type}:{payload.target}"[:200],
        source_ip=client_ip(request),
        detail={"risk_level": payload.risk_level},
    )
    db.commit()
    db.refresh(action)
    return ActionOut.model_validate(action)
