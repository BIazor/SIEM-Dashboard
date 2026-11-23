"""Incident endpoints, including the asynchronous investigation trigger."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..agents.runner import execute_run, reap_stale_runs
from ..config import get_settings
from ..db import get_db
from ..models import Incident, InvestigationRun, ProposedAction, User
from ..ratelimit import RateLimiter
from ..schemas import (
    ActionCreate,
    ActionOut,
    IncidentDetail,
    IncidentOut,
    IncidentStatusUpdate,
    InvestigationOut,
    InvestigationQueued,
    InvestigationRunOut,
)
from ..search import like_pattern
from ..security import CurrentUser, client_ip, require_roles

router = APIRouter(prefix="/api/incidents", tags=["incidents"])
settings = get_settings()
investigation_limiter = RateLimiter()

ANALYST = require_roles("admin", "analyst")
APPROVER = require_roles("admin", "approver")

# Which statuses an incident may move to.  "closed" is terminal until reopened.
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "open": {"investigating", "awaiting_approval", "contained", "closed"},
    "investigating": {"open", "awaiting_approval", "contained", "closed"},
    "awaiting_approval": {"investigating", "contained", "closed"},
    "contained": {"open", "closed"},
    "closed": {"open"},
}


def _get_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return incident


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
        pattern = like_pattern(q)
        conditions.append(
            or_(
                Incident.title.ilike(pattern, escape="\\"),
                Incident.entity.ilike(pattern, escape="\\"),
            )
        )
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
    return IncidentDetail.model_validate(_get_incident(db, incident_id))


@router.post("/{incident_id}/investigate", response_model=InvestigationQueued, status_code=status.HTTP_202_ACCEPTED)
def investigate(
    incident_id: int,
    request: Request,
    background: BackgroundTasks,
    user: Annotated[User, Depends(ANALYST)],
    db: Session = Depends(get_db),
) -> InvestigationQueued:
    """Queue the investigator/critic pair and return immediately.

    The run is a durable record: the request does not wait for the analysis, and at
    most one run per incident can be active at a time.
    """
    incident = _get_incident(db, incident_id)
    if not investigation_limiter.allow(
        db, f"investigate:user:{user.id}", settings.investigation_rate_limit_per_minute
    ):
        db.commit()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many investigations started in the last minute",
        )

    reap_stale_runs(db)
    active = db.execute(
        select(InvestigationRun)
        .where(InvestigationRun.incident_id == incident.id)
        .where(InvestigationRun.status.in_(("queued", "running")))
    ).scalars().first()
    if active is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"An investigation is already {active.status} for this incident (run {active.id})",
        )

    run = InvestigationRun(incident_id=incident.id, status="queued", requested_by=user.email)
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        # The unique partial index caught a concurrent request for the same incident.
        db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An investigation is already queued for this incident"
        ) from None
    db.refresh(run)

    audit.record(
        db,
        action="investigation.queued",
        actor=user.email,
        actor_role=user.role,
        target=f"incident:{incident.id}",
        source_ip=client_ip(request),
        detail={"run_id": run.id},
        commit=True,
    )
    background.add_task(execute_run, run.id)
    return InvestigationQueued(run_id=run.id, incident_id=incident.id, status=run.status)


@router.get("/{incident_id}/runs", response_model=list[InvestigationRunOut])
def list_runs(
    incident_id: int,
    user: CurrentUser,
    db: Session = Depends(get_db),
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> list[InvestigationRunOut]:
    incident = _get_incident(db, incident_id)
    stmt = (
        select(InvestigationRun)
        .where(InvestigationRun.incident_id == incident.id)
        .order_by(InvestigationRun.id.desc())
        .limit(limit)
    )
    return [InvestigationRunOut.model_validate(run) for run in db.execute(stmt).scalars()]


@router.get("/{incident_id}/investigations", response_model=list[InvestigationOut])
def list_investigations(
    incident_id: int, user: CurrentUser, db: Session = Depends(get_db)
) -> list[InvestigationOut]:
    incident = _get_incident(db, incident_id)
    return [InvestigationOut.model_validate(i) for i in incident.investigations]


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    request: Request,
    user: Annotated[User, Depends(ANALYST)],
    db: Session = Depends(get_db),
) -> IncidentOut:
    incident = _get_incident(db, incident_id)
    if payload.status == "contained" and user.role not in ("admin", "approver"):
        # Containment is an outcome of an approved action, not an analyst toggle.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Recording containment requires an approver decision",
        )
    if payload.status != incident.status:
        allowed = ALLOWED_TRANSITIONS.get(incident.status, set())
        if payload.status not in allowed:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Cannot move an incident from {incident.status} to {payload.status}",
            )
    previous = incident.status
    incident.status = payload.status
    incident.updated_at = datetime.now(UTC)
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
    incident = _get_incident(db, incident_id)
    action = ProposedAction(
        incident_id=incident.id,
        action_type=payload.action_type,
        target=payload.target,
        rationale=payload.rationale,
        risk_level=payload.risk_level,
        status="pending",
        proposed_by=user.email,
        proposed_by_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(hours=max(1, settings.approval_ttl_hours)),
    )
    db.add(action)
    if incident.status in {"investigating", "open"}:
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
