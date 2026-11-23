"""Alert browsing endpoints (authenticated, read-only)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import SEVERITIES, Alert
from ..schemas import AlertOut, AlertPage
from ..search import like_pattern
from ..security import CurrentUser

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _conditions(
    severity: list[str] | None,
    alert_status: str | None,
    category: str | None,
    q: str | None,
    host: str | None,
    src_ip: str | None,
    incident_id: int | None,
    since: datetime | None,
    until: datetime | None,
) -> list:
    conditions: list = []
    if severity:
        invalid = set(severity) - set(SEVERITIES)
        if invalid:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, f"Unknown severity: {sorted(invalid)}")
        conditions.append(Alert.severity.in_(severity))
    if alert_status:
        conditions.append(Alert.status == alert_status)
    if category:
        conditions.append(Alert.category == category)
    if host:
        conditions.append(Alert.host == host)
    if src_ip:
        conditions.append(Alert.src_ip == src_ip)
    if incident_id:
        conditions.append(Alert.incident_id == incident_id)
    if since:
        conditions.append(Alert.event_time >= since)
    if until:
        conditions.append(Alert.event_time <= until)
    if q:
        pattern = like_pattern(q)
        conditions.append(
            or_(
                Alert.title.ilike(pattern, escape="\\"),
                Alert.description.ilike(pattern, escape="\\"),
                Alert.host.ilike(pattern, escape="\\"),
                Alert.src_ip.ilike(pattern, escape="\\"),
                Alert.username.ilike(pattern, escape="\\"),
            )
        )
    return conditions


@router.get("", response_model=AlertPage)
def list_alerts(
    user: CurrentUser,
    db: Session = Depends(get_db),
    severity: Annotated[list[str] | None, Query()] = None,
    alert_status: Annotated[str | None, Query(alias="status", max_length=20)] = None,
    category: Annotated[str | None, Query(max_length=32)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    host: Annotated[str | None, Query(max_length=120)] = None,
    src_ip: Annotated[str | None, Query(max_length=64)] = None,
    incident_id: Annotated[int | None, Query(ge=1)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
) -> AlertPage:
    conditions = _conditions(severity, alert_status, category, q, host, src_ip, incident_id, since, until)
    total = db.scalar(select(func.count(Alert.id)).where(*conditions)) or 0
    stmt = (
        select(Alert)
        .where(*conditions)
        .order_by(Alert.event_time.desc(), Alert.id.desc())
        .limit(limit)
        .offset(offset)
    )
    alerts = list(db.execute(stmt).scalars())
    return AlertPage(
        items=[AlertOut.model_validate(a) for a in alerts],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, user: CurrentUser, db: Session = Depends(get_db)) -> AlertOut:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return AlertOut.model_validate(alert)
