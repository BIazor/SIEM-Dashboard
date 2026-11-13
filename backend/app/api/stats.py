"""Dashboard statistics."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Alert, Incident, ProposedAction
from ..schemas import NamedCount, SeverityBucket, StatsOverview, TimelinePoint
from ..security import CurrentUser

router = APIRouter(prefix="/api/stats", tags=["stats"])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@router.get("/overview", response_model=StatsOverview)
def overview(user: CurrentUser, db: Session = Depends(get_db)) -> StatsOverview:
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    total_alerts = db.scalar(select(func.count(Alert.id))) or 0
    open_incidents = db.scalar(
        select(func.count(Incident.id)).where(Incident.status.in_(("open", "investigating", "awaiting_approval")))
    ) or 0
    critical_incidents = db.scalar(
        select(func.count(Incident.id)).where(Incident.severity == "critical").where(Incident.status != "closed")
    ) or 0
    pending_approvals = db.scalar(
        select(func.count(ProposedAction.id)).where(ProposedAction.status == "pending")
    ) or 0
    alerts_last_24h = db.scalar(select(func.count(Alert.id)).where(Alert.event_time >= last_24h)) or 0

    severity_rows = db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    ).all()
    severity_map = {severity: count for severity, count in severity_rows}
    by_severity = [
        SeverityBucket(severity=s, count=int(severity_map.get(s, 0))) for s in SEVERITY_ORDER
    ]

    buckets = db.execute(
        select(func.strftime("%Y-%m-%dT%H:00", Alert.event_time), func.count(Alert.id))
        .where(Alert.event_time >= last_24h)
        .group_by(func.strftime("%Y-%m-%dT%H:00", Alert.event_time))
    ).all()
    counts = {bucket: count for bucket, count in buckets}
    timeline: list[TimelinePoint] = []
    start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    for hour in range(24):
        bucket_dt = start + timedelta(hours=hour)
        key = bucket_dt.strftime("%Y-%m-%dT%H:00")
        timeline.append(TimelinePoint(bucket=bucket_dt.isoformat().replace("+00:00", "Z"), count=int(counts.get(key, 0))))

    host_rows = db.execute(
        select(Alert.host, func.count(Alert.id))
        .where(Alert.host.is_not(None))
        .group_by(Alert.host)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    ).all()
    category_rows = db.execute(
        select(Alert.category, func.count(Alert.id))
        .group_by(Alert.category)
        .order_by(func.count(Alert.id).desc())
        .limit(6)
    ).all()

    return StatsOverview(
        total_alerts=int(total_alerts),
        open_incidents=int(open_incidents),
        critical_incidents=int(critical_incidents),
        pending_approvals=int(pending_approvals),
        alerts_last_24h=int(alerts_last_24h),
        by_severity=by_severity,
        timeline=timeline,
        top_hosts=[NamedCount(name=host, count=int(count)) for host, count in host_rows],
        top_categories=[NamedCount(name=category, count=int(count)) for category, count in category_rows],
    )
