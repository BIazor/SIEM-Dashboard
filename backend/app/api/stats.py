"""Dashboard statistics and detection coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..db import engine, get_db
from ..detection.rules import rule_catalog, rules_version
from ..models import Alert, Incident, ProposedAction
from ..schemas import (
    DetectionStats,
    NamedCount,
    RuleStat,
    SeverityBucket,
    StatsOverview,
    TimelinePoint,
)
from ..security import CurrentUser

router = APIRouter(prefix="/api/stats", tags=["stats"])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
IS_SQLITE = engine.dialect.name == "sqlite"


def _hourly_counts(db: Session, since: datetime) -> dict[str, int]:
    """Hourly alert counts, computed in SQL on SQLite and in Python elsewhere."""
    if IS_SQLITE:
        rows = db.execute(
            select(func.strftime("%Y-%m-%dT%H:00", Alert.event_time), func.count(Alert.id))
            .where(Alert.event_time >= since)
            .group_by(func.strftime("%Y-%m-%dT%H:00", Alert.event_time))
        ).all()
        return {bucket: int(count) for bucket, count in rows}

    counts: dict[str, int] = {}
    for event_time in db.execute(select(Alert.event_time).where(Alert.event_time >= since)).scalars():
        key = event_time.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00")
        counts[key] = counts.get(key, 0) + 1
    return counts


@router.get("/overview", response_model=StatsOverview)
def overview(user: CurrentUser, db: Session = Depends(get_db)) -> StatsOverview:
    now = datetime.now(UTC)
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
        SeverityBucket(severity=severity, count=int(severity_map.get(severity, 0)))
        for severity in SEVERITY_ORDER
    ]

    counts = _hourly_counts(db, last_24h)
    timeline: list[TimelinePoint] = []
    start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
    for hour in range(24):
        bucket_dt = start + timedelta(hours=hour)
        key = bucket_dt.strftime("%Y-%m-%dT%H:00")
        timeline.append(
            TimelinePoint(bucket=bucket_dt.isoformat().replace("+00:00", "Z"), count=int(counts.get(key, 0)))
        )

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


@router.get("/detections", response_model=DetectionStats)
def detections(user: CurrentUser, db: Session = Depends(get_db)) -> DetectionStats:
    """Rule hit counts, so detection tuning is led by data rather than impressions."""
    rows = db.execute(
        select(
            Alert.detection_rule,
            Alert.category,
            Alert.technique,
            func.count(Alert.id),
            func.sum(case((Alert.suppressed.is_(True), 1), else_=0)),
        ).group_by(Alert.detection_rule, Alert.category, Alert.technique)
    ).all()

    counts = {
        str(rule_key or "unmatched"): (int(total), int(suppressed or 0))
        for rule_key, _category, _technique, total, suppressed in rows
    }
    catalog = {entry["key"]: entry for entry in rule_catalog()}
    stats: list[RuleStat] = []
    for key, entry in catalog.items():
        total, suppressed = counts.get(key, (0, 0))
        stats.append(
            RuleStat(
                key=key,
                category=entry["category"],
                technique=entry["technique"],
                alerts=total,
                suppressed=suppressed,
            )
        )
    for key, (total, suppressed) in counts.items():
        if key in catalog:
            continue
        stats.append(RuleStat(key=key, category="other", technique=None, alerts=total, suppressed=suppressed))

    unmatched = counts.get("unmatched", (0, 0))[0]
    suppressed_total = sum(entry[1] for entry in counts.values())
    inferred = db.scalar(
        select(func.count(Alert.id)).where(Alert.event_time_inferred.is_(True))
    ) or 0

    return DetectionStats(
        rules_version=rules_version(),
        rules=stats,
        unmatched_alerts=unmatched,
        suppressed_alerts=int(suppressed_total),
        inferred_timestamps=int(inferred),
    )
