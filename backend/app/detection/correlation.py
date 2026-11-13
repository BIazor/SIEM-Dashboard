"""Alert correlation: group related alerts into incidents per entity + behaviour."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, Incident
from .rules import SEVERITY_RANK, alert_priority, category_title, higher_severity

CORRELATION_WINDOW = timedelta(minutes=90)


def _entity(alert: Alert) -> str:
    return alert.host or alert.src_ip or alert.username or "unknown"


def correlate(db: Session, alert: Alert) -> tuple[Incident, bool]:
    """Attach the alert to an open incident for the same entity, or open a new one.

    Returns (incident, created).  Flushes but does not commit.
    """
    entity = _entity(alert)
    now = datetime.now(timezone.utc)
    event_time = alert.event_time or now
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    window_start = min(event_time, now) - CORRELATION_WINDOW
    stmt = (
        select(Incident)
        .where(Incident.entity == entity)
        .where(Incident.category == alert.category)
        .where(Incident.status.in_(("open", "investigating", "awaiting_approval")))
        .where(Incident.last_seen >= window_start)
        .order_by(Incident.last_seen.desc())
    )
    incident = db.execute(stmt).scalars().first()

    created = False
    if incident is None:
        created = True
        incident = Incident(
            title=f"{category_title(alert.category)} on {entity}",
            entity=entity,
            category=alert.category,
            severity=alert.severity,
            status="open",
            priority=alert_priority(alert.severity),
            host=alert.host,
            alert_count=0,
            first_seen=event_time,
            last_seen=event_time,
            techniques=[alert.technique] if alert.technique else [],
        )
        db.add(incident)
        db.flush()

    incident.alert_count = (incident.alert_count or 0) + 1
    incident.severity = higher_severity(incident.severity, alert.severity)
    incident.priority = min(alert_priority(incident.severity), incident.priority or 5)
    incident.last_seen = max(incident.last_seen, event_time)
    incident.first_seen = min(incident.first_seen, event_time)
    if alert.host and not incident.host:
        incident.host = alert.host
    techniques = list(incident.techniques or [])
    if alert.technique and alert.technique not in techniques:
        techniques.append(alert.technique)
    incident.techniques = techniques

    alert.incident = incident
    if alert.status == "new":
        alert.status = "triaged"
    return incident, created


def severity_gap(incident: Incident) -> int:
    """How far above 'info' the incident sits; used for queue ordering."""
    return SEVERITY_RANK.get(incident.severity, 0)
