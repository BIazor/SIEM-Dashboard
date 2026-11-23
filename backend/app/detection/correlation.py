"""Alert correlation: group related alerts into incidents per entity + behavior."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, Incident
from .rules import SEVERITY_RANK, alert_priority, category_title, higher_severity

CORRELATION_WINDOW = timedelta(minutes=90)
ACTIVE_STATUSES = ("open", "investigating", "awaiting_approval")
MAX_RELATED = 10


def normalize_entity(value: str | None) -> str:
    """Collapse the ways telemetry spells the same host or account.

    ``WS01``, ``ws01`` and ``ws01.corp.example`` are the same machine, and a
    fragmented entity splits one investigation into several incidents.  IP
    addresses are compared in their canonical form.
    """
    text = (value or "").strip().lower()
    if not text:
        return "unknown"
    if "\\" in text:  # DOMAIN\user
        text = text.split("\\", 1)[1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if text.count(".") >= 2 or (text.count(".") == 1 and not text.replace(".", "").isdigit()):
        candidate = text.split(".", 1)[0]
        if candidate:
            text = candidate
    return text[:120] or "unknown"


def _entity(alert: Alert) -> str:
    return normalize_entity(alert.host or alert.src_ip or alert.username)


def _merge_ids(existing: list[int] | None, new_ids: list[int]) -> list[int]:
    merged = list(dict.fromkeys([*(existing or []), *new_ids]))
    return merged[:MAX_RELATED]


def link_related(db: Session, incident: Incident, window_start: datetime) -> list[int]:
    """Record other active incidents for the same entity, in both directions.

    A PowerShell execution followed by a network callback on one host is one
    story; without this link they are three unrelated tickets.
    """
    stmt = (
        select(Incident)
        .where(Incident.entity == incident.entity)
        .where(Incident.id != incident.id)
        .where(Incident.status.in_(ACTIVE_STATUSES))
        .where(Incident.last_seen >= window_start)
    )
    neighbours = list(db.execute(stmt).scalars())
    if not neighbours:
        return list(incident.related_incident_ids or [])
    incident.related_incident_ids = _merge_ids(
        incident.related_incident_ids, [other.id for other in neighbours]
    )
    for other in neighbours:
        other.related_incident_ids = _merge_ids(other.related_incident_ids, [incident.id])
    return list(incident.related_incident_ids or [])


def correlate(db: Session, alert: Alert) -> tuple[Incident, bool]:
    """Attach the alert to an open incident for the same entity, or open a new one.

    Returns (incident, created).  Flushes but does not commit.
    """
    entity = _entity(alert)
    now = datetime.now(UTC)
    event_time = alert.event_time or now
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=UTC)

    window_start = min(event_time, now) - CORRELATION_WINDOW
    stmt = (
        select(Incident)
        .where(Incident.entity == entity)
        .where(Incident.category == alert.category)
        .where(Incident.status.in_(ACTIVE_STATUSES))
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
            related_incident_ids=[],
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

    link_related(db, incident, window_start)
    return incident, created


def severity_gap(incident: Incident) -> int:
    """How far above 'info' the incident sits; used for queue ordering."""
    return SEVERITY_RANK.get(incident.severity, 0)
