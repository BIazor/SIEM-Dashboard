"""Read-only tool registry for agents.

The agent never receives a database handle or network/shell access. It can only call the
tools below, each of which declares a strict pydantic argument model (``extra="forbid"``),
enforces a maximum result size, and refuses requests outside the incident's scope.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..models import Alert, Incident

MAX_RESULTS = 50
DEFAULT_WINDOW_MINUTES = 1440


class ToolError(Exception):
    pass


class ToolPermissionError(ToolError):
    """Tool is not in the allow-list, or the request escapes the incident scope."""


class ToolValidationError(ToolError):
    """Arguments failed strict validation."""


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IncidentIdArgs(_Args):
    incident_id: int = Field(ge=1, le=2_147_483_647)


class ListAlertsArgs(IncidentIdArgs):
    limit: int = Field(default=25, ge=1, le=MAX_RESULTS)


class SearchAlertsArgs(_Args):
    category: str | None = Field(default=None, max_length=32)
    severity: str | None = Field(default=None, max_length=16)
    since_minutes: int = Field(default=240, ge=1, le=DEFAULT_WINDOW_MINUTES)
    limit: int = Field(default=20, ge=1, le=MAX_RESULTS)


class EntityArgs(_Args):
    value: str = Field(min_length=1, max_length=120)
    limit: int = Field(default=20, ge=1, le=MAX_RESULTS)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    args_model: type[BaseModel]
    handler: Callable[[Session, BaseModel, Incident], dict]


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def alert_brief(alert: Alert, include_description: bool = True) -> dict:
    brief = {
        "alert_id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "category": alert.category,
        "technique": alert.technique,
        "rule_id": alert.rule_id,
        "event_time": _iso(alert.event_time),
        "host": alert.host,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "username": alert.username,
    }
    if include_description:
        brief["description"] = alert.description[:1500]
    return brief


def _scope_alerts(db: Session, incident: Incident, limit: int) -> list[Alert]:
    stmt = (
        select(Alert)
        .where(Alert.incident_id == incident.id)
        .order_by(Alert.event_time.asc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars())


def _assert_same_incident(args: IncidentIdArgs, incident: Incident) -> None:
    if args.incident_id != incident.id:
        raise ToolPermissionError("Tool call outside the assigned incident scope")


def _get_incident_summary(db: Session, args: BaseModel, incident: Incident) -> dict:
    assert isinstance(args, IncidentIdArgs)
    _assert_same_incident(args, incident)
    return {
        "incident_id": incident.id,
        "title": incident.title,
        "entity": incident.entity,
        "category": incident.category,
        "severity": incident.severity,
        "status": incident.status,
        "priority": incident.priority,
        "alert_count": len(_scope_alerts(db, incident, MAX_RESULTS)),
        "first_seen": _iso(incident.first_seen),
        "last_seen": _iso(incident.last_seen),
        "techniques": list(incident.techniques or []),
        "host": incident.host,
    }


def _list_incident_alerts(db: Session, args: BaseModel, incident: Incident) -> dict:
    assert isinstance(args, ListAlertsArgs)
    _assert_same_incident(args, incident)
    alerts = _scope_alerts(db, incident, min(args.limit, MAX_RESULTS))
    return {"incident_id": incident.id, "alerts": [alert_brief(a) for a in alerts]}


def _search_alerts(db: Session, args: BaseModel, incident: Incident) -> dict:
    assert isinstance(args, SearchAlertsArgs)
    since = datetime.now(UTC) - timedelta(minutes=args.since_minutes)
    conditions = [Alert.event_time >= since]
    if args.category:
        conditions.append(Alert.category == args.category)
    if args.severity:
        conditions.append(Alert.severity == args.severity)
    # Least privilege: only alerts that share the incident's host or source IP.
    entity_conditions = []
    if incident.host:
        entity_conditions.append(Alert.host == incident.host)
    if incident.entity:
        entity_conditions.append(Alert.src_ip == incident.entity)
        entity_conditions.append(Alert.host == incident.entity)
    if entity_conditions:
        conditions.append(or_(*entity_conditions))
    else:
        return {"alerts": [], "note": "Incident has no entity to scope the search to"}

    stmt = select(Alert).where(*conditions).order_by(Alert.event_time.desc()).limit(min(args.limit, MAX_RESULTS))
    alerts = list(db.execute(stmt).scalars())
    return {"alerts": [alert_brief(a, include_description=False) for a in alerts], "since_minutes": args.since_minutes}


def _entity_matches(entity: str, incident: Incident, db: Session) -> bool:
    """Allow an entity lookup only when it appears in the incident's own alerts."""
    if incident.entity and entity == incident.entity:
        return True
    for alert in _scope_alerts(db, incident, MAX_RESULTS):
        if entity in {alert.host, alert.src_ip, alert.dst_ip, alert.username}:
            return True
    return False


def _host_activity(db: Session, args: BaseModel, incident: Incident) -> dict:
    assert isinstance(args, EntityArgs)
    if not _entity_matches(args.value, incident, db):
        raise ToolPermissionError("Host is not part of this incident")
    stmt = (
        select(Alert)
        .where(Alert.host == args.value)
        .order_by(Alert.event_time.desc())
        .limit(min(args.limit, MAX_RESULTS))
    )
    alerts = list(db.execute(stmt).scalars())
    return {
        "host": args.value,
        "alert_count": len(alerts),
        "categories": sorted({a.category for a in alerts}),
        "source_ips": sorted({a.src_ip for a in alerts if a.src_ip}),
        "users": sorted({a.username for a in alerts if a.username}),
        "first_seen": _iso(min((a.event_time for a in alerts), default=None)),
        "last_seen": _iso(max((a.event_time for a in alerts), default=None)),
        "alerts": [alert_brief(a, include_description=False) for a in alerts[:10]],
    }


def _ip_activity(db: Session, args: BaseModel, incident: Incident) -> dict:
    assert isinstance(args, EntityArgs)
    if not _entity_matches(args.value, incident, db):
        raise ToolPermissionError("IP address is not part of this incident")
    stmt = (
        select(Alert)
        .where(or_(Alert.src_ip == args.value, Alert.dst_ip == args.value))
        .order_by(Alert.event_time.desc())
        .limit(min(args.limit, MAX_RESULTS))
    )
    alerts = list(db.execute(stmt).scalars())
    return {
        "ip": args.value,
        "alert_count": len(alerts),
        "hosts": sorted({a.host for a in alerts if a.host}),
        "users": sorted({a.username for a in alerts if a.username}),
        "categories": sorted({a.category for a in alerts}),
        "alerts": [alert_brief(a, include_description=False) for a in alerts[:10]],
    }


def _user_activity(db: Session, args: BaseModel, incident: Incident) -> dict:
    assert isinstance(args, EntityArgs)
    if not _entity_matches(args.value, incident, db):
        raise ToolPermissionError("User is not part of this incident")
    stmt = (
        select(Alert)
        .where(Alert.username == args.value)
        .order_by(Alert.event_time.desc())
        .limit(min(args.limit, MAX_RESULTS))
    )
    alerts = list(db.execute(stmt).scalars())
    return {
        "username": args.value,
        "alert_count": len(alerts),
        "hosts": sorted({a.host for a in alerts if a.host}),
        "categories": sorted({a.category for a in alerts}),
        "alerts": [alert_brief(a, include_description=False) for a in alerts[:10]],
    }


TOOLS: dict[str, ToolSpec] = {
    spec.name: spec
    for spec in (
        ToolSpec(
            name="get_incident_summary",
            description="Read the incident header: entity, severity, status, technique list.",
            args_model=IncidentIdArgs,
            handler=_get_incident_summary,
        ),
        ToolSpec(
            name="list_incident_alerts",
            description="List the alerts correlated into this incident (read-only, max 50).",
            args_model=ListAlertsArgs,
            handler=_list_incident_alerts,
        ),
        ToolSpec(
            name="search_alerts",
            description="Search recent alerts for the incident entity only (max 50).",
            args_model=SearchAlertsArgs,
            handler=_search_alerts,
        ),
        ToolSpec(
            name="get_host_activity",
            description="Summarize alert activity for a host that appears in this incident.",
            args_model=EntityArgs,
            handler=_host_activity,
        ),
        ToolSpec(
            name="get_ip_activity",
            description="Summarize alert activity for a source/destination IP in this incident.",
            args_model=EntityArgs,
            handler=_ip_activity,
        ),
        ToolSpec(
            name="get_user_activity",
            description="Summarize alert activity for a username in this incident.",
            args_model=EntityArgs,
            handler=_user_activity,
        ),
    )
}

READ_ONLY_TOOLS = frozenset(TOOLS)


def catalog() -> list[dict]:
    """Machine-readable tool definitions (for docs and the admin API)."""
    return [
        {
            "name": spec.name,
            "description": spec.description,
            "read_only": True,
            "arguments_schema": spec.args_model.model_json_schema(),
        }
        for spec in TOOLS.values()
    ]


def execute(db: Session, name: str, raw_args: dict, incident: Incident) -> dict:
    """Validate and run one tool call. Raises ToolError subclasses on misuse."""
    spec = TOOLS.get(name)
    if spec is None:
        raise ToolPermissionError(f"Tool '{name[:40]}' is not permitted")
    try:
        args = spec.args_model.model_validate(raw_args)
    except ValidationError as exc:
        first = exc.errors()[0]
        raise ToolValidationError(
            f"Invalid arguments for {name}: {'.'.join(str(p) for p in first.get('loc', ())) or 'root'} "
            f"{first.get('msg', '')}".strip()
        ) from exc
    return spec.handler(db, args, incident)
