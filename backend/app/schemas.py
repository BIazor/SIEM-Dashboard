"""Pydantic schemas for API input and output validation."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Role = Literal["admin", "approver", "analyst", "viewer"]
Severity = Literal["critical", "high", "medium", "low", "info"]
ActionType = Literal["block_ip", "isolate_host", "disable_account", "collect_forensics"]


# --------------------------------------------------------------------------- auth
class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        value = value.strip().lower()
        if "@" not in value or value.startswith("@") or value.endswith("@"):
            raise ValueError("A valid email address is required")
        return value


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str
    full_name: str
    role: Role
    is_active: bool
    last_login_at: datetime | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    user: UserOut


# -------------------------------------------------------------------------- alerts
class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_uid: str
    source: str
    rule_id: str
    rule_level: int
    severity: Severity
    category: str
    title: str
    description: str
    src_ip: str | None
    dst_ip: str | None
    host: str | None
    username: str | None
    technique: str | None
    event_time: datetime
    ingested_at: datetime
    status: str
    incident_id: int | None


class AlertPage(BaseModel):
    items: list[AlertOut]
    total: int
    limit: int
    offset: int


# ----------------------------------------------------------------------- incidents
class InvestigationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    agent: str
    provider: str
    model: str
    status: str
    summary: str
    findings: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    hypotheses: list[str]
    unsupported_claims: list[str]
    missing_information: list[str]
    recommendations: list[dict[str, Any]]
    priority: int | None
    confidence: float | None
    verdict: str | None
    error: str | None
    created_at: datetime


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    action_type: str
    target: str
    rationale: str
    risk_level: str
    status: str
    proposed_by: str
    requested_at: datetime
    decided_by_id: int | None
    decided_at: datetime | None
    decision_note: str | None


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    entity: str
    category: str
    severity: Severity
    status: str
    priority: int
    host: str | None
    alert_count: int
    first_seen: datetime
    last_seen: datetime
    summary: str | None
    confidence: float | None
    techniques: list[str]
    created_at: datetime
    updated_at: datetime


class IncidentDetail(IncidentOut):
    alerts: list[AlertOut]
    investigations: list[InvestigationOut]
    actions: list[ActionOut]


class ApprovalOut(ActionOut):
    incident_title: str
    incident_severity: Severity


class IncidentStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["open", "investigating", "contained", "closed"]


class ActionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_type: ActionType
    target: str = Field(min_length=1, max_length=160)
    rationale: str = Field(default="", max_length=500)
    risk_level: Literal["low", "medium", "high"] = "medium"


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    note: str = Field(default="", max_length=500)


# -------------------------------------------------------------------------- ingest
class IngestResponse(BaseModel):
    accepted: int
    duplicates: int
    alerts: list[AlertOut]
    incidents: list[int]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    llm_provider: str
    llm_available: bool


# --------------------------------------------------------------------------- stats
class SeverityBucket(BaseModel):
    severity: str
    count: int


class TimelinePoint(BaseModel):
    bucket: str
    count: int


class NamedCount(BaseModel):
    name: str
    count: int


class StatsOverview(BaseModel):
    total_alerts: int
    open_incidents: int
    critical_incidents: int
    pending_approvals: int
    alerts_last_24h: int
    by_severity: list[SeverityBucket]
    timeline: list[TimelinePoint]
    top_hosts: list[NamedCount]
    top_categories: list[NamedCount]


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    actor: str
    actor_role: str
    action: str
    target: str
    source_ip: str | None
    detail: dict[str, Any]
