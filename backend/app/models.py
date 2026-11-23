"""ORM models for users, alerts, incidents, investigations, actions and audit logs."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Store datetimes as naive UTC, return them timezone-aware.

    SQLite has no native timezone support, so normalizing on the way in/out keeps
    comparisons correct and gives the API explicit UTC timestamps.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):  # noqa: ARG002
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect):  # noqa: ARG002
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


ROLES = ("admin", "approver", "analyst", "viewer")
SEVERITIES = ("critical", "high", "medium", "low", "info")
CATEGORIES = ("brute_force", "powershell", "network", "privilege_change", "file_integrity", "other")
INCIDENT_STATUSES = ("open", "investigating", "awaiting_approval", "contained", "closed")
RUN_STATUSES = ("queued", "running", "succeeded", "failed")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="analyst", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Tokens issued before this instant are rejected (set on password change).
    password_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # Bumped on password change; tokens carry the epoch they were minted under.
    token_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_uid: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(40), default="wazuh")
    rule_id: Mapped[str] = mapped_column(String(40), default="")
    rule_level: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="low", index=True)
    category: Mapped[str] = mapped_column(String(32), default="other", index=True)
    # Which internal detection rule matched (empty for unmatched alerts).
    detection_rule: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Suppression entries keep the alert but force it to informational.
    suppressed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    host: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(120), nullable=True)
    technique: Mapped[str | None] = mapped_column(String(40), nullable=True)
    event_time: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    # True when the payload had no usable timestamp and ingest time was substituted.
    event_time_inferred: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    incident: Mapped[Incident | None] = relationship(back_populates="alerts")

    __table_args__ = (Index("ix_alerts_time_severity", "event_time", "severity"),)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    entity: Mapped[str] = mapped_column(String(120), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="low", index=True)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=4)
    host: Mapped[str | None] = mapped_column(String(120), nullable=True)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Other active incidents for the same entity inside the correlation window.
    related_incident_ids: Mapped[list[int] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    alerts: Mapped[list[Alert]] = relationship(back_populates="incident", order_by=Alert.event_time)
    investigations: Mapped[list[Investigation]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="Investigation.id"
    )
    actions: Mapped[list[ProposedAction]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="ProposedAction.id"
    )
    runs: Mapped[list[InvestigationRun]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="InvestigationRun.id"
    )


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    agent: Mapped[str] = mapped_column(String(32), index=True)  # investigator | critic
    provider: Mapped[str] = mapped_column(String(32), default="heuristic")
    model: Mapped[str] = mapped_column(String(80), default="")
    engine_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="completed")
    summary: Mapped[str] = mapped_column(Text, default="")
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    hypotheses: Mapped[list[str]] = mapped_column(JSON, default=list)
    unsupported_claims: Mapped[list[str]] = mapped_column(JSON, default=list)
    missing_information: Mapped[list[str]] = mapped_column(JSON, default=list)
    recommendations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    # Snapshot of what the agent was given, so a run can be replayed or diffed.
    inputs: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    priority: Mapped[int | None] = mapped_column(Integer, nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)

    incident: Mapped[Incident] = relationship(back_populates="investigations")


class InvestigationRun(Base):
    """One queued execution of the investigator/critic pair for an incident."""

    __tablename__ = "investigation_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    requested_by: Mapped[str] = mapped_column(String(160), default="")
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    investigator_id: Mapped[int | None] = mapped_column(ForeignKey("investigations.id"), nullable=True)
    critic_id: Mapped[int | None] = mapped_column(ForeignKey("investigations.id"), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident: Mapped[Incident] = relationship(back_populates="runs")

    __table_args__ = (
        # At most one active run per incident, enforced by the database.
        Index(
            "uq_investigation_runs_active",
            "incident_id",
            unique=True,
            sqlite_where=text("status IN ('queued', 'running')"),
        ),
    )


class ProposedAction(Base):
    __tablename__ = "proposed_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), index=True)
    action_type: Mapped[str] = mapped_column(String(40))
    target: Mapped[str] = mapped_column(String(160))
    rationale: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    proposed_by: Mapped[str] = mapped_column(String(40), default="investigator-agent")
    # Set only for human proposals; used to block self-approval.
    proposed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    requested_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Approvals are recorded as dry-run executions: nothing acts on the network.
    execution_status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    execution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    incident: Mapped[Incident] = relationship(back_populates="actions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(160), default="system")
    actor_role: Mapped[str] = mapped_column(String(20), default="system")
    action: Mapped[str] = mapped_column(String(80), index=True)
    target: Mapped[str] = mapped_column(String(200), default="")
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # Hash chain: each row commits to its predecessor so tampering is detectable.
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    reason: Mapped[str] = mapped_column(String(40), default="logout")


class RateLimitBucket(Base):
    """Fixed-window counters shared by every worker process."""

    __tablename__ = "rate_limit_buckets"

    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    window_start: Mapped[int] = mapped_column(Integer, default=0)
    count: Mapped[int] = mapped_column(Integer, default=0)
