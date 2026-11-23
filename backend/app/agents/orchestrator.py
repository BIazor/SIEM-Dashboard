"""Investigation orchestration: investigator -> critic -> incident update -> action proposals."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..models import Incident, Investigation, ProposedAction
from . import critic, investigator
from .evidence import collect
from .investigator import ENGINE_VERSION

AGENT_ACTOR = "investigator-agent"


def _record_fields(payload: dict, extra: tuple[str, ...] = ()) -> dict:
    keys = (
        "agent",
        "provider",
        "model",
        "engine_version",
        "status",
        "summary",
        "findings",
        "evidence",
        "hypotheses",
        "unsupported_claims",
        "missing_information",
        "recommendations",
        "priority",
        "confidence",
        "inputs",
        "error",
    ) + extra
    return {key: payload[key] for key in keys if key in payload}


def run_investigation(
    db: Session,
    incident: Incident,
    *,
    actor_label: str = AGENT_ACTOR,
    actor_role: str = "agent",
    source_ip: str | None = None,
    run_id: int | None = None,
) -> tuple[Investigation, Investigation]:
    """Run both agents for one incident and persist their reports."""
    evidence = collect(db, incident)

    primary = investigator.investigate(incident, evidence)
    investigator_record = Investigation(incident_id=incident.id, **_record_fields(primary))
    db.add(investigator_record)
    db.flush()

    reviewed = critic.review(incident, evidence, primary)
    reviewed["engine_version"] = ENGINE_VERSION
    reviewed["inputs"] = primary.get("inputs")
    critic_record = Investigation(incident_id=incident.id, **_record_fields(reviewed, ("verdict",)))
    db.add(critic_record)
    db.flush()

    incident.summary = primary["summary"]
    incident.confidence = critic_record.confidence
    incident.priority = max(1, min(5, primary["priority"] or incident.priority))
    incident.techniques = (primary.get("techniques") or incident.techniques or [])[:8]
    incident.status = "investigating"
    incident.updated_at = datetime.now(UTC)

    _propose_actions(db, incident, primary.get("recommendations") or [], investigator_record)
    db.flush()  # the session disables autoflush, so make proposals visible to the query below
    pending = db.execute(
        select(ProposedAction).where(ProposedAction.incident_id == incident.id).where(ProposedAction.status == "pending")
    ).first()
    if pending is not None:
        incident.status = "awaiting_approval"

    audit.record(
        db,
        action="investigation.completed",
        actor=actor_label,
        actor_role=actor_role,
        target=f"incident:{incident.id}",
        source_ip=source_ip,
        detail={
            "run_id": run_id,
            "provider": primary["provider"],
            "model": primary["model"],
            "evidence_digest": (primary.get("inputs") or {}).get("digest"),
            "verdict": critic_record.verdict,
            "confidence": critic_record.confidence,
            "unsupported_claims": len(critic_record.unsupported_claims or []),
        },
    )
    db.commit()
    db.refresh(investigator_record)
    db.refresh(critic_record)
    return investigator_record, critic_record


def _propose_actions(
    db: Session,
    incident: Incident,
    recommendations: list[dict],
    record: Investigation,
) -> None:
    settings = get_settings()
    expires_at = datetime.now(UTC) + timedelta(hours=max(1, settings.approval_ttl_hours))
    existing = {
        (action.action_type, action.target)
        for action in db.execute(
            select(ProposedAction)
            .where(ProposedAction.incident_id == incident.id)
            .where(ProposedAction.status.in_(("pending", "approved")))
        ).scalars()
    }
    for rec in recommendations[:5]:
        action_type = str(rec.get("action_type", "")).strip()
        target = str(rec.get("target", "")).strip()[:160]
        if action_type not in {"block_ip", "isolate_host", "disable_account", "collect_forensics"} or not target:
            continue
        if (action_type, target) in existing:
            continue
        existing.add((action_type, target))
        db.add(
            ProposedAction(
                incident_id=incident.id,
                action_type=action_type,
                target=target,
                rationale=str(rec.get("rationale", ""))[:500],
                risk_level=str(rec.get("risk_level", "medium")),
                status="pending",
                proposed_by=record.agent,
                expires_at=expires_at,
            )
        )
