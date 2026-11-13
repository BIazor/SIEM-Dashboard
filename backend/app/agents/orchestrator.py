"""Investigation orchestration: investigator -> critic -> incident update -> action proposals."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..models import Incident, Investigation, ProposedAction
from . import critic, investigator
from .evidence import collect
from .llm import LLMClient, get_llm_client

AGENT_ACTOR = "investigator-agent"


def run_investigation(
    db: Session,
    incident: Incident,
    *,
    actor_label: str = AGENT_ACTOR,
    actor_role: str = "agent",
    llm: LLMClient | None = None,
    source_ip: str | None = None,
) -> tuple[Investigation, Investigation]:
    """Run both agents for one incident and persist their reports."""
    llm = llm or get_llm_client()
    evidence = collect(db, incident)

    primary = investigator.investigate(incident, evidence, llm)
    investigator_record = Investigation(incident_id=incident.id, **{
        key: primary[key]
        for key in (
            "agent", "provider", "model", "status", "summary", "findings", "evidence",
            "hypotheses", "unsupported_claims", "missing_information", "recommendations",
            "priority", "confidence", "error",
        )
    })
    db.add(investigator_record)
    db.flush()

    reviewed = critic.review(incident, evidence, primary, llm)
    critic_record = Investigation(incident_id=incident.id, **{
        key: reviewed[key]
        for key in (
            "agent", "provider", "model", "status", "summary", "findings", "evidence",
            "hypotheses", "unsupported_claims", "missing_information", "recommendations",
            "priority", "confidence", "verdict", "error",
        )
    })
    db.add(critic_record)
    db.flush()

    incident.summary = primary["summary"]
    incident.confidence = critic_record.confidence
    incident.priority = max(1, min(5, primary["priority"] or incident.priority))
    incident.techniques = (primary.get("techniques") or incident.techniques or [])[:8]
    incident.status = "investigating"
    incident.updated_at = datetime.now(timezone.utc)

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
            "provider": primary["provider"],
            "model": primary["model"],
            "verdict": critic_record.verdict,
            "confidence": critic_record.confidence,
            "llm_available": primary.get("llm_available", False),
            "parse_error": primary.get("error"),
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
            )
        )
