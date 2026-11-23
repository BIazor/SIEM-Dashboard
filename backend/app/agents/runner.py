"""Background execution of queued investigation runs.

The HTTP request only enqueues work; the agents run outside the request cycle so a
slow investigation cannot hold a connection open, and two analysts cannot run the
same incident twice.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import SessionLocal
from ..models import Incident, InvestigationRun
from .orchestrator import run_investigation

logger = logging.getLogger("soc.investigation")

STALE_AFTER = timedelta(minutes=15)


def reap_stale_runs(db: Session, now: datetime | None = None) -> int:
    """Fail runs that were abandoned (worker crash, restart) so the queued slot frees up."""
    now = now or datetime.now(UTC)
    cutoff = now - STALE_AFTER
    stale = list(
        db.execute(
            select(InvestigationRun)
            .where(InvestigationRun.status.in_(("queued", "running")))
            .where(InvestigationRun.requested_at < cutoff)
        ).scalars()
    )
    for run in stale:
        run.status = "failed"
        run.error = "Run abandoned before completion"
        run.finished_at = now
    if stale:
        db.commit()
    return len(stale)


def execute_run(run_id: int) -> None:
    """Run one queued investigation to completion, recording success or failure."""
    with SessionLocal() as db:
        run = db.get(InvestigationRun, run_id)
        if run is None or run.status != "queued":
            return
        run.status = "running"
        run.started_at = datetime.now(UTC)
        db.commit()

        try:
            incident = db.get(Incident, run.incident_id)
            if incident is None:
                raise RuntimeError(f"Incident {run.incident_id} no longer exists")
            primary, reviewer = run_investigation(
                db,
                incident,
                actor_label=run.requested_by or "investigation-worker",
                actor_role="analyst",
                run_id=run.id,
            )
            run = db.get(InvestigationRun, run_id)
            if run is None:  # pragma: no cover - the row is deleted mid-run
                return
            run.investigator_id = primary.id
            run.critic_id = reviewer.id
            run.status = "succeeded"
            run.finished_at = datetime.now(UTC)
            db.commit()
        except Exception as exc:  # noqa: BLE001 - surfaced through the run record
            logger.exception("Investigation run %s failed", run_id)
            db.rollback()
            failed = db.get(InvestigationRun, run_id)
            if failed is None:  # pragma: no cover
                return
            failed.status = "failed"
            failed.error = f"{type(exc).__name__}: {exc}"[:500]
            failed.finished_at = datetime.now(UTC)
            audit.record(
                db,
                action="investigation.failed",
                actor=failed.requested_by or "system",
                actor_role="analyst",
                target=f"incident:{failed.incident_id}",
                detail={"run_id": run_id, "error": failed.error},
            )
            db.commit()
