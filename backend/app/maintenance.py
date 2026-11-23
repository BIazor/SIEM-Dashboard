"""Data lifecycle maintenance.

Run from cron or the CLI:

    python -m app.maintenance --days 90

Deletes alerts older than the retention window, keeps incident counts honest and
clears expired token revocations.  Nothing else is removed.
"""

from __future__ import annotations

import argparse
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from .config import get_settings
from .db import SessionLocal, init_db
from .models import Alert, Incident, RevokedToken

logger = logging.getLogger("soc.maintenance")


def prune_alerts(db: Session, days: int, now: datetime | None = None) -> dict[str, int]:
    """Delete alerts past the retention window and refresh affected incident counts."""
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=max(1, days))
    incident_ids = {
        incident_id
        for incident_id in db.execute(
            select(Alert.incident_id).where(Alert.event_time < cutoff).where(Alert.incident_id.is_not(None)).distinct()
        ).scalars()
        if incident_id is not None
    }
    deleted = db.execute(delete(Alert).where(Alert.event_time < cutoff)).rowcount or 0
    for incident_id in incident_ids:
        remaining = db.scalar(select(func.count(Alert.id)).where(Alert.incident_id == incident_id)) or 0
        db.execute(update(Incident).where(Incident.id == incident_id).values(alert_count=int(remaining)))
    db.commit()
    return {"deleted_alerts": int(deleted), "incidents_updated": len(incident_ids)}


def prune_revoked_tokens(db: Session, now: datetime | None = None) -> int:
    """Drop revocations for tokens that have expired anyway."""
    now = now or datetime.now(UTC)
    deleted = db.execute(delete(RevokedToken).where(RevokedToken.expires_at < now)).rowcount or 0
    db.commit()
    return int(deleted)


def run(days: int | None = None) -> dict[str, int]:
    settings = get_settings()
    window = days if days is not None else settings.retention_days
    with SessionLocal() as db:
        result = prune_alerts(db, window)
        result["deleted_revocations"] = prune_revoked_tokens(db)
    logger.info("Retention run complete: %s", result)
    return result


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Aegis SOC data retention")
    parser.add_argument("--days", type=int, default=None, help="Retention window in days")
    parser.add_argument("--dry-run", action="store_true", help="Report what would be removed")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    init_db()
    settings = get_settings()
    window = args.days if args.days is not None else settings.retention_days
    if args.dry_run:
        cutoff = datetime.now(UTC) - timedelta(days=max(1, window))
        with SessionLocal() as db:
            count = db.scalar(select(func.count(Alert.id)).where(Alert.event_time < cutoff)) or 0
        print(f"Would delete {count} alerts older than {window} days")
        return
    print(run(window))


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    main()
