"""Concurrency, schema upgrade, job and retention behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

import app.api.incidents as incidents_module
import app.api.ingest as ingest_module
from app.agents.runner import STALE_AFTER, reap_stale_runs
from app.maintenance import prune_alerts
from app.migrations import upgrade_schema
from app.models import Alert, Incident, InvestigationRun
from app.sim.scenarios import failed_logins


def test_sqlite_busy_timeout_is_configured(db):
    assert int(db.execute(text("PRAGMA busy_timeout")).scalar()) == 5000


def test_rejected_row_does_not_discard_the_batch(client, users, ingest, monkeypatch):
    real_correlate = ingest_module.correlate
    state = {"calls": 0}

    def flaky_correlate(db, alert):
        state["calls"] += 1
        if state["calls"] == 2:
            # Simulates the unique index rejecting a concurrent insert.
            raise IntegrityError("INSERT", {}, Exception("duplicate alert_uid"))
        return real_correlate(db, alert)

    monkeypatch.setattr(ingest_module, "correlate", flaky_correlate)
    body = ingest(failed_logins())

    assert body["accepted"] == len(failed_logins()) - 1
    assert body["duplicates"] == 1


def test_schema_upgrade_adds_columns_to_an_existing_database(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}", future=True)
    with engine.begin() as connection:
        connection.execute(
            text(
                """CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY,
                    alert_uid VARCHAR(128) NOT NULL,
                    source VARCHAR(40),
                    rule_id VARCHAR(40),
                    rule_level INTEGER,
                    severity VARCHAR(16),
                    category VARCHAR(32),
                    title VARCHAR(300) NOT NULL,
                    description TEXT,
                    src_ip VARCHAR(64),
                    dst_ip VARCHAR(64),
                    host VARCHAR(120),
                    username VARCHAR(120),
                    technique VARCHAR(40),
                    event_time DATETIME,
                    ingested_at DATETIME,
                    status VARCHAR(20),
                    incident_id INTEGER,
                    raw JSON
                )"""
            )
        )

    upgrade_schema(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("alerts")}
    assert {"detection_rule", "suppressed", "event_time_inferred"} <= columns


def test_second_active_run_is_rejected(client, auth, ingest, monkeypatch):
    monkeypatch.setattr(incidents_module, "execute_run", lambda run_id: None)
    incident_id = ingest(failed_logins())["incidents"][0]

    first = client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["analyst"])
    second = client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["analyst"])

    assert first.status_code == 202, first.text
    assert second.status_code == 409, second.text
    assert "already" in second.json()["detail"].lower()


def test_run_record_links_both_reports(client, auth, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    queued = client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["analyst"])
    assert queued.status_code == 202

    detail = client.get(f"/api/incidents/{incident_id}", headers=auth["analyst"]).json()
    assert detail["runs"], "the run should be visible on the incident"
    run = detail["runs"][-1]
    assert run["status"] == "succeeded"
    assert run["investigator_id"] and run["critic_id"]
    assert run["started_at"] and run["finished_at"]
    assert len(detail["investigations"]) == 2


def test_abandoned_run_is_reaped(db):
    incident = Incident(
        title="stale run", entity="host-stale", category="other", severity="low", status="open", priority=4, host="host-stale"
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    run = InvestigationRun(
        incident_id=incident.id,
        status="running",
        requested_by="analyst@test.local",
        requested_at=datetime.now(UTC) - STALE_AFTER - timedelta(minutes=1),
    )
    db.add(run)
    db.commit()

    assert reap_stale_runs(db) == 1
    db.refresh(run)
    assert run.status == "failed"
    assert run.error


def test_retention_prunes_old_alerts_and_refreshes_counts(db):
    now = datetime.now(UTC)
    incident = Incident(
        title="retention", entity="host-ret", category="other", severity="low", status="open", priority=4, host="host-ret"
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    old = Alert(alert_uid="retention-old", title="Old alert", event_time=now - timedelta(days=60), incident_id=incident.id)
    fresh = Alert(alert_uid="retention-new", title="Fresh alert", event_time=now, incident_id=incident.id)
    db.add_all([old, fresh])
    db.commit()
    old_id, fresh_id = old.id, fresh.id

    result = prune_alerts(db, 30)
    db.expire_all()

    assert result["deleted_alerts"] == 1
    assert db.get(Alert, old_id) is None
    assert db.get(Alert, fresh_id) is not None
    assert db.get(Incident, incident.id).alert_count == 1
