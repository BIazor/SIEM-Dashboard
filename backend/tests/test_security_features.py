"""Session cookies, token revocation, approval segregation and audit integrity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from app.db import SessionLocal
from app.models import AuditLog, ProposedAction
from app.sim.scenarios import failed_logins

ANALYST = {"email": "analyst@test.local", "password": "Analyst-Test-Pass-1"}


def _propose(client, auth, incident_id, action_type="block_ip", target="203.0.113.45"):
    response = client.post(
        f"/api/incidents/{incident_id}/actions",
        json={"action_type": action_type, "target": target, "rationale": "test", "risk_level": "medium"},
        headers=auth["analyst"],
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_login_sets_httponly_session_cookie(client, users):
    response = client.post("/api/auth/login", json=ANALYST)
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite" in cookie
    # No Authorization header: the cookie alone identifies the caller.
    assert client.get("/api/auth/me").status_code == 200


def test_logout_revokes_the_presented_token(client, tokens):
    headers = {"Authorization": f"Bearer {tokens['analyst']}"}
    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_cookie_mutations_require_a_same_origin_header(client, users, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    assert client.post("/api/auth/login", json=ANALYST).status_code == 200

    blocked = client.post(f"/api/incidents/{incident_id}/investigate")
    assert blocked.status_code == 403, blocked.text
    assert "origin" in blocked.json()["detail"].lower()

    allowed = client.post(
        f"/api/incidents/{incident_id}/investigate", headers={"Origin": "http://localhost:5173"}
    )
    assert allowed.status_code == 202, allowed.text


def test_password_change_invalidates_issued_tokens(client, tokens):
    headers = {"Authorization": f"Bearer {tokens['analyst']}"}
    changed = client.post(
        "/api/auth/password",
        json={"current_password": "Analyst-Test-Pass-1", "new_password": "Analyst-New-Pass-9"},
        headers=headers,
    )
    assert changed.status_code == 200, changed.text

    assert client.get("/api/auth/me", headers=headers).status_code == 401
    relogin = client.post(
        "/api/auth/login", json={"email": "analyst@test.local", "password": "Analyst-New-Pass-9"}
    )
    assert relogin.status_code == 200


def test_password_change_rejects_weak_and_reused_passwords(client, tokens):
    headers = {"Authorization": f"Bearer {tokens['analyst']}"}
    weak = client.post(
        "/api/auth/password",
        json={"current_password": "Analyst-Test-Pass-1", "new_password": "short"},
        headers=headers,
    )
    assert weak.status_code in (422,), weak.text
    reused = client.post(
        "/api/auth/password",
        json={"current_password": "Analyst-Test-Pass-1", "new_password": "Analyst-Test-Pass-1"},
        headers=headers,
    )
    assert reused.status_code == 422


def test_approver_cannot_decide_on_their_own_proposal(client, auth, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    analyst_proposal = _propose(client, auth, incident_id)
    approved_by_other = client.post(
        f"/api/approvals/{analyst_proposal['id']}/decision",
        json={"decision": "approve"},
        headers=auth["approver"],
    )
    assert approved_by_other.status_code == 200, approved_by_other.text

    admin_proposal = client.post(
        f"/api/incidents/{incident_id}/actions",
        json={"action_type": "isolate_host", "target": "host-1", "rationale": "admin", "risk_level": "high"},
        headers=auth["admin"],
    )
    assert admin_proposal.status_code == 201
    self_decision = client.post(
        f"/api/approvals/{admin_proposal.json()['id']}/decision",
        json={"decision": "approve"},
        headers=auth["admin"],
    )
    assert self_decision.status_code == 403, self_decision.text
    assert "segregation" in self_decision.json()["detail"].lower()


def test_expired_actions_cannot_be_decided(client, auth, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    proposal = _propose(client, auth, incident_id)
    with SessionLocal() as db:
        db.execute(
            update(ProposedAction)
            .where(ProposedAction.id == proposal["id"])
            .values(expires_at=datetime.now(UTC) - timedelta(hours=1))
        )
        db.commit()

    response = client.post(
        f"/api/approvals/{proposal['id']}/decision", json={"decision": "approve"}, headers=auth["approver"]
    )
    assert response.status_code == 409
    assert "expired" in response.json()["detail"].lower()


def test_status_transitions_are_validated(client, auth, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    closed = client.patch(
        f"/api/incidents/{incident_id}/status", json={"status": "closed"}, headers=auth["analyst"]
    )
    assert closed.status_code == 200

    invalid = client.patch(
        f"/api/incidents/{incident_id}/status", json={"status": "investigating"}, headers=auth["analyst"]
    )
    assert invalid.status_code == 409

    reopened = client.patch(
        f"/api/incidents/{incident_id}/status", json={"status": "open"}, headers=auth["analyst"]
    )
    assert reopened.status_code == 200


def test_audit_chain_detects_tampering(client, auth, ingest):
    ingest(failed_logins())
    assert client.get("/api/audit/verify", headers=auth["admin"]).json()["ok"] is True

    with SessionLocal() as db:
        row = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().first()
        db.execute(update(AuditLog).where(AuditLog.id == row.id).values(actor="attacker"))
        db.commit()
        tampered_id = row.id

    result = client.get("/api/audit/verify", headers=auth["admin"]).json()
    assert result["ok"] is False
    assert result["broken_entry_id"] == tampered_id


def test_readiness_reports_schema_version(client):
    body = client.get("/api/health/ready").json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert body["schema_version"] >= 1
