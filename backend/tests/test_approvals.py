"""Human-in-the-loop approval workflow tests."""

from __future__ import annotations

from app.sim.scenarios import failed_logins


def _investigated_incident(client, auth, ingest) -> dict:
    incident_id = ingest(failed_logins())["incidents"][0]
    client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["analyst"])
    return client.get(f"/api/incidents/{incident_id}", headers=auth["analyst"]).json()


def test_investigation_proposes_actions_and_awaits_approval(client, auth, ingest):
    incident = _investigated_incident(client, auth, ingest)
    assert incident["status"] == "awaiting_approval"
    assert incident["actions"], "agents must propose at least one action"
    assert all(action["status"] == "pending" for action in incident["actions"])
    assert len(incident["investigations"]) == 2
    agents = {report["agent"] for report in incident["investigations"]}
    assert agents == {"investigator", "critic"}


def test_pending_actions_are_queued_for_approvers(client, auth, ingest):
    incident = _investigated_incident(client, auth, ingest)
    queue = client.get("/api/approvals", headers=auth["approver"]).json()
    assert len(queue) == len(incident["actions"])
    assert all(item["status"] == "pending" for item in queue)
    assert all(item["incident_title"] for item in queue)


def test_containment_waits_for_the_whole_queue(client, auth, ingest):
    incident = _investigated_incident(client, auth, ingest)
    action_ids = [action["id"] for action in incident["actions"]]
    assert len(action_ids) > 1, "the scenario should propose more than one action"

    first = client.post(
        f"/api/approvals/{action_ids[0]}/decision",
        json={"decision": "approve", "note": "validated source IP"},
        headers=auth["approver"],
    )
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "approved"
    assert first.json()["decided_at"] is not None
    assert first.json()["execution_status"] == "dry_run"

    # Other actions are still waiting, so the incident must not be marked contained.
    pending_state = client.get(f"/api/incidents/{incident['id']}", headers=auth["analyst"]).json()
    assert pending_state["status"] == "awaiting_approval"

    for action_id in action_ids[1:]:
        decision = client.post(
            f"/api/approvals/{action_id}/decision",
            json={"decision": "approve"},
            headers=auth["approver"],
        )
        assert decision.status_code == 200, decision.text

    updated = client.get(f"/api/incidents/{incident['id']}", headers=auth["analyst"]).json()
    assert updated["status"] == "contained"

    audit = client.get("/api/audit", headers=auth["admin"]).json()
    assert any(entry["action"] == "action.approved" for entry in audit)
    assert any(entry["action"] == "investigation.completed" for entry in audit)


def test_rejection_keeps_incident_awaiting_approval(client, auth, ingest):
    incident = _investigated_incident(client, auth, ingest)
    action_id = incident["actions"][0]["id"]
    response = client.post(
        f"/api/approvals/{action_id}/decision",
        json={"decision": "reject", "note": "legitimate admin activity"},
        headers=auth["approver"],
    )
    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    updated = client.get(f"/api/incidents/{incident['id']}", headers=auth["analyst"]).json()
    assert updated["status"] == "awaiting_approval"


def test_second_decision_conflicts(client, auth, ingest):
    incident = _investigated_incident(client, auth, ingest)
    action_id = incident["actions"][0]["id"]
    first = client.post(
        f"/api/approvals/{action_id}/decision", json={"decision": "approve"}, headers=auth["approver"]
    )
    second = client.post(
        f"/api/approvals/{action_id}/decision", json={"decision": "reject"}, headers=auth["approver"]
    )
    assert first.status_code == 200
    assert second.status_code == 409


def test_manual_status_change_is_audited(client, auth, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    response = client.patch(
        f"/api/incidents/{incident_id}/status", json={"status": "closed"}, headers=auth["analyst"]
    )
    assert response.status_code == 200
    assert response.json()["status"] == "closed"
    audit = client.get("/api/audit", headers=auth["admin"]).json()
    assert any(entry["action"] == "incident.status_changed" for entry in audit)
