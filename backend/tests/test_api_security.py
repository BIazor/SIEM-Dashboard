"""API security: authentication, authorization, headers and input handling."""

from __future__ import annotations

from app.sim.scenarios import failed_logins


def test_health_is_public(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_protected_endpoints_require_authentication(client, users):
    for path in ("/api/alerts", "/api/incidents", "/api/approvals", "/api/stats/overview"):
        assert client.get(path).status_code == 401, path
    assert client.get("/api/audit").status_code == 401


def test_viewer_is_read_only(client, auth, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    assert client.get("/api/incidents", headers=auth["viewer"]).status_code == 200
    assert (
        client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["viewer"]).status_code == 403
    )
    assert (
        client.patch(
            f"/api/incidents/{incident_id}/status", json={"status": "closed"}, headers=auth["viewer"]
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/incidents/{incident_id}/actions",
            json={"action_type": "block_ip", "target": "203.0.113.45"},
            headers=auth["viewer"],
        ).status_code
        == 403
    )
    assert client.get("/api/agents/tools", headers=auth["viewer"]).status_code == 403


def test_approver_cannot_run_investigations(client, auth, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    response = client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["approver"])
    assert response.status_code == 403


def test_analyst_cannot_approve_actions(client, auth, ingest):
    incident_id = ingest(failed_logins())["incidents"][0]
    client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["analyst"])
    pending = client.get("/api/approvals", headers=auth["analyst"]).json()
    assert pending, "investigation should have produced proposed actions"
    response = client.post(
        f"/api/approvals/{pending[0]['id']}/decision",
        json={"decision": "approve", "note": "self approved"},
        headers=auth["analyst"],
    )
    assert response.status_code == 403


def test_audit_log_is_admin_only(client, auth):
    assert client.get("/api/audit", headers=auth["analyst"]).status_code == 403
    assert client.get("/api/audit", headers=auth["admin"]).status_code == 200


def test_security_headers_are_set(client):
    headers = client.get("/api/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"


def test_cors_allows_configured_origin_only(client):
    allowed = client.options(
        "/api/health",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"

    blocked = client.options(
        "/api/health",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert blocked.headers.get("access-control-allow-origin") is None


def test_like_wildcards_are_escaped(client, auth, ingest):
    ingest(failed_logins())
    wildcard = client.get("/api/alerts", params={"q": "%"}, headers=auth["analyst"])
    underscore = client.get("/api/alerts", params={"q": "_"}, headers=auth["analyst"])
    assert wildcard.status_code == 200 and wildcard.json()["total"] == 0
    assert underscore.status_code == 200 and underscore.json()["total"] == 0
    matched = client.get("/api/alerts", params={"q": "logon failure"}, headers=auth["analyst"])
    assert matched.json()["total"] == 8


def test_invalid_path_and_query_types_are_rejected(client, auth, ingest):
    ingest(failed_logins())
    assert client.get("/api/alerts/abc", headers=auth["analyst"]).status_code == 422
    assert client.get("/api/alerts", params={"limit": 5000}, headers=auth["analyst"]).status_code == 422
    assert (
        client.get("/api/alerts", params={"severity": "catastrophic"}, headers=auth["analyst"]).status_code
        == 422
    )


def test_unknown_route_returns_404(client):
    assert client.get("/api/does-not-exist").status_code == 404
