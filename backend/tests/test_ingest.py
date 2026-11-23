"""Ingestion, normalization and classification tests."""

from __future__ import annotations

from app.sim.scenarios import (
    beaconing_network,
    failed_logins,
    file_integrity,
    privilege_change,
    suspicious_powershell,
)


def test_ingest_requires_valid_token(client, users):
    payload = {"alerts": failed_logins()}
    assert client.post("/api/ingest/wazuh", json=payload).status_code == 401
    bad = client.post("/api/ingest/wazuh", json=payload, headers={"X-Ingest-Token": "nope"})
    assert bad.status_code == 401


def test_failed_logins_create_one_incident(ingest, client, auth):
    body = ingest(failed_logins())
    assert body["accepted"] == 8
    assert len(body["incidents"]) == 1
    severities = {alert["severity"] for alert in body["alerts"]}
    assert severities == {"low", "high"}  # rule level 5 and 10
    assert all(alert["category"] == "brute_force" for alert in body["alerts"])
    assert all(alert["src_ip"] == "203.0.113.45" for alert in body["alerts"])

    detail = client.get(f"/api/incidents/{body['incidents'][0]}", headers=auth["viewer"]).json()
    assert detail["alert_count"] == 8
    assert detail["severity"] == "high"
    assert detail["priority"] == 2
    assert detail["techniques"] == ["T1110 - Brute Force"]


def test_duplicate_alerts_are_counted_not_stored(ingest, client, auth):
    first = ingest(failed_logins())
    second = ingest(failed_logins())
    assert second["accepted"] == 0
    assert second["duplicates"] == len(failed_logins())
    assert second["incidents"] == []
    listing = client.get("/api/alerts", headers=auth["viewer"]).json()
    assert listing["total"] == first["accepted"]


def test_powershell_scenario_is_critical_and_technique_tagged(ingest):
    body = ingest(suspicious_powershell())
    alerts = body["alerts"]
    assert len(alerts) == 2
    assert {a["category"] for a in alerts} == {"powershell"}
    assert alerts[0]["severity"] == "critical"  # rule level 12
    assert "T1059.001" in alerts[0]["technique"]


def test_beaconing_scenario_categorized_as_network(ingest):
    body = ingest(beaconing_network())
    assert {a["category"] for a in body["alerts"]} == {"network"}
    assert {a["dst_ip"] for a in body["alerts"]} == {"198.51.100.77"}


def test_privilege_and_file_scenarios_are_classified(ingest):
    privilege = ingest(privilege_change())
    assert {a["category"] for a in privilege["alerts"]} == {"privilege_change"}
    integrity = ingest(file_integrity())
    assert {a["category"] for a in integrity["alerts"]} == {"file_integrity"}


def test_invalid_ip_and_control_characters_are_sanitized(ingest):
    payload = [
        {
            "id": "sanitize-1",
            "timestamp": "2026-01-01T00:00:00Z",
            "rule": {"id": "5710", "level": 7, "description": "Failed password for root\x00\x07"},
            "agent": {"name": "HOST-1"},
            "data": {"srcip": "999.999.999.999", "dstuser": "root"},
            "full_log": "bad\tchars\x01 here",
        }
    ]
    body = ingest(payload)
    alert = body["alerts"][0]
    assert alert["src_ip"] is None
    assert "\x00" not in alert["title"]
    assert alert["category"] == "brute_force"


def test_batch_size_is_enforced(client, users):
    oversized = {"alerts": [{"id": f"x{i}"} for i in range(501)]}
    response = client.post(
        "/api/ingest/wazuh", json=oversized, headers={"X-Ingest-Token": "test-ingest-token"}
    )
    assert response.status_code == 413


def test_payload_shape_is_validated(client, users, ingest):
    body = ingest({"alerts": [{"id": "single", "rule": {"level": 3}}]})
    assert body["accepted"] == 1
    assert body["alerts"][0]["category"] == "other"


def test_incident_correlation_merges_same_entity(client, users, ingest, auth):
    base = failed_logins()
    ingest(base[:4])
    body = ingest(base[4:])
    listing = client.get("/api/incidents", headers=auth["viewer"]).json()
    assert len(listing) == 1
    assert listing[0]["alert_count"] == 8
    assert body["incidents"] == [listing[0]["id"]]
