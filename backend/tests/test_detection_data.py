"""Detection rules as data, suppression, entity normalization and cross-category linking."""

from __future__ import annotations

import pytest

import app.detection.rules as rules_module
from app.detection.correlation import normalize_entity
from app.detection.rules import (
    RuleConfigError,
    Suppression,
    load_rules,
    rule_catalog,
    rules_version,
    technique_for_category,
)


def _alert(uid: str, description: str, host: str = "HOST-1", level: int = 10, ip: str = "203.0.113.9") -> dict:
    return {
        "id": uid,
        "timestamp": "2026-11-01T10:00:00Z",
        "rule": {"id": "100001", "level": level, "description": description},
        "agent": {"name": host},
        "data": {"srcip": ip, "dstuser": "root"},
        "full_log": description,
    }


def test_rule_catalog_is_data_driven_and_referenced():
    catalog = rule_catalog()
    keys = {entry["key"] for entry in catalog}
    assert {"auth.failure", "powershell.execution", "network.behavior"} <= keys
    assert all(entry["references"] for entry in catalog)
    assert all("T1000" not in (entry["technique"] or "") for entry in catalog)
    assert technique_for_category("other") is None
    assert rules_version()


def test_malformed_rule_file_is_rejected(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text('{"version":"1","rules":[{"key":"x","category":"nope","patterns":["a"]}]}', encoding="utf-8")
    with pytest.raises(RuleConfigError):
        load_rules(path)

    duplicate = tmp_path / "dupes.json"
    duplicate.write_text(
        '{"version":"1","rules":['
        '{"key":"a","category":"network","patterns":["x"]},'
        '{"key":"a","category":"network","patterns":["y"]}]}',
        encoding="utf-8",
    )
    with pytest.raises(RuleConfigError):
        load_rules(duplicate)


def test_unmatched_activity_has_no_technique(ingest):
    alert = ingest([_alert("unmapped-1", "Quarterly compliance review completed", level=3)])["alerts"][0]
    assert alert["category"] == "other"
    assert alert["technique"] is None
    assert alert["detection_rule"] == "unmatched"


def test_missing_timestamp_is_flagged_as_inferred(ingest):
    payload = _alert("no-timestamp", "Failed password for root")
    payload.pop("timestamp")
    alert = ingest([payload])["alerts"][0]
    assert alert["event_time_inferred"] is True

    reported = ingest([_alert("with-timestamp", "Failed password for root")])["alerts"][0]
    assert reported["event_time_inferred"] is False


def test_suppression_downgrades_but_keeps_the_alert(ingest, monkeypatch):
    monkeypatch.setattr(
        rules_module,
        "SUPPRESSIONS",
        (Suppression(reason="known scanner", hosts=frozenset({"scan-01"}), src_ips=frozenset(), categories=frozenset()),),
    )
    alert = ingest([_alert("suppressed-1", "Failed password for root", host="SCAN-01", level=12)])["alerts"][0]
    assert alert["suppressed"] is True
    assert alert["severity"] == "info"
    assert alert["category"] == "brute_force"


def test_entity_normalization_collapses_case_domain_and_account():
    assert normalize_entity("WS01") == normalize_entity("ws01.corp.example") == "ws01"
    assert normalize_entity("CORP\\Analyst") == "analyst"
    assert normalize_entity("203.0.113.5") == "203.0.113.5"
    assert normalize_entity(None) == "unknown"


def test_host_spelling_variants_share_one_incident(ingest):
    first = ingest([_alert("case-1", "Failed password for root", host="WS01")])
    second = ingest([_alert("case-2", "Failed password for root", host="ws01.corp.example")])
    assert second["incidents"] == first["incidents"]


def test_different_categories_on_one_host_are_linked(client, auth, ingest):
    first = ingest([_alert("link-1", "Encoded PowerShell command executed", host="HOST-L", level=12)])["incidents"][0]
    second = ingest([_alert("link-2", "Outbound connection to a beacon endpoint", host="HOST-L", level=10)])["incidents"][0]
    assert first != second

    first_detail = client.get(f"/api/incidents/{first}", headers=auth["analyst"]).json()
    second_detail = client.get(f"/api/incidents/{second}", headers=auth["analyst"]).json()
    assert second in first_detail["related_incident_ids"]
    assert first in second_detail["related_incident_ids"]


def test_detection_stats_count_rule_hits(client, auth, ingest):
    ingest([_alert(f"stat-{index}", "Failed password for root") for index in range(3)])
    body = client.get("/api/stats/detections", headers=auth["analyst"]).json()
    entry = {rule["key"]: rule for rule in body["rules"]}["auth.failure"]
    assert entry["alerts"] == 3
    assert entry["suppressed"] == 0
    assert body["unmatched_alerts"] == 0


def test_investigation_persists_inputs_and_derived_gaps(client, auth, ingest):
    incident_id = ingest([_alert("snapshot-1", "Failed password for root")])["incidents"][0]
    client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["analyst"])
    detail = client.get(f"/api/incidents/{incident_id}", headers=auth["analyst"]).json()

    investigator = next(item for item in detail["investigations"] if item["agent"] == "investigator")
    critic = next(item for item in detail["investigations"] if item["agent"] == "critic")
    assert investigator["engine_version"] == "rules-v2"
    assert investigator["inputs"]["digest"]
    assert investigator["inputs"]["alert_ids"]
    # No success/outcome telemetry exists for this incident, so the gap is derived.
    assert any("outcome" in item.lower() for item in critic["missing_information"])
    assert critic["verdict"] == "supported"
