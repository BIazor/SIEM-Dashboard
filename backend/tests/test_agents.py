"""Agent tooling and reviewer tests (rule-based investigation)."""

from __future__ import annotations

import pytest

from app.agents import critic, investigator
from app.agents.evidence import collect
from app.agents.tooling import ToolPermissionError, ToolValidationError, catalog, execute
from app.models import Incident
from app.sim.scenarios import failed_logins


@pytest.fixture
def incident(db, ingest) -> Incident:
    body = ingest(failed_logins())
    return db.get(Incident, body["incidents"][0])


def test_tool_catalog_is_read_only_and_schemas_forbid_extras():
    tools = catalog()
    names = {tool["name"] for tool in tools}
    assert {"get_incident_summary", "list_incident_alerts", "search_alerts"} <= names
    assert "run_shell" not in names and "http_get" not in names
    assert all(tool["read_only"] for tool in tools)
    for tool in tools:
        assert tool["arguments_schema"]["additionalProperties"] is False


def test_unknown_tool_is_denied(db, incident):
    with pytest.raises(ToolPermissionError):
        execute(db, "run_shell", {"command": "whoami"}, incident)


def test_tool_arguments_are_strictly_validated(db, incident):
    with pytest.raises(ToolValidationError):
        execute(db, "list_incident_alerts", {"incident_id": incident.id, "limit": 5000}, incident)
    with pytest.raises(ToolValidationError):
        execute(db, "list_incident_alerts", {"incident_id": incident.id, "surprise": True}, incident)
    with pytest.raises(ToolValidationError):
        execute(db, "get_host_activity", {"value": "", "limit": 5}, incident)


def test_tool_scope_blocks_other_entities(db, incident):
    with pytest.raises(ToolPermissionError):
        execute(db, "get_host_activity", {"value": "WKS-ENG-04"}, incident)
    with pytest.raises(ToolPermissionError):
        execute(db, "get_ip_activity", {"value": "10.0.0.9"}, incident)
    with pytest.raises(ToolPermissionError):
        execute(db, "get_incident_summary", {"incident_id": incident.id + 99}, incident)


def test_in_scope_tool_returns_bounded_data(db, incident):
    result = execute(db, "list_incident_alerts", {"incident_id": incident.id, "limit": 5}, incident)
    assert len(result["alerts"]) == 5
    assert all("alert_id" in alert for alert in result["alerts"])


def test_heuristic_investigation_cites_real_alerts(db, incident):
    evidence = collect(db, incident)
    result = investigator.investigate(incident, evidence)
    assert result["provider"] == "heuristic"
    assert result["model"] == "rules-v2"
    assert result["findings"]
    valid_ids = set(evidence.alert_ids)
    for finding in result["findings"]:
        assert set(finding["evidence_alert_ids"]) <= valid_ids
    assert result["error"] is None


def test_critic_flags_unsupported_confirmed_claim(db, incident):
    evidence = collect(db, incident)
    fabricated = {
        "summary": "An incident summary produced for testing.",
        "findings": [
            {
                "statement": "Confirmed data exfiltration to 198.51.100.77.",
                "evidence_alert_ids": [999_999],
                "confidence": "high",
                "nature": "confirmed",
            }
        ],
        "confidence": 0.8,
        "recommendations": [],
    }
    reviewed = critic.review(incident, evidence, fabricated)
    assert reviewed["unsupported_claims"]
    assert reviewed["verdict"] != "supported"
    assert reviewed["confidence"] < 0.8


def test_critic_supports_grounded_investigation(db, incident):
    evidence = collect(db, incident)
    primary = investigator.investigate(incident, evidence)
    reviewed = critic.review(incident, evidence, primary)
    assert reviewed["verdict"] in {"supported", "partially_supported"}
    assert reviewed["missing_information"]
    assert reviewed["summary"]
