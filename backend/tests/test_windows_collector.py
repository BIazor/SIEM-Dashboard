"""Windows Event Log collector mapping tests (no Windows APIs required)."""

from __future__ import annotations

from app.ingestion.normalize import normalize_wazuh_alert
from tools.windows_event_collector import build_payload


def _event(event_id: int, record_id: int = 1, **event_data: str) -> dict:
    return {
        "channel": "Security",
        "recordId": record_id,
        "id": event_id,
        "provider": "Microsoft-Windows-Security-Auditing",
        "timeCreated": "2026-11-09T08:00:00.0000000Z",
        "computer": "TEST-PC",
        "level": "Information",
        "message": "Security event",
        "eventData": event_data,
    }


def test_failed_logon_maps_to_brute_force_with_source_ip():
    alert = normalize_wazuh_alert(
        build_payload(
            _event(
                4625,
                record_id=9001,
                TargetUserName="alice",
                IpAddress="203.0.113.9",
                LogonType="3",
                Status="0xc000006d",
                SubStatus="0xc000006a",
            )
        )
    )
    assert alert.alert_uid == "win-TEST-PC-Security-9001"
    assert alert.category == "brute_force"
    assert alert.severity == "medium"
    assert alert.src_ip == "203.0.113.9"
    assert alert.username == "alice"
    assert alert.host == "TEST-PC"


def test_successful_logon_is_low_noise():
    alert = normalize_wazuh_alert(
        build_payload(_event(4624, record_id=9002, TargetUserName="bob", IpAddress="10.0.0.5"))
    )
    assert alert.category == "other"
    assert alert.severity == "info"
    assert alert.src_ip == "10.0.0.5"


def test_powershell_process_creation_is_high_severity():
    alert = normalize_wazuh_alert(
        build_payload(
            _event(
                4688,
                record_id=9003,
                SubjectUserName="carol",
                NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine="powershell.exe -nop -enc SQBFAFgA",
            )
        )
    )
    assert alert.category == "powershell"
    assert alert.rule_level == 10
    assert alert.severity == "high"


def test_account_creation_and_audit_cleared_are_distinct_and_severe():
    created = normalize_wazuh_alert(
        build_payload(_event(4720, record_id=9004, TargetUserName="mallory", SubjectUserName="admin"))
    )
    cleared = normalize_wazuh_alert(
        build_payload(_event(1102, record_id=9005, SubjectUserName="admin"))
    )
    assert created.category == "privilege_change"
    assert created.username == "mallory"
    assert cleared.category == "other"
    assert cleared.severity == "critical"
    assert created.alert_uid != cleared.alert_uid
