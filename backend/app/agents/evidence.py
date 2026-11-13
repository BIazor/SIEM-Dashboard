"""Deterministic evidence collection.

All data the agents see comes through :mod:`app.agents.tooling`, so the same validation
and scope rules apply whether an LLM is configured or not.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models import Incident
from .guardrails import wrap_untrusted
from .tooling import ToolError, execute


@dataclass
class Evidence:
    incident: dict = field(default_factory=dict)
    alerts: list[dict] = field(default_factory=list)
    host_activity: dict = field(default_factory=dict)
    ip_activity: dict = field(default_factory=dict)
    user_activity: dict = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)

    @property
    def alert_ids(self) -> list[int]:
        return [a["alert_id"] for a in self.alerts]

    def as_evidence_list(self) -> list[dict]:
        return [
            {
                "alert_id": a["alert_id"],
                "title": a["title"],
                "severity": a["severity"],
                "category": a["category"],
                "host": a["host"],
                "src_ip": a["src_ip"],
                "username": a["username"],
                "event_time": a["event_time"],
            }
            for a in self.alerts
        ]

    def summary_for_prompt(self) -> str:
        lines = [
            f"Incident: {self.incident.get('title')}",
            f"Entity: {self.incident.get('entity')} | Category: {self.incident.get('category')} "
            f"| Severity: {self.incident.get('severity')} | Alerts: {len(self.alerts)}",
            f"First seen: {self.incident.get('first_seen')} | Last seen: {self.incident.get('last_seen')}",
            "Alerts (id | time | severity | category | host | src_ip | user | title):",
        ]
        for alert in self.alerts:
            lines.append(
                f"- {alert['alert_id']} | {alert['event_time']} | {alert['severity']} | {alert['category']} "
                f"| {alert['host'] or '-'} | {alert['src_ip'] or '-'} | {alert['username'] or '-'} | {alert['title']}"
            )
        if self.host_activity:
            lines.append(f"Host activity: {self.host_activity}")
        if self.ip_activity:
            lines.append(f"IP activity: {self.ip_activity}")
        if self.user_activity:
            lines.append(f"User activity: {self.user_activity}")
        if self.failures:
            lines.append("Tool calls that were rejected: " + "; ".join(self.failures))
        # Titles, hostnames, usernames and command lines all originate in log data.
        # Redact instruction-like text and delimit the block so the model treats it as data.
        return wrap_untrusted("evidence_bundle", "\n".join(lines), limit=8000)


def collect(db: Session, incident: Incident) -> Evidence:
    evidence = Evidence()

    def call(name: str, args: dict) -> dict:
        try:
            return execute(db, name, args, incident)
        except ToolError as exc:
            evidence.failures.append(f"{name}: {exc}")
            return {}

    evidence.incident = call("get_incident_summary", {"incident_id": incident.id})
    evidence.alerts = call("list_incident_alerts", {"incident_id": incident.id, "limit": 50}).get("alerts", [])

    if incident.host:
        evidence.host_activity = call("get_host_activity", {"value": incident.host, "limit": 25})
    if incident.entity and any(a.get("src_ip") == incident.entity for a in evidence.alerts):
        evidence.ip_activity = call("get_ip_activity", {"value": incident.entity, "limit": 25})
    usernames = {a["username"] for a in evidence.alerts if a.get("username")}
    if usernames:
        evidence.user_activity = call("get_user_activity", {"value": sorted(usernames)[0], "limit": 25})
    return evidence


def counters(evidence: Evidence) -> dict:
    return {
        "by_category": Counter(a.get("category", "other") for a in evidence.alerts),
        "by_severity": Counter(a.get("severity", "info") for a in evidence.alerts),
        "by_src_ip": Counter(a.get("src_ip") for a in evidence.alerts if a.get("src_ip")),
        "by_user": Counter(a.get("username") for a in evidence.alerts if a.get("username")),
        "by_host": Counter(a.get("host") for a in evidence.alerts if a.get("host")),
    }


def alert_times(evidence: Evidence) -> list[datetime]:
    times: list[datetime] = []
    for alert in evidence.alerts:
        raw = alert.get("event_time")
        if not raw:
            continue
        try:
            parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        times.append(parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc))
    return sorted(times)


def beacon_intervals(evidence: Evidence) -> list[float]:
    times = alert_times(evidence)
    if len(times) < 3:
        return []
    deltas = [round((b - a).total_seconds(), 1) for a, b in zip(times, times[1:])]
    return [d for d in deltas if d > 0]
