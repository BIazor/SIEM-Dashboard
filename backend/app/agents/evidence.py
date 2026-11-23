"""Deterministic evidence collection.

All data the agents see comes through :mod:`app.agents.tooling`, so the same validation
and scope rules apply regardless of the alert category.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from ..models import Incident
from .tooling import ToolError, execute

MAX_USERS = 3
MAX_IPS = 2


@dataclass
class Evidence:
    incident: dict = field(default_factory=dict)
    alerts: list[dict] = field(default_factory=list)
    host_activity: dict = field(default_factory=dict)
    ip_activity: dict[str, dict] = field(default_factory=dict)
    user_activity: dict[str, dict] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

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

    def digest(self) -> str:
        """Stable fingerprint of the material an agent reasoned over."""
        canonical = json.dumps(
            [
                {
                    "id": a["alert_id"],
                    "title": a["title"],
                    "severity": a["severity"],
                    "category": a["category"],
                    "event_time": a["event_time"],
                }
                for a in sorted(self.alerts, key=lambda item: item["alert_id"])
            ],
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]

    def snapshot(self) -> dict:
        """What the agents were given, stored with the investigation record."""
        return {
            "alert_ids": self.alert_ids[:200],
            "alert_count": len(self.alerts),
            "digest": self.digest(),
            "collected_at": self.collected_at.isoformat(),
            "usernames": sorted(self.user_activity),
            "ip_addresses": sorted(self.ip_activity),
            "hosts": [self.host_activity.get("host")] if self.host_activity else [],
            "tool_failures": list(self.failures),
        }


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

    # Every actor in the incident matters: looking only at the first username hides
    # a password-spraying campaign against several accounts.
    usernames = sorted({a["username"] for a in evidence.alerts if a.get("username")})[:MAX_USERS]
    for username in usernames:
        result = call("get_user_activity", {"value": username, "limit": 25})
        if result:
            evidence.user_activity[username] = result

    known_values = {a.get("src_ip") for a in evidence.alerts} | {a.get("dst_ip") for a in evidence.alerts}
    addresses = sorted({value for value in known_values if value})[:MAX_IPS]
    for address in addresses:
        result = call("get_ip_activity", {"value": address, "limit": 25})
        if result:
            evidence.ip_activity[address] = result
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
        times.append(parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC))
    return sorted(times)


def beacon_intervals(evidence: Evidence) -> list[float]:
    times = alert_times(evidence)
    if len(times) < 3:
        return []
    deltas = [round((b - a).total_seconds(), 1) for a, b in zip(times, times[1:], strict=False)]
    return [d for d in deltas if d > 0]


def evidence_confidence(evidence: Evidence) -> float:
    """Confidence from how complete the telemetry is, not from how much was written.

    Each factor is a property of the evidence a reviewer can check, which makes the
    number defensible: breadth of evidence raises it, missing actors and rejected
    tool calls lower it.
    """
    score = 0.35
    count = len(evidence.alerts)
    if count >= 3:
        score += 0.10
    if count >= 5:
        score += 0.10
    sources = {a.get("src_ip") for a in evidence.alerts if a.get("src_ip")}
    if sources:
        score += 0.05
    if len(sources) > 1:
        score += 0.05
    if any(a.get("host") for a in evidence.alerts):
        score += 0.05
    if any(a.get("username") for a in evidence.alerts):
        score += 0.05
    if any(a.get("dst_ip") for a in evidence.alerts):
        score += 0.05
    if evidence.host_activity:
        score += 0.05
    if evidence.failures:
        score -= 0.10 * len(evidence.failures)
    return round(max(0.2, min(0.85, score)), 2)
