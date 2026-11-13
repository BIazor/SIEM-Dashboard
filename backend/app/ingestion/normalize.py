"""Normalize Wazuh / Sysmon alerts into the platform's alert shape.

All fields are treated as untrusted: values are coerced, length-limited and
stripped of control characters before they enter the database or any prompt.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..detection.rules import classify_category, severity_from_rule_level, technique_for_category

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"[ \t]+")


def clean_text(value: Any, max_length: int = 4000) -> str:
    """Return a safe, length-limited string from an untrusted value."""
    if value is None:
        return ""
    text = str(value)
    text = _CONTROL_CHARS.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _WHITESPACE.sub(" ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()[:max_length]


def _clean_ip(value: Any) -> str | None:
    text = clean_text(value, 64)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_timestamp(value: Any) -> datetime:
    text = clean_text(value, 64)
    if text:
        candidate = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _dig(data: Any, *keys: str) -> Any:
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


@dataclass
class NormalizedEvent:
    alert_uid: str
    source: str
    rule_id: str
    rule_level: int
    severity: str
    category: str
    technique: str
    title: str
    description: str
    src_ip: str | None
    dst_ip: str | None
    host: str | None
    username: str | None
    event_time: datetime
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "alert_uid": self.alert_uid,
            "source": self.source,
            "rule_id": self.rule_id,
            "rule_level": self.rule_level,
            "severity": self.severity,
            "category": self.category,
            "technique": self.technique,
            "title": self.title,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "host": self.host,
            "username": self.username,
            "event_time": self.event_time,
            "raw": self.raw,
        }


def _fingerprint(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return "evt-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def normalize_wazuh_alert(payload: dict[str, Any], source: str = "wazuh") -> NormalizedEvent:
    """Map a Wazuh (or Wazuh-forwarded Sysmon) alert document to NormalizedEvent."""
    if not isinstance(payload, dict):
        raise ValueError("Alert payload must be an object")

    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}
    data = payload.get("data") if isinstance(payload.get("data"), dict) else {}

    win = data.get("win") if isinstance(data.get("win"), dict) else {}
    eventdata = win.get("eventdata") if isinstance(win.get("eventdata"), dict) else {}
    system = win.get("system") if isinstance(win.get("system"), dict) else {}

    title = clean_text(rule.get("description") or payload.get("title") or "Unclassified security event", 300)
    full_log = clean_text(
        payload.get("full_log") or payload.get("message") or eventdata.get("commandLine") or "", 4000
    )

    rule_level = _coerce_int(rule.get("level", payload.get("rule_level", 0)))
    rule_id = clean_text(rule.get("id", payload.get("rule_id", "")), 40) or "0"

    # A single comma-separated field from Wazuh keeps normalisation simple.
    groups_raw = rule.get("groups") or payload.get("groups") or []
    if isinstance(groups_raw, str):
        groups = [g.strip() for g in groups_raw.split(",") if g.strip()]
    elif isinstance(groups_raw, list):
        groups = [clean_text(g, 40) for g in groups_raw]
    else:
        groups = []

    src_ip = _clean_ip(
        data.get("srcip") or data.get("src_ip") or _dig(data, "win", "eventdata", "ipAddress")
    )
    dst_ip = _clean_ip(data.get("dstip") or data.get("dst_ip"))
    host = clean_text(agent.get("name") or data.get("hostname") or system.get("computer"), 120) or None
    username = clean_text(
        data.get("dstuser")
        or data.get("srcuser")
        or eventdata.get("targetUserName")
        or eventdata.get("user")
        or payload.get("username"),
        120,
    ) or None

    category = classify_category(
        title=title,
        description=full_log,
        rule_id=rule_id,
        groups=groups,
    )
    severity = severity_from_rule_level(rule_level, category)

    alert_uid = clean_text(payload.get("id") or payload.get("alert_uid") or "", 128) or _fingerprint(payload)

    return NormalizedEvent(
        alert_uid=alert_uid,
        source=clean_text(source, 40) or "wazuh",
        rule_id=rule_id,
        rule_level=max(0, min(rule_level, 16)),
        severity=severity,
        category=category,
        technique=technique_for_category(category),
        title=title,
        description=full_log,
        src_ip=src_ip,
        dst_ip=dst_ip,
        host=host,
        username=username,
        event_time=_parse_timestamp(payload.get("timestamp")),
        raw=payload,
    )
