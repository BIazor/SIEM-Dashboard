"""Investigator agent: builds the primary investigation.

A deterministic engine derives confirmed facts from validated evidence. Every
statement carries the alert IDs that support it, and anything the telemetry
cannot prove is kept separately as an open hypothesis.
"""

from __future__ import annotations

import re

from ..models import Incident
from .evidence import Evidence, beacon_intervals

POWERSHELL_INDICATORS = {
    "encoded_command": re.compile(r"(?i)(encodedcommand|\s-enc\s|\s-e\s[a-z0-9+/=]{8,})"),
    "download_string": re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|wget |curl )"),
    "execution_policy_bypass": re.compile(r"(?i)(-nop|-noprofile|bypass|unrestricted)"),
    "obfuscation": re.compile(r"(?i)(frombase64string|iex\s*\(|invoke-expression|\[char\])"),
}

PRIVILEGED_GROUP = re.compile(r"(?i)(administrators?|sudo|wheel|domain admins?|root|privileged)")

SYSTEM_PATHS = re.compile(
    r"(?i)(c:\\windows|c:\\programdata|/etc/|/usr/bin|/usr/sbin|startup folder|\\start menu\\|run key)"
)

PLACEHOLDER_VALUES = {"-", "n/a", "na", "unknown", "null", "none"}


def _named(value: str | None) -> bool:
    """Windows writes '-' into empty fields; treat those as no value at all."""
    return bool(value) and value.strip().lower() not in PLACEHOLDER_VALUES


def heuristic_findings(incident: Incident, evidence: Evidence) -> tuple[list[dict], list[str], list[dict]]:
    """Return (findings, hypotheses, recommendations) derived deterministically."""
    from ..detection.rules import SEVERITY_RANK  # local import avoids a cycle at module import

    findings: list[dict] = []
    hypotheses: list[str] = []
    recommendations: list[dict] = []
    category = incident.category
    ids = evidence.alert_ids
    severity = incident.severity
    entity = incident.entity

    def add(statement: str, evidence_ids: list[int], confidence: str = "high", nature: str = "confirmed") -> None:
        findings.append(
            {
                "statement": statement,
                "evidence_alert_ids": [i for i in evidence_ids if i in ids][:10],
                "confidence": confidence,
                "nature": nature,
            }
        )

    if category == "brute_force":
        failures = [a for a in evidence.alerts if "fail" in (a["title"] + " " + a.get("description", "")).lower()]
        sources = sorted({a["src_ip"] for a in failures if a["src_ip"]})
        targets = sorted({a["username"] for a in failures if _named(a["username"])})
        accused = ", ".join(targets) if targets else "an unidentified account"
        add(
            f"{len(failures)} authentication failures were recorded against "
            f"{accused} from {', '.join(sources) if sources else 'an internal source'}.",
            [a["alert_id"] for a in failures],
        )
        if len(sources) == 1 and len(failures) >= 5:
            conclusions = "consistent with a password-guessing campaign from a single source"
            add(
                f"The failures come from one source address ({sources[0]}), {conclusions}.",
                [a["alert_id"] for a in failures],
                confidence="high",
            )
        if len(targets) > 1:
            hypotheses.append(
                f"{len(targets)} distinct accounts were targeted, suggesting password spraying rather than a targeted guess."
            )
        if len(failures) < 5:
            hypotheses.append("The failure volume is low and may be explained by ordinary user error.")
        recommendations.append(
            {
                "action_type": "block_ip",
                "target": sources[0] if sources else entity,
                "rationale": "Source of repeated authentication failures; block at the perimeter pending review.",
                "risk_level": "medium",
            }
        )
        if targets:
            recommendations.append(
                {
                    "action_type": "disable_account",
                    "target": targets[0],
                    "rationale": "Targeted account should be locked and its password reset if compromise is confirmed.",
                    "risk_level": "high",
                }
            )

    elif category == "powershell":
        text = " ".join((a.get("description") or "") + " " + a["title"] for a in evidence.alerts)
        matched = [name for name, pattern in POWERSHELL_INDICATORS.items() if pattern.search(text)]
        if matched:
            add(
                "PowerShell execution shows high-risk indicators: " + ", ".join(sorted(matched)).replace("_", " ") + ".",
                ids,
            )
        else:
            add("PowerShell activity was recorded on the host without recognised high-risk flags.", ids, "medium")
        if "encoded_command" in matched or "obfuscation" in matched:
            hypotheses.append(
                "The encoded/obfuscated command may decode to a download cradle or in-memory payload; "
                "decoding the script block is required to confirm."
            )
        hypotheses.append("No parent-process telemetry is available, so the launch chain cannot be confirmed.")
        recommendations.append(
            {
                "action_type": "isolate_host",
                "target": incident.host or entity,
                "rationale": "Encoded PowerShell on a workstation justifies network isolation during triage.",
                "risk_level": "high",
            }
        )
        recommendations.append(
            {
                "action_type": "collect_forensics",
                "target": incident.host or entity,
                "rationale": "Preserve the PowerShell script block log and volatile process memory.",
                "risk_level": "low",
            }
        )

    elif category == "network":
        dsts = sorted({a.get("dst_ip") for a in evidence.alerts if a.get("dst_ip")})
        intervals = beacon_intervals(evidence)
        add(
            f"Outbound connections were observed to {', '.join(dsts) if dsts else 'external infrastructure'} "
            f"from {incident.host or entity}.",
            ids,
        )
        if len(intervals) >= 2 and max(intervals) - min(intervals) <= max(3.0, 0.15 * (sum(intervals) / len(intervals))):
            jitter = max(intervals) - min(intervals)
            add(
                f"Connection timing is highly regular (~{sum(intervals) / len(intervals):.0f}s apart, jitter {jitter:.1f}s), "
                "which is characteristic of beaconing.",
                ids,
            )
            hypotheses.append("Regular callbacks suggest command-and-control check-in rather than user-driven traffic.")
        else:
            hypotheses.append("Traffic regularity is not sufficient to distinguish beaconing from application polling.")
        recommendations.append(
            {
                "action_type": "block_ip",
                "target": dsts[0] if dsts else entity,
                "rationale": "Block the suspicious destination at the firewall if it is not a sanctioned service.",
                "risk_level": "medium",
            }
        )

    elif category == "privilege_change":
        privileged = [a for a in evidence.alerts if PRIVILEGED_GROUP.search((a["title"] + " " + a.get("description", "")))]
        add(
            f"{len(privileged) or len(evidence.alerts)} privilege-related change(s) were recorded"
            + (f" involving {', '.join(sorted({a['username'] for a in privileged if a['username']}))}" if privileged else "")
            + ".",
            [a["alert_id"] for a in privileged] or ids,
        )
        hypotheses.append(
            "A change to a privileged group can be legitimate administrative work; a change ticket or operator "
            "confirmation is needed before treating it as malicious."
        )
        recommendations.append(
            {
                "action_type": "disable_account",
                "target": (sorted({a["username"] for a in evidence.alerts if a["username"]})[0]
                           if any(a["username"] for a in evidence.alerts) else entity),
                "rationale": "Suspend the modified account until the change is confirmed as authorised.",
                "risk_level": "high",
            }
        )
        recommendations.append(
            {
                "action_type": "collect_forensics",
                "target": incident.host or entity,
                "rationale": "Capture authentication and group-membership logs for the change window.",
                "risk_level": "low",
            }
        )

    elif category == "file_integrity":
        risky = [a for a in evidence.alerts if SYSTEM_PATHS.search(a["title"] + " " + (a.get("description") or ""))]
        add(
            f"{len(risky) or len(evidence.alerts)} file or configuration change(s) were detected on "
            f"{incident.host or entity}"
            + (", including paths in protected system locations." if risky else "."),
            [a["alert_id"] for a in risky] or ids,
        )
        hypotheses.append(
            "The change may be the result of a dropper or persistence mechanism; file hashes and the creating "
            "process are not present in this evidence."
        )
        recommendations.append(
            {
                "action_type": "isolate_host",
                "target": incident.host or entity,
                "rationale": "Contain the host while the modified files are validated against a known-good baseline.",
                "risk_level": "high",
            }
        )

    else:
        add(f"{len(evidence.alerts)} alert(s) were correlated for {entity} without a recognised behavioural pattern.", ids, "low")
        hypotheses.append("The activity does not match a known detection pattern and may be benign; analyst triage is required.")

    if SEVERITY_RANK.get(severity, 0) >= 3 and not any(h.lower().startswith("escalate") for h in hypotheses):
        if incident.alert_count >= 5:
            hypotheses.append("The volume and severity of correlated alerts warrant escalation to tier 2.")

    seen: set[tuple[str, str]] = set()
    unique_recommendations = []
    for rec in recommendations:
        key = (rec["action_type"], rec["target"])
        if key not in seen:
            seen.add(key)
            unique_recommendations.append(rec)
    return findings, hypotheses, unique_recommendations


def heuristic_summary(incident: Incident, evidence: Evidence, findings: list[dict], hypotheses: list[str]) -> str:
    confirmed = [f for f in findings if f["nature"] == "confirmed"]
    window_start = incident.first_seen.isoformat() if incident.first_seen else "unknown"
    window_end = incident.last_seen.isoformat() if incident.last_seen else "unknown"
    parts = [
        f"{incident.title}: {len(evidence.alerts)} correlated alerts between {window_start} and {window_end}.",
        "Confirmed observations: " + (confirmed[0]["statement"] if confirmed else "none established from the available telemetry."),
    ]
    if len(confirmed) > 1:
        parts.append(confirmed[1]["statement"])
    if hypotheses:
        parts.append("Open hypotheses: " + hypotheses[0])
    parts.append(
        f"Assessed severity {incident.severity} and priority P{incident.priority}. "
        "Recommended actions are proposals only and require human approval."
    )
    return " ".join(parts)



def investigate(incident: Incident, evidence: Evidence) -> dict:
    """Run the investigator and return fields for an Investigation record."""
    findings, hypotheses, recommendations = heuristic_findings(incident, evidence)
    summary = heuristic_summary(incident, evidence, findings, hypotheses)
    confidence = min(0.85, 0.55 + 0.05 * len([f for f in findings if f["nature"] == "confirmed"]))
    return {
        "agent": "investigator",
        "provider": "heuristic",
        "model": "rules-v1",
        "status": "completed",
        "summary": summary,
        "findings": findings[:12],
        "evidence": evidence.as_evidence_list(),
        "hypotheses": hypotheses[:8],
        "unsupported_claims": [],
        "missing_information": [],
        "recommendations": recommendations[:5],
        "priority": max(1, min(5, incident.priority)),
        "confidence": round(confidence, 2),
        "techniques": list(incident.techniques or [])[:8],
        "error": None,
    }
