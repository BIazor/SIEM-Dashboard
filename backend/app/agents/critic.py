"""Security analysis (critic) agent.

Reviews the investigator's output independently:
  * every "confirmed" finding must cite alerts that really belong to the incident;
  * numeric and structural claims are re-derived from the evidence;
  * missing investigative information is derived from what the telemetry lacks
    rather than copied from a fixed per-category list.
"""

from __future__ import annotations

import re

from ..models import Incident
from .evidence import Evidence, counters

_FAILURE_HINTS = ("fail", "invalid", "denied", "rejected")
_SUCCESS_HINTS = ("accepted", "success", "4624", "logged on", "granted", "approved")


def _text(alert: dict) -> str:
    return f"{alert.get('title') or ''} {alert.get('description') or ''}".lower()


def _missing_information(incident: Incident, evidence: Evidence) -> list[str]:
    """List the facts an analyst would need next, based on what is actually absent."""
    missing: list[str] = []
    totals = counters(evidence)
    alerts_text = " ".join(_text(alert) for alert in evidence.alerts)
    has_host = any(alert.get("host") for alert in evidence.alerts)
    has_user = bool(totals["by_user"])
    has_destination = any(alert.get("dst_ip") for alert in evidence.alerts)

    if incident.category == "brute_force":
        if not any(hint in alerts_text for hint in _SUCCESS_HINTS):
            missing.append(
                "No authentication outcome is present: we cannot tell whether any attempt succeeded."
            )
        if not has_host:
            missing.append("No host field is present, so the targeted endpoint cannot be confirmed.")
        if not has_user:
            missing.append("No targeted account was identified in the telemetry.")
        if not any(hint in alerts_text for hint in ("4624", "logon type", "process name")):
            missing.append("No endpoint telemetry correlates the failures with a logon session.")
    elif incident.category == "powershell":
        if "4104" not in alerts_text and "scriptblock" not in alerts_text.replace(" ", ""):
            missing.append(
                "No PowerShell script-block (4104) content is present, so the executed payload is unknown."
            )
        if not has_user:
            missing.append("No user context is attached to the PowerShell session.")
        if not evidence.host_activity:
            missing.append("No parent-process telemetry is available for the host.")
        if not any(alert.get("dst_ip") for alert in evidence.alerts):
            missing.append("No file hashes or destination data are present for dropped artifacts.")
    elif incident.category == "network":
        if not has_destination:
            missing.append("No destination address is present, so the remote endpoint is unknown.")
        if "dns" not in alerts_text and "proxy" not in alerts_text:
            missing.append("No DNS or proxy logs are available to attribute the destination domain.")
        if not has_host:
            missing.append("No host attribution, so the originating asset cannot be confirmed.")
    elif incident.category == "privilege_change":
        if not has_user:
            missing.append("No account is named in the change, so the operator is unknown.")
        if not evidence.host_activity:
            missing.append("No directory-service audit trail shows who performed the change.")
        missing.append("No change ticket or authorization record is available for this window.")
    elif incident.category == "file_integrity":
        missing.append("No file hashes or known-good baseline exist for the modified files.")
        missing.append("No process telemetry shows which binary wrote the files.")
        if not has_host:
            missing.append("No host is attached to the file events.")
    else:
        missing.append("Detection rule context and endpoint telemetry are insufficient to confirm intent.")

    if evidence.failures:
        missing.append(
            "Some evidence queries were rejected by the tool layer: " + "; ".join(evidence.failures)[:300]
        )
    return missing


def _verify_findings(incident: Incident, evidence: Evidence, findings: list[dict]) -> list[str]:
    valid_ids = set(evidence.alert_ids)
    unsupported: list[str] = []
    for finding in findings:
        if finding.get("nature") != "confirmed":
            continue
        cited = finding.get("evidence_alert_ids") or []
        if not cited:
            unsupported.append(f"Confirmed claim has no supporting alert: {str(finding.get('statement'))[:140]}")
            continue
        invalid = [i for i in cited if i not in valid_ids]
        if invalid:
            unsupported.append(
                f"Confirmed claim cites alerts {invalid} that are not in incident {incident.id}: "
                f"{str(finding.get('statement'))[:120]}"
            )
    return unsupported


def _leading_int(statement: str) -> int | None:
    match = re.match(r"\s*(\d+)\b", statement)
    return int(match.group(1)) if match else None


def _verify_counts(incident: Incident, evidence: Evidence, findings: list[dict]) -> list[str]:
    """Re-derive numbers and structural claims the investigator asserted."""
    issues: list[str] = []
    totals = counters(evidence)
    total_alerts = len(evidence.alerts)
    sources = sorted(totals["by_src_ip"])
    users = sorted(totals["by_user"])

    for finding in findings:
        statement = str(finding.get("statement", ""))
        claimed = _leading_int(statement)
        if claimed is None:
            continue
        if "authentication failures were recorded" in statement or "correlated alerts" in statement:
            if claimed != total_alerts:
                issues.append(
                    f"Claimed count {claimed} does not match the {total_alerts} alerts in this incident."
                )
            continue
        if "distinct accounts" in statement or "accounts were targeted" in statement:
            if claimed != len(users):
                issues.append(
                    f"Claimed {claimed} distinct accounts, but the evidence contains {len(users)}."
                )
            continue
        if "authentication failures" in statement and claimed > total_alerts:
            issues.append(f"Claimed {claimed} failures but the incident holds only {total_alerts} alerts.")

    if "one source address" in " ".join(str(f.get("statement", "")) for f in findings) and len(sources) != 1:
        issues.append(f"Report claims a single source address but the evidence shows {len(sources)}.")

    if incident.category == "brute_force" and not any(
        hint in _text(alert) for alert in evidence.alerts for hint in _FAILURE_HINTS
    ):
        issues.append("Incident is classified as brute force but no failure evidence was found.")
    return issues


def _verify_summary(incident: Incident, evidence: Evidence, investigation: dict) -> list[str]:
    """Check claims about severity, priority and technique coverage."""
    issues: list[str] = []
    summary = str(investigation.get("summary") or "")
    match = re.search(r"Assessed severity (critical|high|medium|low|info)", summary)
    if match and match.group(1) != incident.severity:
        issues.append(f"Summary states severity {match.group(1)} but the incident is {incident.severity}.")

    known_techniques = {alert.get("technique") for alert in evidence.alerts if alert.get("technique")}
    for technique in investigation.get("techniques") or []:
        if technique not in known_techniques:
            issues.append(f"Technique {technique} is attributed to the incident but no alert carries it.")

    confirmed = [f for f in investigation.get("findings") or [] if f.get("nature") == "confirmed"]
    cited = {i for finding in confirmed for i in finding.get("evidence_alert_ids") or []}
    if confirmed and not cited & set(evidence.alert_ids):
        issues.append("No confirmed finding cites an alert that belongs to this incident.")
    return issues


def review(incident: Incident, evidence: Evidence, investigation: dict) -> dict:
    """Independently re-check the investigator's report against the evidence."""
    findings = list(investigation.get("findings") or [])
    unsupported = (
        _verify_findings(incident, evidence, findings)
        + _verify_counts(incident, evidence, findings)
        + _verify_summary(incident, evidence, investigation)
    )
    missing = _missing_information(incident, evidence)
    investigator_confidence = float(investigation.get("confidence") or 0.5)

    verdict = "supported"
    if unsupported:
        verdict = "partially_supported" if len(unsupported) < max(1, len(findings)) else "unsupported"

    assessment = (
        f"Independent review of incident {incident.id}. {len(findings)} finding(s) examined; "
        f"{len(unsupported)} could not be tied to incident evidence. "
        + (
            "The investigator's conclusions are consistent with the stored alerts."
            if not unsupported
            else "Unsupported claims must be corrected before escalation."
        )
    )
    confidence = round(min(0.9, investigator_confidence * (0.8 if unsupported else 0.95)), 2)

    return {
        "agent": "critic",
        "provider": "heuristic",
        "model": "rules-v2",
        "status": "completed",
        "summary": assessment,
        "findings": [],
        "evidence": investigation.get("evidence"),
        "hypotheses": [],
        "unsupported_claims": unsupported[:10],
        "missing_information": missing[:10],
        "recommendations": [],
        "priority": None,
        "confidence": confidence,
        "verdict": verdict,
        "error": None,
    }
