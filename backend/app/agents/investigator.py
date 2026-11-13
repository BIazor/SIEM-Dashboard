"""Investigator agent: builds the primary investigation.

Two layers:
  * a deterministic engine that derives confirmed facts from validated evidence;
  * an optional LLM narrative that can add hypotheses, which are always validated,
    scope-checked and clearly separated from confirmed facts.

The deterministic layer is authoritative: if the model is unavailable or returns
anything that does not validate, the investigation still completes.
"""

from __future__ import annotations

import re

from ..models import Incident
from .evidence import Evidence, beacon_intervals
from .guardrails import SECURITY_PREAMBLE, LLMOutputError, sanitize_untrusted, validate_model
from .llm import LLMClient, get_llm_client
from .output_schemas import InvestigatorOutput

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
        targets = sorted({a["username"] for a in failures if a["username"]})
        add(
            f"{len(failures)} authentication failures were recorded against "
            f"{', '.join(targets) if targets else entity} from {', '.join(sources) if sources else 'an internal source'}.",
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


def _prompt(incident: Incident, evidence: Evidence, findings: list[dict], hypotheses: list[str]) -> str:
    return (
        "Investigate the security incident below and return JSON with fields: summary, findings "
        "(statement, evidence_alert_ids, confidence, nature), hypotheses, recommendations "
        "(action_type one of block_ip|isolate_host|disable_account|collect_forensics, target, rationale, "
        "risk_level), priority (1 highest - 5 lowest), confidence (0-1), attack_techniques.\n"
        "Mark nature='confirmed' only for facts directly visible in the evidence.\n\n"
        f"Deterministic findings already established:\n- "
        + "\n- ".join(f["statement"] for f in findings)
        + "\n\nOpen hypotheses:\n- "
        + ("\n- ".join(hypotheses) if hypotheses else "none")
        + "\n\n"
        + evidence.summary_for_prompt()
    )


def investigate(
    incident: Incident,
    evidence: Evidence,
    llm: LLMClient | None = None,
) -> dict:
    """Run the investigator and return fields for an Investigation record."""
    llm = llm or get_llm_client()
    findings, hypotheses, recommendations = heuristic_findings(incident, evidence)
    summary = heuristic_summary(incident, evidence, findings, hypotheses)
    provider, model = "heuristic", "rules-v1"
    error: str | None = None
    confidence = min(0.85, 0.55 + 0.05 * len([f for f in findings if f["nature"] == "confirmed"]))
    priority = incident.priority
    unsupported: list[str] = []
    techniques = list(incident.techniques or [])

    result = llm.generate_json(SECURITY_PREAMBLE, _prompt(incident, evidence, findings, hypotheses))
    if result.ok:
        try:
            parsed = validate_model(InvestigatorOutput, result.text)
        except LLMOutputError as exc:
            error = f"LLM output rejected, deterministic findings kept: {exc}"
        else:
            provider, model = result.provider, result.model
            valid_ids = set(evidence.alert_ids)
            for claim in parsed.findings:
                bad = [i for i in claim.evidence_alert_ids if i not in valid_ids]
                if bad:
                    unsupported.append(
                        f"Model cited alert IDs {bad} that are not part of this incident (claim dropped)."
                    )
                    continue
                if claim.nature == "confirmed" and not claim.evidence_alert_ids:
                    unsupported.append(f"Unsupported confirmed claim without evidence: {claim.statement[:120]}")
                    continue
                findings.append(
                    {
                        "statement": sanitize_untrusted(claim.statement, 500)[0],
                        "evidence_alert_ids": claim.evidence_alert_ids[:10],
                        "confidence": claim.confidence,
                        "nature": claim.nature,
                        "source": "llm",
                    }
                )
            for hyp in parsed.hypotheses:
                cleaned = sanitize_untrusted(hyp, 400)[0]
                if cleaned:
                    hypotheses.append(cleaned)
            if parsed.recommendations:
                recommendations = [
                    {
                        "action_type": rec.action_type,
                        "target": sanitize_untrusted(rec.target, 160)[0],
                        "rationale": sanitize_untrusted(rec.rationale, 400)[0],
                        "risk_level": rec.risk_level,
                    }
                    for rec in parsed.recommendations
                ]
            cleaned_summary = sanitize_untrusted(parsed.summary, 2000)[0]
            if len(cleaned_summary) >= 15:
                summary = cleaned_summary
            # The model may raise priority but never below what severity justifies.
            priority = min(parsed.priority, incident.priority)
            confidence = min(0.85, max(0.3, parsed.confidence))
            for technique in parsed.attack_techniques:
                cleaned = sanitize_untrusted(technique, 60)[0]
                if cleaned and cleaned not in techniques:
                    techniques.append(cleaned)
    else:
        error = result.error

    return {
        "agent": "investigator",
        "provider": provider,
        "model": model,
        "status": "completed",
        "summary": summary,
        "findings": findings[:12],
        "evidence": evidence.as_evidence_list(),
        "hypotheses": hypotheses[:8],
        "unsupported_claims": unsupported[:10],
        "missing_information": [],
        "recommendations": recommendations[:5],
        "priority": max(1, min(5, priority)),
        "confidence": round(confidence, 2),
        "techniques": techniques[:8],
        "error": error,
        "llm_available": result.ok,
    }
