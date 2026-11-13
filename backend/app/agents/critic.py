"""Security analysis (critic) agent.

Reviews the investigator's output independently:
  * every "confirmed" finding must cite alerts that really belong to the incident;
  * numeric claims are re-counted from the evidence;
  * missing investigative information is enumerated per behaviour;
  * the model's opinion can never override a failed deterministic check.
"""

from __future__ import annotations

from ..models import Incident
from .evidence import Evidence, counters
from .guardrails import (
    SECURITY_PREAMBLE,
    LLMOutputError,
    sanitize_untrusted,
    validate_model,
    wrap_untrusted,
)
from .llm import LLMClient, get_llm_client
from .output_schemas import CriticOutput

MISSING_INFO = {
    "brute_force": [
        "No authentication outcome is present: we cannot tell whether any attempt succeeded.",
        "No endpoint telemetry (Sysmon 4624/4625 correlation) to confirm which host was targeted.",
    ],
    "powershell": [
        "No parent process or user context for the PowerShell session.",
        "The encoded command has not been decoded, so the executed payload is unknown.",
        "No file hashes or reputation data for dropped artefacts.",
    ],
    "network": [
        "No DNS or proxy logs to attribute the destination domain.",
        "No NetFlow or packet capture to confirm payload size or protocol abuse.",
    ],
    "privilege_change": [
        "No change ticket or operator identity to confirm authorisation.",
        "No directory-service audit trail for who performed the change.",
    ],
    "file_integrity": [
        "No file hashes or known-good baseline for the modified files.",
        "No process telemetry showing which binary wrote the files.",
    ],
    "other": [
        "Detection rule context and endpoint telemetry are insufficient to confirm intent.",
    ],
}


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


def _verify_counts(incident: Incident, evidence: Evidence, findings: list[dict]) -> list[str]:
    """Re-derive counts that the investigator asserted, and flag mismatches."""
    issues: list[str] = []
    actual = counters(evidence)
    for finding in findings:
        statement = str(finding.get("statement", ""))
        if "authentication failures were recorded" in statement:
            claimed = statement.split(" ", 1)[0]
            try:
                claimed_n = int(claimed)
            except ValueError:
                continue
            if claimed_n != len(evidence.alerts):
                issues.append(
                    f"Failure count {claimed_n} does not match the {len(evidence.alerts)} alerts in this incident."
                )
        if "correlated alerts" in statement:
            claimed = statement.split(" ", 1)[0]
            try:
                claimed_n = int(claimed)
            except ValueError:
                continue
            if claimed_n != len(evidence.alerts):
                issues.append(f"Alert count {claimed_n} does not match the stored evidence.")
    if incident.category == "brute_force" and actual["by_category"].get("brute_force", 0) == 0:
        issues.append("Incident is classified as brute force but no brute-force alerts were found in evidence.")
    return issues


def review(
    incident: Incident,
    evidence: Evidence,
    investigation: dict,
    llm: LLMClient | None = None,
) -> dict:
    llm = llm or get_llm_client()
    findings = list(investigation.get("findings") or [])
    unsupported = _verify_findings(incident, evidence, findings) + _verify_counts(incident, evidence, findings)
    missing = MISSING_INFO.get(incident.category, MISSING_INFO["other"])[:]
    investigator_confidence = float(investigation.get("confidence") or 0.5)

    verdict = "supported"
    if unsupported:
        verdict = "partially_supported" if len(unsupported) < max(1, len(findings)) else "unsupported"
    if evidence.failures:
        missing.append("Some evidence queries were rejected by the tool layer: " + "; ".join(evidence.failures)[:300])

    assessment = (
        f"Independent review of incident {incident.id}. {len(findings)} finding(s) examined; "
        f"{len(unsupported)} could not be tied to incident evidence. "
        + ("The investigator's conclusions are consistent with the stored alerts."
           if not unsupported else "Unsupported claims must be corrected before escalation.")
    )
    confidence = round(min(0.9, investigator_confidence * (0.8 if unsupported else 0.95)), 2)
    provider, model = "heuristic", "rules-v1"

    result = llm.generate_json(
        SECURITY_PREAMBLE,
        "You are the independent reviewer. Check whether the investigator's conclusions are supported by the "
        "evidence, list unsupported claims and missing information, and give a verdict of supported, "
        "partially_supported or unsupported.\n\n"
        + wrap_untrusted(
            "investigator_report",
            f"Summary: {investigation.get('summary')}\n"
            + "Findings:\n"
            + "\n".join(f"- [{f.get('nature')}] {f.get('statement')}" for f in findings[:12]),
            limit=4000,
        )
        + "\n\n"
        + evidence.summary_for_prompt(),
    )
    if result.ok:
        try:
            parsed = validate_model(CriticOutput, result.text)
        except LLMOutputError as exc:
            missing.append(f"Critic model output rejected: {exc}")
        else:
            provider, model = result.provider, result.model
            for claim in parsed.unsupported_claims:
                cleaned = sanitize_untrusted(claim, 300)[0]
                if cleaned:
                    unsupported.append(cleaned)
            for item in parsed.missing_information:
                cleaned = sanitize_untrusted(item, 300)[0]
                if cleaned and cleaned not in missing:
                    missing.append(cleaned)
            cleaned_assessment = sanitize_untrusted(parsed.assessment, 2000)[0]
            if len(cleaned_assessment) >= 10:
                assessment = cleaned_assessment
            # A model may downgrade but never upgrade a verdict that failed deterministic checks.
            rank = {"unsupported": 0, "partially_supported": 1, "supported": 2}
            if unsupported:
                if rank[parsed.verdict] < rank[verdict]:
                    verdict = parsed.verdict
            else:
                verdict = parsed.verdict
            confidence = round(min(0.9, max(0.25, parsed.confidence * (0.75 if unsupported else 1.0))), 2)
    else:
        missing.append(f"Independent model review unavailable: {result.error}")

    return {
        "agent": "critic",
        "provider": provider,
        "model": model,
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
        "error": None if result.ok else result.error,
    }
