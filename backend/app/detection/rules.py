"""Deterministic classification rules used before any AI reasoning happens.

Keeping this logic rule-based means severity/category decisions are reproducible
and testable, and the AI layer can only *interpret* verified classifications.
"""

from __future__ import annotations

import re

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "powershell",
        re.compile(
            r"(?i)(powershell|pwsh|encodedcommand|\s-enc\s|\s-e\s|downloadstring|invoke-expression|"
            r"iex\s*\(|script\s*block|4104|amsi)"
        ),
    ),
    (
        "privilege_change",
        re.compile(
            r"(?i)(user added to|added to (the )?(local )?administrators?|group (added|changed|modified)|"
            r"\b4720\b|\b4728\b|\b4732\b|\b4756\b|new user (account )?created|privilege (escalation|change)|"
            r"sudoers|granted sudo|role assignment|account (enabled|created))"
        ),
    ),
    (
        "file_integrity",
        re.compile(
            r"(?i)(file (added|modified|deleted|integrity)|syscheck|integrity (checking|sum)|"
            r"\b550\b|\b554\b|startup folder|autorun|scheduled task created|registry (key )?(modified|added))"
        ),
    ),
    (
        "brute_force",
        re.compile(
            r"(?i)(failed (password|logon|login|authentication)|authentication failure|logon failure|"
            r"invalid user|brute ?force|\b4625\b|\b5710\b|too many authentication failures|"
            r"repeated (login|authentication) failures)"
        ),
    ),
    (
        "network",
        re.compile(
            r"(?i)(network connection|outbound connection|suspicious (connection|traffic|dns)|c2|command and control|"
            r"beacon|port scan|firewall (drop|deny|block)|dns (query|tunnel)|unusual port|\b5156\b|\b5157\b|"
            r"netstat|reverse shell|tcp connection)"
        ),
    ),
]

_TECHNIQUE = {
    "brute_force": "T1110 - Brute Force",
    "powershell": "T1059.001 - PowerShell",
    "network": "T1071 - Application Layer Protocol",
    "privilege_change": "T1098 - Account Manipulation",
    "file_integrity": "T1565.001 - Stored Data Manipulation",
    "other": "T1000 - Unmapped",
}

_CATEGORY_TITLES = {
    "brute_force": "Repeated authentication failures",
    "powershell": "Suspicious PowerShell execution",
    "network": "Anomalous network activity",
    "privilege_change": "Account privilege change",
    "file_integrity": "Suspicious file or configuration change",
    "other": "Security event",
}


def classify_category(*, title: str, description: str, rule_id: str, groups: list[str] | None = None) -> str:
    haystack = " ".join([title or "", description or "", rule_id or "", " ".join(groups or [])])
    # Order matters: PowerShell/privilege evidence wins over generic network text.
    for category, pattern in _PATTERNS:
        if pattern.search(haystack):
            return category
    return "other"


def severity_from_rule_level(rule_level: int, category: str) -> str:
    """Map Wazuh rule level to severity, escalating destructive categories."""
    try:
        level = int(rule_level)
    except (TypeError, ValueError):
        level = 0
    if level >= 12:
        severity = "critical"
    elif level >= 10:
        severity = "high"
    elif level >= 7:
        severity = "medium"
    elif level >= 4:
        severity = "low"
    else:
        severity = "info"
    # A low-level rule that clearly matches a high-risk technique is never "info".
    if category in {"powershell", "privilege_change"} and severity in {"info", "low"}:
        severity = "medium"
    if category == "brute_force" and severity == "info":
        severity = "low"
    return severity


def technique_for_category(category: str) -> str:
    return _TECHNIQUE.get(category, _TECHNIQUE["other"])


def category_title(category: str) -> str:
    return _CATEGORY_TITLES.get(category, _CATEGORY_TITLES["other"])


def higher_severity(a: str, b: str) -> str:
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b


def alert_priority(severity: str) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(severity, 5)
