"""Deterministic classification rules, loaded from data files.

Rules live in ``rules.json`` so the catalog can be inspected, versioned and
extended without touching Python.  Every alert records the rule that matched, so
detection decisions are reproducible and can be counted for tuning.

Keeping this logic rule-based means severity/category decisions are reproducible
and testable, and the analysis layer can only *interpret* verified classifications.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import CATEGORIES, SEVERITIES

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

RULES_PATH = Path(__file__).with_name("rules.json")
SUPPRESSIONS_PATH = Path(__file__).with_name("suppressions.json")

UNMATCHED_KEY = "unmatched"


class RuleConfigError(RuntimeError):
    """The rule or suppression file is malformed; fail fast at startup."""


@dataclass(frozen=True)
class DetectionRule:
    key: str
    category: str
    title: str
    technique: str | None
    severity_floor: str | None
    order: int
    patterns: tuple[re.Pattern[str], ...]
    references: tuple[str, ...]


@dataclass(frozen=True)
class RuleMatch:
    key: str
    category: str
    title: str
    technique: str | None
    severity_floor: str | None
    references: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "category": self.category,
            "title": self.title,
            "technique": self.technique,
            "references": list(self.references),
        }


def load_rules(path: Path = RULES_PATH) -> tuple[str, tuple[DetectionRule, ...]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - packaging error
        raise RuleConfigError(f"Cannot read detection rules from {path.name}: {exc}") from exc

    version = str(payload.get("version") or "")
    if not version:
        raise RuleConfigError("Detection rules require a version")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleConfigError("Detection rules require a non-empty 'rules' array")

    rules: list[DetectionRule] = []
    seen: set[str] = set()
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise RuleConfigError("Each detection rule must be an object")
        key = str(raw.get("key") or "").strip()
        category = str(raw.get("category") or "").strip()
        patterns = raw.get("patterns")
        if not key or key in seen:
            raise RuleConfigError(f"Rule key missing or duplicated: {key!r}")
        if category not in CATEGORIES:
            raise RuleConfigError(f"Rule {key} has unknown category {category!r}")
        if not isinstance(patterns, list) or not all(isinstance(p, str) and p for p in patterns):
            raise RuleConfigError(f"Rule {key} requires at least one non-empty pattern")
        floor = raw.get("severity_floor")
        if floor is not None and floor not in SEVERITIES:
            raise RuleConfigError(f"Rule {key} has unknown severity floor {floor!r}")
        technique = raw.get("technique")
        if technique is not None and not isinstance(technique, str):
            raise RuleConfigError(f"Rule {key} technique must be a string or null")
        references = raw.get("references") or []
        if not isinstance(references, list) or not all(isinstance(r, str) for r in references):
            raise RuleConfigError(f"Rule {key} references must be a list of strings")
        try:
            compiled = tuple(re.compile(pattern) for pattern in patterns)
        except re.error as exc:
            raise RuleConfigError(f"Rule {key} has an invalid pattern: {exc}") from exc
        seen.add(key)
        rules.append(
            DetectionRule(
                key=key,
                category=category,
                title=str(raw.get("title") or key),
                technique=technique,
                severity_floor=floor,
                order=int(raw.get("order", 0)),
                patterns=compiled,
                references=tuple(references),
            )
        )
    rules.sort(key=lambda rule: rule.order)
    return version, tuple(rules)


@dataclass(frozen=True)
class Suppression:
    reason: str
    hosts: frozenset[str]
    src_ips: frozenset[str]
    categories: frozenset[str]


def _load_suppressions(path: Path = SUPPRESSIONS_PATH) -> tuple[dict[str, Any], tuple[Suppression, ...]]:
    if not path.exists():  # pragma: no cover - optional file
        return {"version": "0"}, ()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:  # pragma: no cover - packaging error
        raise RuleConfigError(f"Cannot read suppressions: {exc}") from exc
    entries = payload.get("entries") or []
    if not isinstance(entries, list):
        raise RuleConfigError("Suppressions 'entries' must be an array")
    suppressions: list[Suppression] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuleConfigError("Each suppression must be an object")
        reason = str(entry.get("reason") or "suppressed").strip()[:160]
        hosts = frozenset(str(h).lower() for h in entry.get("hosts") or [])
        ips = frozenset(str(i) for i in entry.get("src_ips") or [])
        categories = frozenset(str(c) for c in entry.get("categories") or [])
        if categories - set(CATEGORIES):
            raise RuleConfigError(f"Suppression '{reason}' names an unknown category")
        if not (hosts or ips or categories):
            raise RuleConfigError(f"Suppression '{reason}' needs at least one selector")
        suppressions.append(Suppression(reason=reason, hosts=hosts, src_ips=ips, categories=categories))
    return payload, tuple(suppressions)


RULES_VERSION, RULES = load_rules()
SUPPRESSIONS_VERSION, SUPPRESSIONS = _load_suppressions()

_REFERENCES_BY_CATEGORY = {rule.category: rule.references for rule in RULES}
_TECHNIQUE_BY_CATEGORY = {rule.category: rule.technique for rule in RULES}
_FLOOR_BY_CATEGORY = {rule.category: rule.severity_floor for rule in RULES}

_CATEGORY_TITLES = {
    "brute_force": "Repeated authentication failures",
    "powershell": "Suspicious PowerShell execution",
    "network": "Anomalous network activity",
    "privilege_change": "Account privilege change",
    "file_integrity": "Suspicious file or configuration change",
    "other": "Security event",
}


def rules_version() -> str:
    return RULES_VERSION


def rule_catalog() -> list[dict[str, Any]]:
    """The rule set in machine-readable form (API and tests)."""
    return [
        {
            "key": rule.key,
            "category": rule.category,
            "title": rule.title,
            "technique": rule.technique,
            "severity_floor": rule.severity_floor,
            "pattern_count": len(rule.patterns),
            "references": list(rule.references),
        }
        for rule in RULES
    ]


def classify(*, title: str, description: str, rule_id: str, groups: list[str] | None = None) -> RuleMatch | None:
    """Return the first matching rule, or None when nothing matches.

    Order is meaningful: PowerShell and privilege evidence win over generic network
    text, exactly as declared by the ``order`` field in the data file.
    """
    haystack = " ".join([title or "", description or "", rule_id or "", " ".join(groups or [])])
    for rule in RULES:
        if any(pattern.search(haystack) for pattern in rule.patterns):
            return RuleMatch(
                key=rule.key,
                category=rule.category,
                title=rule.title,
                technique=rule.technique,
                severity_floor=rule.severity_floor,
                references=rule.references,
            )
    return None


def classify_category(*, title: str, description: str, rule_id: str, groups: list[str] | None = None) -> str:
    match = classify(title=title, description=description, rule_id=rule_id, groups=groups)
    return match.category if match else "other"


def severity_for_level(rule_level: int, floor: str | None = None) -> str:
    """Map a Wazuh rule level to severity, respecting the rule's declared floor."""
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
    if floor and SEVERITY_RANK[floor] > SEVERITY_RANK[severity]:
        severity = floor
    return severity


def severity_from_rule_level(rule_level: int, category: str) -> str:
    """Backwards-compatible helper: severity for a category's declared floor."""
    return severity_for_level(rule_level, _FLOOR_BY_CATEGORY.get(category))


def technique_for_category(category: str) -> str | None:
    """ATT&CK technique for a category, or None when the category is unmapped."""
    return _TECHNIQUE_BY_CATEGORY.get(category)


def category_references(category: str) -> tuple[str, ...]:
    return _REFERENCES_BY_CATEGORY.get(category, ())


def category_title(category: str) -> str:
    return _CATEGORY_TITLES.get(category, _CATEGORY_TITLES["other"])


def higher_severity(a: str, b: str) -> str:
    return a if SEVERITY_RANK.get(a, 0) >= SEVERITY_RANK.get(b, 0) else b


def alert_priority(severity: str) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}.get(severity, 5)


def is_suppressed(*, host: str | None, src_ip: str | None, category: str) -> str | None:
    """Return the suppression reason when every filled-in selector matches."""
    host_key = (host or "").strip().lower()
    for suppression in SUPPRESSIONS:
        if suppression.hosts and host_key not in suppression.hosts:
            continue
        if suppression.src_ips and (src_ip or "") not in suppression.src_ips:
            continue
        if suppression.categories and category not in suppression.categories:
            continue
        return suppression.reason
    return None
