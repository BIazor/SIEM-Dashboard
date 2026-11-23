"""Detection helpers: severity mapping, category classification, MITRE hints."""

from .rules import (
    SEVERITY_RANK,
    alert_priority,
    classify_category,
    higher_severity,
    severity_from_rule_level,
    technique_for_category,
)

__all__ = [
    "SEVERITY_RANK",
    "alert_priority",
    "classify_category",
    "higher_severity",
    "severity_from_rule_level",
    "technique_for_category",
]
