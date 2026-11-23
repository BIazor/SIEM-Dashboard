"""Event ingestion and normalization."""

from .normalize import NormalizedEvent, normalize_wazuh_alert

__all__ = ["NormalizedEvent", "normalize_wazuh_alert"]
