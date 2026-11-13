"""Strict schemas for LLM replies.

These models are the contract between the model and the platform: anything that does
not validate is discarded and the deterministic investigation result is used instead.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Finding(_Strict):
    statement: str = Field(min_length=8, max_length=500)
    evidence_alert_ids: list[int] = Field(default_factory=list, max_length=10)
    confidence: Literal["high", "medium", "low"] = "medium"
    nature: Literal["confirmed", "hypothesis"] = "hypothesis"


class Recommendation(_Strict):
    action_type: Literal["block_ip", "isolate_host", "disable_account", "collect_forensics"]
    target: str = Field(min_length=1, max_length=160)
    rationale: str = Field(min_length=5, max_length=400)
    risk_level: Literal["low", "medium", "high"] = "medium"


class InvestigatorOutput(_Strict):
    summary: str = Field(min_length=15, max_length=2000)
    findings: list[Finding] = Field(default_factory=list, max_length=12)
    hypotheses: list[str] = Field(default_factory=list, max_length=8)
    recommendations: list[Recommendation] = Field(default_factory=list, max_length=5)
    priority: int = Field(ge=1, le=5)
    confidence: float = Field(ge=0.0, le=1.0)
    attack_techniques: list[str] = Field(default_factory=list, max_length=6)


class CriticOutput(_Strict):
    verdict: Literal["supported", "partially_supported", "unsupported"]
    assessment: str = Field(min_length=10, max_length=2000)
    unsupported_claims: list[str] = Field(default_factory=list, max_length=10)
    missing_information: list[str] = Field(default_factory=list, max_length=10)
    confidence: float = Field(ge=0.0, le=1.0)
