"""Agent introspection: analysis engine status and the read-only tool catalog."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from ..agents.investigator import ENGINE_VERSION
from ..agents.tooling import catalog
from ..detection.rules import SUPPRESSIONS, rule_catalog, rules_version
from ..models import User
from ..security import CurrentUser, require_roles

router = APIRouter(prefix="/api/agents", tags=["agents"])

ADMIN = require_roles("admin")


@router.get("/status")
def agent_status(user: CurrentUser) -> dict:
    return {
        "mode": "deterministic",
        "engine": ENGINE_VERSION,
        "rules_version": rules_version(),
        "rules": len(rule_catalog()),
        "suppression_entries": len(SUPPRESSIONS),
        "detail": "Rule-based analysis: every finding cites the alerts that support it.",
    }


@router.get("/tools")
def agent_tools(user: Annotated[User, Depends(ADMIN)]) -> dict:
    tools = catalog()
    return {
        "count": len(tools),
        "read_only": True,
        "tools": tools,
        "denied_capabilities": [
            "shell execution",
            "arbitrary network requests",
            "database writes",
            "action approval",
            "credential access",
        ],
    }
