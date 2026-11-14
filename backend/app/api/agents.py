"""Agent introspection: analysis engine status and the read-only tool catalogue."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from ..agents.tooling import catalog
from ..models import User
from ..security import CurrentUser, require_roles

router = APIRouter(prefix="/api/agents", tags=["agents"])

ADMIN = require_roles("admin")


@router.get("/status")
def agent_status(user: CurrentUser) -> dict:
    return {
        "mode": "deterministic",
        "engine": "rules-v1",
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
