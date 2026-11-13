"""Agent introspection: provider status and the read-only tool catalogue."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from ..agents.llm import get_llm_client
from ..agents.tooling import catalog
from ..config import get_settings
from ..models import User
from ..security import CurrentUser, require_roles

router = APIRouter(prefix="/api/agents", tags=["agents"])

ADMIN = require_roles("admin")


@router.get("/status")
def agent_status(user: CurrentUser) -> dict:
    client = get_llm_client()
    settings = get_settings()
    description = client.describe()
    return {
        "llm_available": description["available"],
        "provider": description["provider"],
        "model": settings.ollama_model if description["provider"] == "ollama" else settings.openai_model,
        "detail": description["detail"],
        "mode": "ai-assisted" if description["available"] else "deterministic-only",
    }


@router.get("/tools")
def agent_tools(    user: Annotated[User, Depends(ADMIN)]) -> dict:
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
