"""FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__
from .api import agents as agents_api
from .api import alerts as alerts_api
from .api import approvals as approvals_api
from .api import audit as audit_api
from .api import auth as auth_api
from .api import incidents as incidents_api
from .api import ingest as ingest_api
from .api import stats as stats_api
from .config import get_settings
from .db import init_db
from .schemas import HealthResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("soc")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        if request.url.path.startswith("/api"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        settings.validate_for_runtime()
        init_db()
        from .seed import ensure_demo_users

        seeded = ensure_demo_users()
        if seeded:
            logger.info("Seeded demo accounts: %s", ", ".join(seeded))
        yield

    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Security Operations Center platform (read-only agents, human-approved actions).",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Ingest-Token"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    for router in (
        auth_api.router,
        ingest_api.router,
        alerts_api.router,
        incidents_api.router,
        approvals_api.router,
        stats_api.router,
        audit_api.router,
        agents_api.router,
    ):
        app.include_router(router)

    @app.get("/api/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse(status="ok", version=__version__)

    return app


app = create_app()
