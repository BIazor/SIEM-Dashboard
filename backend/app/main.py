"""FastAPI application entry point."""

from __future__ import annotations

import json
import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
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
from .config import BACKEND_ROOT, get_settings
from .context import current_request_id, request_id_var
from .db import engine, init_db
from .migrations import schema_version
from .schemas import HealthResponse, ReadyResponse

logger = logging.getLogger("soc")

FRONTEND_DIST = BACKEND_ROOT.parent / "frontend" / "dist"

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


class JsonFormatter(logging.Formatter):
    """One JSON object per line, carrying the request id when there is one."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": current_request_id(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(log_level: str, json_logs: bool) -> None:
    root = logging.getLogger()
    level = getattr(logging, str(log_level).upper(), logging.INFO)
    root.setLevel(level)
    if not any(getattr(handler, "_aegis_handler", False) for handler in root.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(
            JsonFormatter() if json_logs else logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
        )
        handler._aegis_handler = True  # type: ignore[attr-defined]
        root.addHandler(handler)


class RequestIdMiddleware:
    """Give every request an id that appears in logs, audit rows and the response."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        supplied = dict(scope["headers"]).get(b"x-request-id", b"").decode("latin-1")
        request_id = (supplied.strip()[:64] or uuid.uuid4().hex)
        token = request_id_var.set(request_id)

        async def send_with_header(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_header)
        finally:
            request_id_var.reset(token)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        settings = get_settings()
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("Content-Security-Policy", CSP)
        if settings.environment == "production":
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.url.path.startswith("/api"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


class SPAStaticFiles(StaticFiles):
    """Serve the built React app, falling back to index.html for client-side routes."""

    async def get_response(self, path: str, scope):
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code == 404 and self._can_fallback(scope):
                return await super().get_response("index.html", scope)
            raise
        if response.status_code == 404 and self._can_fallback(scope):
            return await super().get_response("index.html", scope)
        return response

    @staticmethod
    def _can_fallback(scope) -> bool:
        return scope.get("method") in {"GET", "HEAD"} and not scope.get("path", "").startswith("/api")


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        for warning in settings.validate_for_runtime():
            logger.warning(warning)
        init_db()
        logger.info("Schema ready (version %s)", schema_version(engine))
        from .seed import ensure_demo_users

        seeded = ensure_demo_users()
        if seeded:
            logger.info("Seeded demo accounts: %s", ", ".join(seeded))
        yield

    production = settings.environment == "production"
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Security Operations Center platform (read-only agents, human-approved actions).",
        lifespan=lifespan,
        docs_url=None if production else "/api/docs",
        openapi_url=None if production else "/api/openapi.json",
    )
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Ingest-Token", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )

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
        """Liveness: the process is up. Use /api/health/ready for dependencies."""
        return HealthResponse(status="ok", version=__version__)

    @app.get("/api/health/ready", response_model=ReadyResponse, tags=["system"])
    def ready() -> ReadyResponse:
        """Readiness: the database answers and the schema is current."""
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            version = schema_version(engine)
        except Exception as exc:  # noqa: BLE001 - readiness must not leak internals
            logger.error("Readiness check failed: %s", type(exc).__name__)
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Database unavailable") from exc
        return ReadyResponse(status="ok", version=__version__, database="ok", schema_version=version)

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error", "request_id": current_request_id()},
        )

    if FRONTEND_DIST.is_dir():
        app.mount("/", SPAStaticFiles(directory=str(FRONTEND_DIST), html=True), name="spa")

    return app


app = create_app()
