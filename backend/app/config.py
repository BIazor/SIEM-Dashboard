"""Application configuration loaded from environment variables / .env."""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent

DEV_SECRET_PLACEHOLDER = "dev-only-insecure-secret-change-me"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", str(BACKEND_ROOT / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "Aegis SOC Analyst Platform"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "info"

    database_url: str = "sqlite:///./data/soc.db"

    # Authentication
    secret_key: str = ""
    access_token_ttl_minutes: int = 60
    jwt_algorithm: str = "HS256"
    login_rate_limit_per_minute: int = 5
    min_password_length: int = 12

    # Event ingestion (Wazuh manager / shipper -> platform webhook)
    ingest_token: str = ""
    ingest_allowed_ips: str = ""  # comma separated; empty = any (documented)

    # Only enable when a reverse proxy you control overwrites X-Forwarded-For.
    # Leaving this on lets any client spoof its source address (rate limits, audit, allow-list).
    trust_proxy_headers: bool = False

    # CORS
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Demo seeding (never enable in production)
    seed_demo_users: bool = False
    seed_admin_email: str = "admin@soc.local"
    seed_admin_password: str = ""
    seed_analyst_email: str = "analyst@soc.local"
    seed_analyst_password: str = ""
    seed_viewer_email: str = "viewer@soc.local"
    seed_viewer_password: str = ""
    seed_approver_email: str = "approver@soc.local"
    seed_approver_password: str = ""

    @field_validator("cors_origins")
    @classmethod
    def _strip_origins(cls, value: str) -> str:
        return value.strip()

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def data_dir(self) -> Path:
        url = self.database_url
        if url.startswith("sqlite:///"):
            raw = url.removeprefix("sqlite:///")
            path = Path(raw)
            if not path.is_absolute():
                path = (BACKEND_ROOT / path).resolve()
            return path.parent
        return BACKEND_ROOT / "data"

    def resolved_secret_key(self) -> str:
        """Return the JWT signing key.

        In development/test an ephemeral key is generated when none is configured so
        the app never ships a hard-coded secret.  Production requires a real value.
        """
        if self.secret_key:
            return self.secret_key
        if self.environment == "production":
            raise RuntimeError("SECRET_KEY must be set when ENVIRONMENT=production")
        return secrets.token_urlsafe(48)

    def validate_for_runtime(self) -> list[str]:
        """Return a list of configuration warnings for non-development use."""
        warnings: list[str] = []
        if self.environment != "production":
            return warnings
        if not self.secret_key or self.secret_key == DEV_SECRET_PLACEHOLDER:
            raise RuntimeError("SECRET_KEY must be a strong, unique value in production")
        if len(self.secret_key) < 32:
            raise RuntimeError("SECRET_KEY must be at least 32 characters in production")
        if not self.ingest_token:
            raise RuntimeError("INGEST_TOKEN must be set so the Wazuh webhook is authenticated")
        if self.seed_demo_users:
            raise RuntimeError("SEED_DEMO_USERS must be disabled in production")
        if "*" in self.cors_origin_list:
            raise RuntimeError("Wildcard CORS origins are not allowed in production")
        return warnings

@lru_cache
def get_settings() -> Settings:
    return Settings()
