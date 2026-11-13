"""Shared pytest fixtures.

Environment variables are set before the application is imported so the app uses a
throwaway SQLite file and the deterministic (offline) agent path.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="soc-tests-"))
_DB = (_TMP / "test.db").as_posix()

os.environ.update(
    {
        "ENVIRONMENT": "test",
        "DATABASE_URL": f"sqlite:///{_DB}",
        "SECRET_KEY": "test-secret-key-0123456789abcdefghijklmnop",
        "INGEST_TOKEN": "test-ingest-token",
        "SEED_DEMO_USERS": "false",
        "LLM_PROVIDER": "none",
        "CORS_ORIGINS": "http://localhost:5173",
        "LOGIN_RATE_LIMIT_PER_MINUTE": "50",
        "OPENAI_API_KEY": "",
    }
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402
from app.security import hash_password, login_limiter  # noqa: E402

PASSWORDS = {
    "admin": "Admin-Test-Pass-1",
    "approver": "Approver-Test-Pass-1",
    "analyst": "Analyst-Test-Pass-1",
    "viewer": "Viewer-Test-Pass-1",
}
EMAILS = {role: f"{role}@test.local" for role in PASSWORDS}
INGEST_HEADERS = {"X-Ingest-Token": "test-ingest-token"}

# The app also creates tables in its lifespan; doing it here keeps teardown valid
# regardless of test ordering (the first test may never enter the client fixture).
Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _clean_state():
    login_limiter.reset()
    yield
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    login_limiter.reset()


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def users(db):
    for role, password in PASSWORDS.items():
        db.add(
            User(
                email=EMAILS[role],
                full_name=f"Test {role.title()}",
                role=role,
                password_hash=hash_password(password),
            )
        )
    db.commit()
    return EMAILS


@pytest.fixture
def tokens(client, users):
    result = {}
    for role, password in PASSWORDS.items():
        response = client.post("/api/auth/login", json={"email": EMAILS[role], "password": password})
        assert response.status_code == 200, response.text
        result[role] = response.json()["access_token"]
    return result


@pytest.fixture
def auth(tokens):
    return {role: {"Authorization": f"Bearer {token}"} for role, token in tokens.items()}


@pytest.fixture
def ingest(client):
    def _ingest(alerts, headers=None):
        response = client.post("/api/ingest/wazuh", json={"alerts": alerts}, headers=headers or INGEST_HEADERS)
        assert response.status_code == 200, response.text
        return response.json()

    return _ingest


@pytest.fixture
def investigated(client, auth, ingest):
    """Ingest the brute-force scenario, run the agents, return the incident detail."""

    def _run(alerts):
        body = ingest(alerts)
        incident_id = body["incidents"][0]
        response = client.post(f"/api/incidents/{incident_id}/investigate", headers=auth["analyst"])
        assert response.status_code == 200, response.text
        return response.json()

    return _run
