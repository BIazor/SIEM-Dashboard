"""Authentication and password-handling tests."""

from __future__ import annotations

from app.api import auth as auth_module
from app.security import hash_password, verify_password


def test_login_returns_token_and_user(client, users):
    response = client.post(
        "/api/auth/login", json={"email": "analyst@test.local", "password": "Analyst-Test-Pass-1"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "analyst"
    assert body["expires_in"] > 0
    assert body["access_token"].count(".") == 2  # JWT structure


def test_login_rejects_wrong_password(client, users):
    response = client.post(
        "/api/auth/login", json={"email": "analyst@test.local", "password": "wrong-password"}
    )
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]


def test_login_rejects_unknown_user(client, users):
    response = client.post(
        "/api/auth/login", json={"email": "ghost@test.local", "password": "Analyst-Test-Pass-1"}
    )
    assert response.status_code == 401


def test_login_rejects_invalid_email(client, users):
    response = client.post("/api/auth/login", json={"email": "not-an-email", "password": "whatever"})
    assert response.status_code == 422


def test_login_rate_limited(client, users, monkeypatch):
    monkeypatch.setattr(auth_module.settings, "login_rate_limit_per_minute", 3)
    statuses = [
        client.post(
            "/api/auth/login", json={"email": "viewer@test.local", "password": "Viewer-Test-Pass-1"}
        ).status_code
        for _ in range(4)
    ]
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3] == 429


def test_me_requires_authentication(client, users):
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_me_returns_current_user(client, auth):
    response = client.get("/api/auth/me", headers=auth["approver"])
    assert response.status_code == 200
    assert response.json()["role"] == "approver"


def test_password_hash_uses_scrypt_not_plaintext():
    stored = hash_password("Correct-Horse-Battery-1")
    assert stored.startswith("scrypt$")
    assert "Correct-Horse-Battery-1" not in stored
    assert verify_password("Correct-Horse-Battery-1", stored)
    assert not verify_password("wrong", stored)


def test_password_hashes_are_salted():
    assert hash_password("same-password-123") != hash_password("same-password-123")
