import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.security import create_access_token, decode_access_token
from app.main import app


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-xss-protection"] == "1; mode=block"
    assert response.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in response.headers["permissions-policy"]


def test_cors_allowed_origin(client):
    response = client.get(
        "/health",
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cors_disallowed_origin(client):
    response = client.get(
        "/health",
        headers={"Origin": "https://attacker.example.com"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") != "https://attacker.example.com"


def test_cors_preflight_options(client):
    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "POST" in response.headers.get("access-control-allow-methods", "")


def test_token_expiration_customizable(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "access_token_expire_minutes", 15)
    token = create_access_token({"sub": "test-user"})
    payload = decode_access_token(token)
    exp = payload["exp"]
    iat = payload["iat"]
    duration_minutes = (exp - iat) / 60
    assert round(duration_minutes) == 15
