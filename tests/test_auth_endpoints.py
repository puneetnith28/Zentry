import uuid
import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import get_db
from app.db.models import Base, User
from app.main import app


@pytest.fixture
def auth_client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def test_register_user_success(auth_client):
    email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "email": email,
        "password": "StrongPassword123!",
    }
    response = auth_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == email
    assert "id" in data
    assert data["is_active"] is True
    assert data["is_superuser"] is False


def test_register_duplicate_email_fails(auth_client):
    email = f"dup_{uuid.uuid4().hex[:8]}@example.com"
    payload = {
        "email": email,
        "password": "StrongPassword123!",
    }
    res1 = auth_client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = auth_client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
    assert "already registered" in res2.json()["detail"]


def test_register_weak_password_fails(auth_client):
    payload = {
        "email": "weak@example.com",
        "password": "weak",
    }
    res = auth_client.post("/api/v1/auth/register", json=payload)
    assert res.status_code == 400
    assert "at least 8 characters" in res.json()["detail"]


def test_login_and_me_endpoints(auth_client):
    email = f"login_{uuid.uuid4().hex[:8]}@example.com"
    password = "CorrectPassword123!"

    # Register
    reg_res = auth_client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert reg_res.status_code == 201

    # Login with incorrect password
    bad_login = auth_client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPassword123!"})
    assert bad_login.status_code == 401

    # Login with correct password
    good_login = auth_client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert good_login.status_code == 200
    token_data = good_login.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    token = token_data["access_token"]

    # Access /me without token
    me_unauth = auth_client.get("/api/v1/auth/me")
    assert me_unauth.status_code == 401

    # Access /me with valid token
    me_auth = auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_auth.status_code == 200
    profile = me_auth.json()
    assert profile["email"] == email
