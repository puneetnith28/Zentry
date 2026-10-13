import json
import uuid

import pytest

from app.core.config import get_settings
from app.core.security import create_access_token, get_password_hash
from app.db.models import User


def create_test_user(db_session):
    user = User(
        email=f"user_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return user, {"Authorization": f"Bearer {token}"}


def test_request_within_size_limit_accepted(client, db_session):
    _, headers = create_test_user(db_session)
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "test@example.com", "password": "SmallPayload123!"},
    )
    # Reached handler (either 401 invalid creds or 200, but not 413)
    assert response.status_code in (200, 401)


def test_oversized_request_body_rejected_with_413(client, db_session):
    _, headers = create_test_user(db_session)
    settings = get_settings()

    # Generate oversized payload > 64 KB
    large_padding = "x" * (settings.max_request_body_bytes + 1024)
    payload = json.dumps({"target": "https://example.com", "padding": large_padding})

    headers.update({"Content-Type": "application/json"})
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        content=payload,
    )
    assert response.status_code == 413
    assert "payload exceeds maximum allowed size" in response.json()["detail"].lower()


def test_oversized_unauthenticated_request_rejected_with_413(client):
    settings = get_settings()
    large_padding = "a" * (settings.max_request_body_bytes + 500)
    payload = json.dumps({"email": "huge@example.com", "password": large_padding})

    response = client.post(
        "/api/v1/auth/register",
        headers={"Content-Type": "application/json"},
        content=payload,
    )
    assert response.status_code == 413
