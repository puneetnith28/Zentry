from unittest.mock import patch
import uuid

import pytest

from app.core.config import get_settings
from app.core.rate_limit import SlidingWindowRateLimiter, limiter
from app.core.security import create_access_token, get_password_hash
from app.db.models import User


def create_test_user(db_session):
    user = User(
        email=f"rate_user_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_superuser=False,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return user, {"Authorization": f"Bearer {token}"}


def test_login_rate_limiting(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "auth_rate_limit_per_minute", 3)
    limiter.clear()

    # Send 3 attempts (allowed)
    for _ in range(3):
        res = client.post(
            "/api/v1/auth/login",
            json={"email": "wrong@example.com", "password": "WrongPassword123!"},
        )
        assert res.status_code == 401

    # 4th attempt exceeds limit -> 429
    res_burst = client.post(
        "/api/v1/auth/login",
        json={"email": "wrong@example.com", "password": "WrongPassword123!"},
    )
    assert res_burst.status_code == 429
    assert "rate limit exceeded" in res_burst.json()["detail"].lower()
    assert "retry-after" in res_burst.headers


def test_scan_rate_limiting(client, db_session, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "scan_rate_limit_per_minute", 3)
    limiter.clear()

    _, headers = create_test_user(db_session)
    with patch("app.api.v1.scans.scan_task.delay"):
        for _ in range(3):
            res = client.post(
                "/api/v1/scans/",
                headers=headers,
                json={"target": "https://example.com", "options": {}},
            )
            assert res.status_code == 202

        # 4th scan request exceeds limit -> 429
        res_burst = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={"target": "https://example.com", "options": {}},
        )
        assert res_burst.status_code == 429
        assert "rate limit exceeded" in res_burst.json()["detail"].lower()
        assert "retry-after" in res_burst.headers


def test_rate_limit_can_be_disabled(client, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    monkeypatch.setattr(settings, "auth_rate_limit_per_minute", 2)
    limiter.clear()

    for _ in range(5):
        res = client.post(
            "/api/v1/auth/login",
            json={"email": "wrong@example.com", "password": "WrongPassword123!"},
        )
        assert res.status_code == 401


def test_sliding_window_rate_limiter_unit():
    test_limiter = SlidingWindowRateLimiter()
    # 2 requests per 10 seconds
    test_limiter.check("test-key", max_requests=2, window_seconds=10.0)
    test_limiter.check("test-key", max_requests=2, window_seconds=10.0)

    with pytest.raises(Exception) as exc_info:
        test_limiter.check("test-key", max_requests=2, window_seconds=10.0)
    assert exc_info.value.status_code == 429
