import json
import uuid
from unittest.mock import patch
import pytest

from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.core.security import create_access_token, get_password_hash
from app.db.models import ScanJob, ScanStatusEnum, User

settings = get_settings()


def create_user_and_headers(db_session, email_prefix: str = "abuse_test", is_superuser: bool = False):
    user = User(
        email=f"{email_prefix}_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
        is_superuser=is_superuser,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return user, {"Authorization": f"Bearer {token}"}


# -----------------------------------------------------------------------------
# 1. Target URL Abuse & Canonicalization
# -----------------------------------------------------------------------------
def test_target_with_credentials_rejected(client, db_session):
    _, headers = create_user_and_headers(db_session)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://admin:secret123@example.com"},
    )
    assert response.status_code == 400
    assert "userinfo" in response.text or "credentials" in response.text


def test_target_with_unsupported_scheme_rejected(client, db_session):
    _, headers = create_user_and_headers(db_session)
    for scheme in ["ftp://example.com", "file:///etc/passwd", "gopher://example.com"]:
        response = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={"target": scheme},
        )
        assert response.status_code == 400


def test_target_empty_or_whitespace_rejected(client, db_session):
    _, headers = create_user_and_headers(db_session)
    for target in ["", "   "]:
        response = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={"target": target},
        )
        assert response.status_code in [400, 422]


# -----------------------------------------------------------------------------
# 2. Port Bounds and Abuse Prevention
# -----------------------------------------------------------------------------
def test_ports_out_of_range_rejected(client, db_session):
    _, headers = create_user_and_headers(db_session)
    for bad_port in [0, -1, 65536, 70000]:
        response = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={"target": "https://example.com", "options": {"port_scan": True, "port_list": [80, bad_port]}},
        )
        assert response.status_code == 422


def test_ports_exceeding_max_count_rejected(client, db_session):
    _, headers = create_user_and_headers(db_session)
    too_many_ports = list(range(1, 55))  # 54 ports > max 50
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com", "options": {"port_scan": True, "port_list": too_many_ports}},
    )
    assert response.status_code == 422


@patch("app.api.v1.scans.scan_task.delay")
def test_ports_deduplicated_cleanly(mock_delay, client, db_session):
    _, headers = create_user_and_headers(db_session)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com", "options": {"port_scan": True, "port_list": [443, 80, 443, 80, 8080]}},
    )
    assert response.status_code == 202


# -----------------------------------------------------------------------------
# 3. Scanner Options Boundary Abuse
# -----------------------------------------------------------------------------
def test_scanner_extra_fields_forbidden(client, db_session):
    _, headers = create_user_and_headers(db_session)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com", "options": {"ssl_scan": True, "malicious_injected_field": "exploit"}},
    )
    assert response.status_code == 422


def test_scanner_timeout_bounds(client, db_session):
    _, headers = create_user_and_headers(db_session)
    # Negative/zero timeout
    resp_low = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com", "options": {"timeout": 0.5}},
    )
    assert resp_low.status_code == 422

    # Excessive timeout (>60)
    resp_high = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com", "options": {"timeout": 120.0}},
    )
    assert resp_high.status_code == 422


def test_scanner_max_redirects_bounds(client, db_session):
    _, headers = create_user_and_headers(db_session)
    # Negative redirects
    resp_low = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com", "options": {"max_redirects": -1}},
    )
    assert resp_low.status_code == 422

    # Excessive redirects (>10)
    resp_high = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com", "options": {"max_redirects": 50}},
    )
    assert resp_high.status_code == 422


# -----------------------------------------------------------------------------
# 4. Request Body Size Abuse (413 Content Too Large)
# -----------------------------------------------------------------------------
def test_oversized_request_body_rejected(client, db_session):
    _, headers = create_user_and_headers(db_session)
    oversized_data = {"target": "https://example.com", "padding": "A" * (settings.max_request_body_bytes + 1024)}
    body = json.dumps(oversized_data)
    response = client.post(
        "/api/v1/scans/",
        headers={**headers, "Content-Type": "application/json"},
        content=body,
    )
    assert response.status_code == 413


# -----------------------------------------------------------------------------
# 5. Rate Limit Exhaustion (429 Too Many Requests)
# -----------------------------------------------------------------------------
def test_auth_login_rate_limiting_burst(client, db_session):
    limiter.clear()
    # auth login allows 10 requests per 60s
    for _ in range(10):
        resp = client.post(
            "/api/v1/auth/login",
            json={"email": "ratelimit_user@example.com", "password": "WrongPassword123!"},
        )
        assert resp.status_code in [401, 200]

    # 11th request must be rate limited
    blocked_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "ratelimit_user@example.com", "password": "WrongPassword123!"},
    )
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers


@patch("app.api.v1.scans.scan_task.delay")
def test_scan_create_rate_limiting_burst(mock_delay, client, db_session):
    limiter.clear()
    # Use superuser to bypass active scan quota so we test pure rate limiting burst
    _, headers = create_user_and_headers(db_session, is_superuser=True)
    # scans create allows 20 requests per 60s
    for _ in range(20):
        resp = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={"target": "https://example.com"},
        )
        assert resp.status_code == 202

    # 21st request must trigger 429 rate limit
    blocked_resp = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com"},
    )
    assert blocked_resp.status_code == 429
    assert "Retry-After" in blocked_resp.headers
    assert "rate limit exceeded" in blocked_resp.json()["detail"].lower()


# -----------------------------------------------------------------------------
# 6. Per-User Active Scan Quota Abuse
# -----------------------------------------------------------------------------
@patch("app.api.v1.scans.scan_task.delay")
def test_active_scan_quota_enforcement(mock_delay, client, db_session):
    limiter.clear()
    user, headers = create_user_and_headers(db_session)

    # Populate active scans up to limit
    for i in range(settings.max_active_scans_per_user):
        job = ScanJob(
            target_url=f"https://target{i}.example.com",
            status=ScanStatusEnum.PENDING,
            user_id=user.id,
        )
        db_session.add(job)
    db_session.commit()

    # Next submission must be rejected with 429 quota error
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://excess.example.com"},
    )
    assert response.status_code == 429
    assert "active scan quota" in response.json()["detail"].lower()


@patch("app.api.v1.scans.scan_task.delay")
def test_superuser_bypasses_active_scan_quota(mock_delay, client, db_session):
    limiter.clear()
    superuser, headers = create_user_and_headers(db_session, is_superuser=True)

    # Populate active scans exceeding regular quota
    for i in range(settings.max_active_scans_per_user + 2):
        job = ScanJob(
            target_url=f"https://admin-target{i}.example.com",
            status=ScanStatusEnum.RUNNING,
            user_id=superuser.id,
        )
        db_session.add(job)
    db_session.commit()

    # Superuser can still submit
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://admin-extra.example.com"},
    )
    assert response.status_code == 202


# -----------------------------------------------------------------------------
# 7. Broker Saturation & Backpressure Rejection
# -----------------------------------------------------------------------------
@patch("app.api.v1.scans.get_queue_depth", return_value=150)
def test_broker_backpressure_rejection(mock_get_depth, client, db_session):
    limiter.clear()
    _, headers = create_user_and_headers(db_session)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={"target": "https://example.com"},
    )
    assert response.status_code == 503
    assert response.headers.get("Retry-After") == "30"
    assert "high load" in response.json()["detail"].lower()
