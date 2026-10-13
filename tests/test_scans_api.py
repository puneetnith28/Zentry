from unittest.mock import patch
import uuid
from uuid import uuid4

import pytest

from app.core.security import create_access_token, get_password_hash
from app.db.models import ScanJob, ScanStatusEnum, User


def create_test_user(db_session, email_prefix: str = "user", is_superuser: bool = False):
    user = User(
        email=f"{email_prefix}_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("StrongPassword123!"),
        is_active=True,
        is_superuser=is_superuser,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return user, {"Authorization": f"Bearer {token}"}


def test_unauthenticated_create_scan_rejected(client):
    response = client.post(
        "/api/v1/scans/",
        json={
            "target": "https://example.com",
            "options": {"ssl_scan": True, "headers_scan": False, "port_scan": False},
        },
    )
    assert response.status_code == 401


def test_unauthenticated_get_scan_rejected(client):
    response = client.get(f"/api/v1/scans/{uuid4()}")
    assert response.status_code == 401


@patch("app.api.v1.scans.scan_task.delay")
def test_create_scan_returns_pending(mock_delay, client, db_session):
    user, headers = create_test_user(db_session)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"ssl_scan": True, "headers_scan": False, "port_scan": False},
        },
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "PENDING"
    assert "scan_id" in data
    mock_delay.assert_called_once()

    scan_id = uuid.UUID(data["scan_id"])
    job = db_session.get(ScanJob, scan_id)
    assert job is not None
    assert job.user_id == user.id


def test_get_scan_not_found(client, db_session):
    _, headers = create_test_user(db_session)
    response = client.get(f"/api/v1/scans/{uuid4()}", headers=headers)
    assert response.status_code == 404


def test_get_scan_completed(client, db_session):
    user, headers = create_test_user(db_session)
    job = ScanJob(
        user_id=user.id,
        target_url="https://example.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload={
            "target": "https://example.com",
            "scanned_at": "2026-05-15T00:00:00+00:00",
            "modules": {"ssl": {"status": "success", "findings": []}},
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    response = client.get(f"/api/v1/scans/{job.id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert data["result"] is not None
    assert "ssl" in data["result"]["modules"]


def test_user_cannot_read_another_users_scan(client, db_session):
    user_a, _ = create_test_user(db_session, email_prefix="usera")
    _, headers_b = create_test_user(db_session, email_prefix="userb")

    job = ScanJob(
        user_id=user_a.id,
        target_url="https://example.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload={
            "target": "https://example.com",
            "scanned_at": "2026-05-15T00:00:00+00:00",
            "modules": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    # User B requests User A's scan
    response = client.get(f"/api/v1/scans/{job.id}", headers=headers_b)
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_superuser_can_read_another_users_scan(client, db_session):
    user_a, _ = create_test_user(db_session, email_prefix="usera")
    _, admin_headers = create_test_user(db_session, email_prefix="admin", is_superuser=True)

    job = ScanJob(
        user_id=user_a.id,
        target_url="https://example.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload={
            "target": "https://example.com",
            "scanned_at": "2026-05-15T00:00:00+00:00",
            "modules": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    response = client.get(f"/api/v1/scans/{job.id}", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "COMPLETED"


def test_scan_with_valid_and_deduped_port_list(client, db_session):
    _, headers = create_test_user(db_session)
    with patch("app.api.v1.scans.scan_task.delay"):
        response = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={
                "target": "https://example.com",
                "options": {"port_scan": True, "port_list": [80, 443, 80, 8080]},
            },
        )
    assert response.status_code == 202
    scan_id = uuid.UUID(response.json()["scan_id"])
    job = db_session.get(ScanJob, scan_id)
    assert job is not None
    assert job.options["port_list"] == [80, 443, 8080]


def test_scan_with_invalid_port_range_rejected(client, db_session):
    _, headers = create_test_user(db_session)
    # Port 0
    res_zero = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"port_scan": True, "port_list": [0, 80]},
        },
    )
    assert res_zero.status_code == 422

    # Port 70000
    res_high = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"port_scan": True, "port_list": [70000]},
        },
    )
    assert res_high.status_code == 422


def test_scan_with_excessive_ports_rejected(client, db_session):
    _, headers = create_test_user(db_session)
    too_many_ports = list(range(1, 55))  # 54 ports (> 50)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"port_scan": True, "port_list": too_many_ports},
        },
    )
    assert response.status_code == 422


def test_scan_with_empty_port_list_rejected(client, db_session):
    _, headers = create_test_user(db_session)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"port_scan": True, "port_list": []},
        },
    )
    assert response.status_code == 422


def test_scan_with_unknown_options_rejected(client, db_session):
    _, headers = create_test_user(db_session)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"unsupported_flag": True},
        },
    )
    assert response.status_code == 422


def test_scan_with_unknown_root_fields_rejected(client, db_session):
    _, headers = create_test_user(db_session)
    response = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {},
            "malicious_extra_field": "injected",
        },
    )
    assert response.status_code == 422


def test_scan_with_out_of_bounds_timeout_and_redirects(client, db_session):
    _, headers = create_test_user(db_session)
    # Timeout too low (< 1.0)
    res_low = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"timeout": 0.2},
        },
    )
    assert res_low.status_code == 422

    # Timeout too high (> 60.0)
    res_high = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"timeout": 120.0},
        },
    )
    assert res_high.status_code == 422

    # Redirects too high (> 10)
    res_redir = client.post(
        "/api/v1/scans/",
        headers=headers,
        json={
            "target": "https://example.com",
            "options": {"max_redirects": 25},
        },
    )
    assert res_redir.status_code == 422


def test_concurrent_active_scan_quota_enforced(client, db_session):
    user, headers = create_test_user(db_session)
    with patch("app.api.v1.scans.scan_task.delay"):
        # Create 3 scans (quota limit)
        for i in range(3):
            res = client.post(
                "/api/v1/scans/",
                headers=headers,
                json={"target": f"https://example{i}.com", "options": {}},
            )
            assert res.status_code == 202

        # 4th scan attempt exceeds quota
        res_exceeded = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={"target": "https://example-exceeded.com", "options": {}},
        )
        assert res_exceeded.status_code == 429
        assert "active scan quota exceeded" in res_exceeded.json()["detail"].lower()


def test_completed_scans_do_not_count_towards_active_quota(client, db_session):
    user, headers = create_test_user(db_session)
    with patch("app.api.v1.scans.scan_task.delay"):
        # Create 2 pending scans
        for i in range(2):
            res = client.post(
                "/api/v1/scans/",
                headers=headers,
                json={"target": f"https://example{i}.com", "options": {}},
            )
            assert res.status_code == 202

        # Add 1 completed scan
        completed_job = ScanJob(
            user_id=user.id,
            target_url="https://completed.com",
            status=ScanStatusEnum.COMPLETED,
            options={},
        )
        db_session.add(completed_job)
        db_session.commit()

        # Should still be able to submit a 3rd active scan (since only 2 are pending)
        res_third = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={"target": "https://example-third.com", "options": {}},
        )
        assert res_third.status_code == 202


def test_queue_depth_backpressure_returns_503(client, db_session):
    _, headers = create_test_user(db_session)
    with patch("app.api.v1.scans.get_queue_depth", return_value=150):
        response = client.post(
            "/api/v1/scans/",
            headers=headers,
            json={"target": "https://example.com", "options": {}},
        )
    assert response.status_code == 503
    assert "high load" in response.json()["detail"].lower()
    assert response.headers.get("retry-after") == "30"


def test_queue_depth_under_threshold_accepted(client, db_session):
    _, headers = create_test_user(db_session)
    with patch("app.api.v1.scans.get_queue_depth", return_value=10):
        with patch("app.api.v1.scans.scan_task.delay"):
            response = client.post(
                "/api/v1/scans/",
                headers=headers,
                json={"target": "https://example.com", "options": {}},
            )
    assert response.status_code == 202


def test_get_scan_returns_timing_metrics(client, db_session):
    from datetime import datetime, timedelta, timezone

    user, headers = create_test_user(db_session)
    job = ScanJob(
        user_id=user.id,
        target_url="https://timed-scan.example.com",
        status=ScanStatusEnum.PENDING,
    )
    db_session.add(job)
    db_session.commit()

    start = datetime(2026, 10, 13, 10, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(seconds=8.75)
    job.transition_to(ScanStatusEnum.RUNNING, timestamp=start)
    job.transition_to(ScanStatusEnum.COMPLETED, timestamp=end)
    db_session.commit()

    response = client.get(f"/api/v1/scans/{job.id}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["started_at"] is not None
    assert data["finished_at"] is not None
    assert data["duration_seconds"] == 8.75

