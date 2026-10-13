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


def test_unauthenticated_report_download_rejected(client):
    response = client.get(f"/api/v1/reports/{uuid4()}/pdf")
    assert response.status_code == 401


def test_report_download_not_found(client, db_session):
    _, headers = create_test_user(db_session)
    response = client.get(f"/api/v1/reports/{uuid4()}/pdf", headers=headers)
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_cross_user_report_download_returns_404(client, db_session):
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

    # User B requests User A's report
    response = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers_b)
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan not found"


def test_report_download_incomplete_scan_returns_409(client, db_session):
    user, headers = create_test_user(db_session)
    job = ScanJob(
        user_id=user.id,
        target_url="https://example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    response = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)
    assert response.status_code == 409
    assert "not completed" in response.json()["detail"]


@patch("app.api.v1.reports.generate_pdf", return_value=b"%PDF-1.4 mock pdf content")
def test_owner_report_download_success(mock_pdf, client, db_session):
    user, headers = create_test_user(db_session)
    job = ScanJob(
        user_id=user.id,
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

    response = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert f'filename="zentry-report-{job.id}.pdf"' in response.headers["content-disposition"]
    assert response.content == b"%PDF-1.4 mock pdf content"
    mock_pdf.assert_called_once()


@patch("app.api.v1.reports.generate_pdf", return_value=b"%PDF-1.4 admin pdf content")
def test_superuser_can_download_any_report(mock_pdf, client, db_session):
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

    response = client.get(f"/api/v1/reports/{job.id}/pdf", headers=admin_headers)
    assert response.status_code == 200
    assert response.content == b"%PDF-1.4 admin pdf content"
    mock_pdf.assert_called_once()
