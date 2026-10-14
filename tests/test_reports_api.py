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
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "private" in response.headers["cache-control"]
    assert f'filename="zentry-report-example.com-{str(job.id)[:8]}.pdf"' in response.headers["content-disposition"]
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
    assert f'filename="zentry-report-example.com-{str(job.id)[:8]}.pdf"' in response.headers["content-disposition"]
    mock_pdf.assert_called_once()


@patch("app.api.v1.reports.generate_pdf", return_value=b"%PDF-1.4 failed scan report")
def test_report_download_failed_scan_success(mock_pdf, client, db_session):
    user, headers = create_test_user(db_session)
    job = ScanJob(
        user_id=user.id,
        target_url="https://failed.example.com",
        status=ScanStatusEnum.FAILED,
        error_message="Connection timeout during network probe",
        options={},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    response = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)
    assert response.status_code == 200
    assert response.content == b"%PDF-1.4 failed scan report"
    assert f'filename="zentry-report-failed.example.com-{str(job.id)[:8]}.pdf"' in response.headers["content-disposition"]
    mock_pdf.assert_called_once()
    assert mock_pdf.call_args[1]["scan_status"] == "FAILED"
    assert mock_pdf.call_args[1]["error_message"] == "Connection timeout during network probe"


@patch("app.api.v1.reports.generate_pdf", return_value=b"%PDF-1.4 cancelled scan report")
def test_report_download_cancelled_scan_success(mock_pdf, client, db_session):
    user, headers = create_test_user(db_session)
    job = ScanJob(
        user_id=user.id,
        target_url="https://cancelled.example.com",
        status=ScanStatusEnum.CANCELLED,
        error_message="User requested cancellation",
        options={},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    response = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)
    assert response.status_code == 200
    assert response.content == b"%PDF-1.4 cancelled scan report"
    assert f'filename="zentry-report-cancelled.example.com-{str(job.id)[:8]}.pdf"' in response.headers["content-disposition"]
    mock_pdf.assert_called_once()
    assert mock_pdf.call_args[1]["scan_status"] == "CANCELLED"


def test_sanitize_report_filename_various_targets():
    """Verify sanitize_report_filename strips injection characters, paths, credentials, and control chars."""
    from app.api.v1.reports import sanitize_report_filename

    scan_uuid = "12345678-abcd-1111-2222-333344445555"

    # Standard URL
    assert sanitize_report_filename("https://my-app.org/dashboard", scan_uuid) == "zentry-report-my-app.org-12345678.pdf"

    # URL with embedded credentials
    assert sanitize_report_filename("https://admin:secret@api.internal.net:8443/v1", scan_uuid) == "zentry-report-api.internal.net-12345678.pdf"

    # Path traversal attempt
    assert sanitize_report_filename("https://evil.corp/../../../../etc/passwd", scan_uuid) == "zentry-report-evil.corp-12345678.pdf"

    # CRLF header injection attempt
    assert sanitize_report_filename("https://injected.com\r\nX-Injected: attack", scan_uuid) == "zentry-report-injected.com-12345678.pdf"

    # Special characters and spaces
    assert sanitize_report_filename("foo bar \" ' < >", scan_uuid) == "zentry-report-foo_bar-12345678.pdf"

    # Empty string fallback
    assert sanitize_report_filename("", scan_uuid) == "zentry-report-target-12345678.pdf"


@patch("app.api.v1.reports.generate_pdf", return_value=b"%PDF-1.4 cached test bytes")
def test_report_download_uses_cache_on_repeat_requests(mock_pdf, client, db_session):
    """Verify repeat report requests serve cached PDF without re-running WeasyPrint."""
    from app.services.report_cache import clear_report_cache, invalidate_cached_report

    clear_report_cache()
    user, headers = create_test_user(db_session, email_prefix="cached_user")
    job = ScanJob(
        user_id=user.id,
        target_url="https://cached.example.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload={
            "target": "https://cached.example.com",
            "scanned_at": "2026-05-15T00:00:00+00:00",
            "modules": {},
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        },
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    # 1. First request compiles PDF
    resp1 = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)
    assert resp1.status_code == 200
    assert resp1.content == b"%PDF-1.4 cached test bytes"
    assert mock_pdf.call_count == 1

    # 2. Second request hits cache; generate_pdf is NOT called again
    resp2 = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)
    assert resp2.status_code == 200
    assert resp2.content == b"%PDF-1.4 cached test bytes"
    assert mock_pdf.call_count == 1  # Still 1! Zero re-compilation

    # 3. Invalidate cache; third request re-compiles
    invalidate_cached_report(job.id)
    resp3 = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)
    assert resp3.status_code == 200
    assert resp3.content == b"%PDF-1.4 cached test bytes"
    assert mock_pdf.call_count == 2


def test_report_cache_operations_and_traversal_safety():
    """Verify report_cache direct operations, atomic writes, and path traversal rejection."""
    import uuid
    from app.services.report_cache import (
        clear_report_cache,
        get_cached_report,
        invalidate_cached_report,
        set_cached_report,
    )

    test_id = uuid.uuid4()
    pdf_sample = b"%PDF-sample-atomic-cache"

    # Set and get
    set_cached_report(test_id, pdf_sample)
    cached = get_cached_report(test_id)
    assert cached == pdf_sample

    # Invalidate
    assert invalidate_cached_report(test_id) is True
    assert get_cached_report(test_id) is None
    assert invalidate_cached_report(test_id) is False

    # Path traversal attack in scan_id should be safely neutralized to filename
    traversal_id = "../../etc/passwd"
    set_cached_report(traversal_id, b"%PDF-traversal-safe")
    assert get_cached_report("passwd") == b"%PDF-traversal-safe"
    invalidate_cached_report("passwd")

    clear_report_cache()


