"""Tests for standardized API error response schemas and request correlation tracking."""

import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.error import StandardErrorResponse

client = TestClient(app)


def test_error_schema_404_not_found():
    """Verify 404 Not Found returns standardized error schema with correlation ID."""
    response = client.get("/api/v1/nonexistent-endpoint-xyz")
    assert response.status_code == 404
    data = response.json()

    assert "detail" in data
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert data["error"]["request_id"] is not None
    assert response.headers.get("X-Request-ID") == data["error"]["request_id"]

    validated = StandardErrorResponse(**data)
    assert validated.error.code == "NOT_FOUND"


def test_error_schema_401_unauthorized():
    """Verify 401 Unauthorized returns standardized error schema."""
    response = client.get("/api/v1/scans")
    assert response.status_code == 401
    data = response.json()

    assert "detail" in data
    assert "error" in data
    assert data["error"]["code"] == "UNAUTHORIZED"
    assert data["error"]["request_id"] is not None
    assert response.headers.get("X-Request-ID") == data["error"]["request_id"]

    validated = StandardErrorResponse(**data)
    assert validated.error.code == "UNAUTHORIZED"


def test_error_schema_422_validation_error():
    """Verify 422 Validation Error returns standardized schema with error details."""
    response = client.post("/api/v1/auth/register", json={"email": "invalid"})
    assert response.status_code == 422
    data = response.json()

    assert "detail" in data
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert data["error"]["request_id"] is not None
    assert data["error"]["details"] is not None
    assert isinstance(data["error"]["details"], list)

    validated = StandardErrorResponse(**data)
    assert validated.error.code == "VALIDATION_ERROR"


def test_error_schema_custom_request_id_propagated():
    """Verify client-supplied X-Request-ID is preserved and echoed in error responses."""
    custom_id = f"test-req-{uuid.uuid4().hex[:12]}"
    response = client.get(
        "/api/v1/nonexistent-path",
        headers={"X-Request-ID": custom_id},
    )
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["request_id"] == custom_id
    assert response.headers.get("X-Request-ID") == custom_id


def test_error_schema_500_internal_server_error():
    """Verify unhandled exceptions return 500 with sanitized generic error and correlation ID."""
    from unittest.mock import MagicMock
    from app.api.dependencies import get_db

    mock_session = MagicMock()
    mock_session.query.side_effect = RuntimeError("Secret database crash")

    app.dependency_overrides[get_db] = lambda: mock_session
    try:
        no_raise_client = TestClient(app, raise_server_exceptions=False)
        response = no_raise_client.post(
            "/api/v1/auth/register",
            json={"email": f"err_{uuid.uuid4().hex}@example.com", "password": "SecurePassword123!"},
        )
        assert response.status_code == 500
        data = response.json()

        assert "detail" in data
        assert "error" in data
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
        assert data["error"]["request_id"] is not None
        # Must NOT leak exception text
        assert "Secret database crash" not in response.text

        validated = StandardErrorResponse(**data)
        assert validated.error.code == "INTERNAL_SERVER_ERROR"
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_error_response_redacts_sensitive_system_details_and_tracebacks():
    """Verify exceptions with tracebacks and internal system paths are strictly redacted."""
    from unittest.mock import MagicMock
    from app.api.dependencies import get_db

    mock_session = MagicMock()
    mock_session.query.side_effect = Exception(
        'Traceback (most recent call last):\n  File "/code/app/secret.py", line 42, in connect\n'
        'psycopg2.OperationalError: password=supersecret host=10.0.0.5'
    )

    app.dependency_overrides[get_db] = lambda: mock_session
    try:
        no_raise_client = TestClient(app, raise_server_exceptions=False)
        response = no_raise_client.post(
            "/api/v1/auth/register",
            json={"email": f"trace_{uuid.uuid4().hex}@example.com", "password": "SecurePassword123!"},
        )
        assert response.status_code == 500
        data = response.json()

        assert "Traceback" not in response.text
        assert "supersecret" not in response.text
        assert "10.0.0.5" not in response.text
        assert "/code/app/secret.py" not in response.text
        assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
        assert data["error"]["message"] == "An internal server error occurred."
    finally:
        app.dependency_overrides.pop(get_db, None)


def test_report_pdf_error_sanitizes_library_exception(client, db_session):
    """Verify PDF generator failure does not leak underlying C-library or file details."""
    from unittest.mock import patch
    from app.db.models import ScanJob, ScanStatusEnum, User
    from app.core.security import get_password_hash

    # Create user and completed scan
    user = User(email=f"pdf_{uuid.uuid4().hex}@example.com", hashed_password=get_password_hash("Pass1234!"), is_active=True)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    job = ScanJob(
        user_id=user.id,
        target_url="https://example.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload={"target": "https://example.com", "findings": []},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    from app.core.security import create_access_token
    token = create_access_token(data={"sub": str(user.id)})
    headers = {"Authorization": f"Bearer {token}"}

    with patch("app.api.v1.reports.generate_pdf", side_effect=RuntimeError("WeasyPrint /usr/lib/x86_64/libc.so missing")):
        resp = client.get(f"/api/v1/reports/{job.id}/pdf", headers=headers)
        assert resp.status_code == 500
        data = resp.json()
        assert "/usr/lib" not in resp.text
        assert "libc.so" not in resp.text
        assert data["error"]["message"] == "Failed to generate PDF report."




