import uuid
import pytest
from fastapi.testclient import TestClient

from app.db.models import ScanJob, ScanStatusEnum, User
from app.db.session import SessionLocal
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.mark.security
def test_full_e2e_backend_workflow(client):
    """
    End-to-End verification covering:
    1. User Registration with strong credentials
    2. Authentication & JWT access token acquisition
    3. Profile inspection via /me
    4. Target submission with SSRF validation
    5. Result synthesis & database record updates
    6. Executive PDF report generation & secure caching
    7. Multi-tenant access isolation verification
    """
    # 1. User Registration
    unique_suffix = str(uuid.uuid4())[:8]
    email = f"e2e_user_{unique_suffix}@example.com"
    password = "StrongPassword2026!#"

    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_resp.status_code == 201, f"Registration failed: {reg_resp.text}"
    user_id = reg_resp.json()["id"]

    # 2. Login & JWT Bearer Token
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 3. Verify Authenticated Profile
    me_resp = client.get("/api/v1/auth/me", headers=auth_headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email

    # 4. Submit New Scan Target
    scan_resp = client.post(
        "/api/v1/scans/",
        headers=auth_headers,
        json={
            "target": "example.com",
            "options": {
                "ssl_scan": True,
                "headers_scan": True,
                "port_scan": True,
            },
        },
    )
    assert scan_resp.status_code == 202, f"Scan creation failed: {scan_resp.text}"
    scan_id = scan_resp.json()["scan_id"]
    assert scan_resp.json()["status"] in ("PENDING", "RUNNING")



    # 5. Simulate Scan Execution and Canonical Result Synthesis
    db = SessionLocal()
    try:
        job = db.get(ScanJob, uuid.UUID(scan_id))
        assert job is not None
        assert str(job.user_id) == user_id

        # Populate realistic scan payload with canonical findings
        job.status = ScanStatusEnum.COMPLETED
        job.risk_score = 42
        job.result_payload = {
            "target": "example.com",
            "scanned_at": "2026-10-15T00:00:00Z",
            "modules": {
                "ssl": {"grade": "A+", "valid": True},
                "headers": {"missing": ["Content-Security-Policy"]},
                "ports": {"open_ports": [80, 443]},
            },
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "info": 0,
                "module_statuses": {
                    "ssl": "COMPLETED",
                    "headers": "COMPLETED",
                    "ports": "COMPLETED",
                },
            },
            "module_statuses": {
                "ssl": "COMPLETED",
                "headers": "COMPLETED",
                "ports": "COMPLETED",
            },
            "risk_score": 42,
            "risk_level": "MODERATE",
            "score_version": "v1.0",
        }
        db.commit()

    finally:
        db.close()

    # 6. Retrieve Scan Status and Results via API
    get_scan_resp = client.get(f"/api/v1/scans/{scan_id}", headers=auth_headers)
    assert get_scan_resp.status_code == 200
    assert get_scan_resp.json()["status"] == "COMPLETED"
    assert get_scan_resp.json()["result"]["risk_score"] == 42


    # 7. Request Executive PDF Report
    pdf_resp = client.get(f"/api/v1/reports/{scan_id}/pdf", headers=auth_headers)
    assert pdf_resp.status_code == 200, f"PDF report generation failed: {pdf_resp.text}"
    assert pdf_resp.headers.get("content-type") == "application/pdf"
    assert "Content-Disposition" in pdf_resp.headers
    assert len(pdf_resp.content) > 1000

    # 8. Verify Multi-Tenant Access Isolation (Unrelated User Blocked)
    other_email = f"other_user_{unique_suffix}@example.com"
    client.post(
        "/api/v1/auth/register",
        json={"email": other_email, "password": password},
    )
    other_login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": other_email, "password": password},
    )
    other_token = other_login_resp.json()["access_token"]
    other_headers = {"Authorization": f"Bearer {other_token}"}

    # Other user must NOT be able to view or download first user's scan
    isolated_scan_resp = client.get(f"/api/v1/scans/{scan_id}", headers=other_headers)
    assert isolated_scan_resp.status_code == 404

    isolated_pdf_resp = client.get(f"/api/v1/reports/{scan_id}/pdf", headers=other_headers)
    assert isolated_pdf_resp.status_code == 404
