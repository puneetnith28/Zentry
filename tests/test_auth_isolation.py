from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import uuid
from uuid import uuid4

import pytest

pytestmark = pytest.mark.security

from app.core.security import create_access_token, get_password_hash

from app.db.models import ScanJob, ScanStatusEnum, User


def create_user(db_session, email_prefix: str, is_superuser: bool = False, is_active: bool = True):
    user = User(
        email=f"{email_prefix}_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("StrongPassword123!"),
        is_active=is_active,
        is_superuser=is_superuser,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return user, {"Authorization": f"Bearer {token}"}


def test_cross_tenant_scan_isolation(client, db_session):
    user_alice, headers_alice = create_user(db_session, "alice")
    user_bob, headers_bob = create_user(db_session, "bob")

    # Alice creates a scan
    with patch("app.api.v1.scans.scan_task.delay"):
        res_alice = client.post(
            "/api/v1/scans/",
            headers=headers_alice,
            json={"target": "https://alice-site.com", "options": {}},
        )
    assert res_alice.status_code == 202
    alice_scan_id = res_alice.json()["scan_id"]

    # Bob creates a scan
    with patch("app.api.v1.scans.scan_task.delay"):
        res_bob = client.post(
            "/api/v1/scans/",
            headers=headers_bob,
            json={"target": "https://bob-site.com", "options": {}},
        )
    assert res_bob.status_code == 202
    bob_scan_id = res_bob.json()["scan_id"]

    # Alice can read Alice's scan
    read_alice = client.get(f"/api/v1/scans/{alice_scan_id}", headers=headers_alice)
    assert read_alice.status_code == 200
    assert read_alice.json()["scan_id"] == alice_scan_id

    # Bob CANNOT read Alice's scan -> 404 (non-enumerating)
    bob_read_alice = client.get(f"/api/v1/scans/{alice_scan_id}", headers=headers_bob)
    assert bob_read_alice.status_code == 404
    assert bob_read_alice.json()["detail"] == "Scan not found"

    # Alice CANNOT read Bob's scan -> 404 (non-enumerating)
    alice_read_bob = client.get(f"/api/v1/scans/{bob_scan_id}", headers=headers_alice)
    assert alice_read_bob.status_code == 404
    assert alice_read_bob.json()["detail"] == "Scan not found"


def test_cross_tenant_report_isolation(client, db_session):
    user_alice, headers_alice = create_user(db_session, "alice")
    _, headers_bob = create_user(db_session, "bob")

    job_alice = ScanJob(
        user_id=user_alice.id,
        target_url="https://alice-secret-findings.com",
        status=ScanStatusEnum.COMPLETED,
        result_payload={
            "target": "https://alice-secret-findings.com",
            "scanned_at": "2026-05-15T00:00:00+00:00",
            "modules": {},
            "summary": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
        },
    )
    db_session.add(job_alice)
    db_session.commit()
    db_session.refresh(job_alice)

    # Bob attempts to download Alice's confidential PDF report
    res_unauth = client.get(f"/api/v1/reports/{job_alice.id}/pdf", headers=headers_bob)
    assert res_unauth.status_code == 404
    assert res_unauth.json()["detail"] == "Scan not found"

    # Alice can download her own report
    with patch("app.api.v1.reports.generate_pdf", return_value=b"%PDF-1.4 alice"):
        res_auth = client.get(f"/api/v1/reports/{job_alice.id}/pdf", headers=headers_alice)
        assert res_auth.status_code == 200
        assert res_auth.content == b"%PDF-1.4 alice"


def test_inactive_user_access_blocked(client, db_session):
    user_deactivated, headers_deactivated = create_user(db_session, "inactive", is_active=False)

    # Inactive user cannot read /me
    res_me = client.get("/api/v1/auth/me", headers=headers_deactivated)
    assert res_me.status_code == 403
    assert res_me.json()["detail"] == "Inactive user account"

    # Inactive user cannot create scans
    res_scan = client.post(
        "/api/v1/scans/",
        headers=headers_deactivated,
        json={"target": "https://example.com", "options": {}},
    )
    assert res_scan.status_code == 403


def test_tampered_and_forged_tokens_rejected(client, db_session):
    _, headers_valid = create_user(db_session, "valid")

    # Tampered signature
    valid_token = headers_valid["Authorization"].replace("Bearer ", "")
    tampered_token = valid_token[:-4] + "xxxx"
    res_tampered = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert res_tampered.status_code == 401
    assert "credentials" in res_tampered.json()["detail"].lower()

    # Expired token
    user, _ = create_user(db_session, "expired")
    expired_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(minutes=-10),
    )
    res_expired = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res_expired.status_code == 401

    # Forged user ID that does not exist in DB
    unregistered_uuid = str(uuid4())
    forged_token = create_access_token(data={"sub": unregistered_uuid})
    res_forged = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    assert res_forged.status_code == 401
    assert res_forged.json()["detail"] == "User not found"


def test_random_uuid_probing_returns_uniform_404(client, db_session):
    _, headers = create_user(db_session, "probe")
    probe_id = uuid4()

    # Probing scans and reports returns identical 404s
    res_scan = client.get(f"/api/v1/scans/{probe_id}", headers=headers)
    assert res_scan.status_code == 404
    assert res_scan.json()["detail"] == "Scan not found"

    res_report = client.get(f"/api/v1/reports/{probe_id}/pdf", headers=headers)
    assert res_report.status_code == 404
    assert res_report.json()["detail"] == "Scan not found"
