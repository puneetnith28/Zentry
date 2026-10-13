import uuid
from datetime import datetime, timezone, timedelta
import pytest

from app.core.security import create_access_token, get_password_hash
from app.db.models import ScanJob, ScanStatusEnum, User


def create_user(db_session, email_prefix: str = "hist_user", is_superuser: bool = False):
    user = User(
        email=f"{email_prefix}_{uuid.uuid4().hex[:8]}@example.com",
        hashed_password=get_password_hash("SecretPassword123!"),
        is_active=True,
        is_superuser=is_superuser,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token({"sub": str(user.id)})
    return user, {"Authorization": f"Bearer {token}"}


def test_unauthenticated_list_scans_rejected(client):
    response = client.get("/api/v1/scans/")
    assert response.status_code == 401


def test_empty_history_for_new_user(client, db_session):
    _, headers = create_user(db_session)
    response = client.get("/api/v1/scans/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["total"] == 0
    assert data["page"] == 1
    assert data["page_size"] == 20
    assert data["total_pages"] == 0


def test_user_history_scoped_and_ordered(client, db_session):
    user_a, headers_a = create_user(db_session, "user_a")
    user_b, _ = create_user(db_session, "user_b")

    now = datetime.now(timezone.utc)

    # Scans for User A (ordered by time)
    job_a1 = ScanJob(
        target_url="https://site1.example.com",
        status=ScanStatusEnum.COMPLETED,
        user_id=user_a.id,
        created_at=now - timedelta(minutes=10),
        result_payload={"summary": {"high": 1, "medium": 2, "low": 0, "info": 3, "critical": 0}},
    )
    job_a2 = ScanJob(
        target_url="https://site2.example.com",
        status=ScanStatusEnum.PENDING,
        user_id=user_a.id,
        created_at=now - timedelta(minutes=2),
    )
    # Scan for User B
    job_b = ScanJob(
        target_url="https://secret-b.example.com",
        status=ScanStatusEnum.COMPLETED,
        user_id=user_b.id,
        created_at=now - timedelta(minutes=1),
    )
    db_session.add_all([job_a1, job_a2, job_b])
    db_session.commit()

    # User A requests history
    response = client.get("/api/v1/scans/", headers=headers_a)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    # Verify descending creation order: site2 (newer) before site1 (older)
    assert data["items"][0]["target_url"] == "https://site2.example.com"
    assert data["items"][1]["target_url"] == "https://site1.example.com"
    assert data["items"][1]["summary"]["high"] == 1
    assert data["items"][1]["summary"]["info"] == 3

    # Verify User B's scan is completely absent
    returned_targets = [item["target_url"] for item in data["items"]]
    assert "https://secret-b.example.com" not in returned_targets


def test_history_pagination_pages_and_limits(client, db_session):
    user, headers = create_user(db_session)
    now = datetime.now(timezone.utc)

    # Create 5 scans
    for i in range(5):
        job = ScanJob(
            target_url=f"https://paginated-{i}.example.com",
            status=ScanStatusEnum.COMPLETED,
            user_id=user.id,
            created_at=now - timedelta(minutes=10 - i),
        )
        db_session.add(job)
    db_session.commit()

    # Page 1 with page_size=2
    res_p1 = client.get("/api/v1/scans/?page=1&page_size=2", headers=headers)
    assert res_p1.status_code == 200
    data_p1 = res_p1.json()
    assert data_p1["total"] == 5
    assert data_p1["page"] == 1
    assert data_p1["page_size"] == 2
    assert data_p1["total_pages"] == 3
    assert len(data_p1["items"]) == 2

    # Page 2 with page_size=2
    res_p2 = client.get("/api/v1/scans/?page=2&page_size=2", headers=headers)
    assert res_p2.status_code == 200
    data_p2 = res_p2.json()
    assert len(data_p2["items"]) == 2
    # Ensure distinct items
    p1_ids = {item["scan_id"] for item in data_p1["items"]}
    p2_ids = {item["scan_id"] for item in data_p2["items"]}
    assert p1_ids.isdisjoint(p2_ids)

    # Page 3 with page_size=2 (last item)
    res_p3 = client.get("/api/v1/scans/?page=3&page_size=2", headers=headers)
    assert res_p3.status_code == 200
    assert len(res_p3.json()["items"]) == 1

    # Page 4 with page_size=2 (empty beyond end)
    res_p4 = client.get("/api/v1/scans/?page=4&page_size=2", headers=headers)
    assert res_p4.status_code == 200
    assert len(res_p4.json()["items"]) == 0


def test_superuser_sees_all_scans_in_history(client, db_session):
    u1, _ = create_user(db_session, "norm1")
    u2, _ = create_user(db_session, "norm2")
    _, admin_headers = create_user(db_session, "admin", is_superuser=True)

    j1 = ScanJob(target_url="https://u1.example.com", status=ScanStatusEnum.COMPLETED, user_id=u1.id)
    j2 = ScanJob(target_url="https://u2.example.com", status=ScanStatusEnum.COMPLETED, user_id=u2.id)
    db_session.add_all([j1, j2])
    db_session.commit()

    response = client.get("/api/v1/scans/", headers=admin_headers)
    assert response.status_code == 200
    data = response.json()
    targets = {item["target_url"] for item in data["items"]}
    assert "https://u1.example.com" in targets
    assert "https://u2.example.com" in targets
