import uuid
from datetime import datetime

from app.db.models import Base, ScanJob, ScanStatusEnum, User


def test_user_model_attributes():
    user = User(
        email="test@example.com",
        hashed_password="securehashedpassword",
        is_active=True,
        is_superuser=False,
    )
    assert user.email == "test@example.com"
    assert user.hashed_password == "securehashedpassword"
    assert user.is_active is True
    assert user.is_superuser is False


def test_user_table_schema_columns():
    table = User.__table__
    assert table.name == "users"
    assert "id" in table.c
    assert "email" in table.c
    assert "hashed_password" in table.c
    assert "is_active" in table.c
    assert "is_superuser" in table.c
    assert "created_at" in table.c
    assert "updated_at" in table.c

    # Assert constraints
    assert table.c.email.unique is True
    assert table.c.email.nullable is False
    assert table.c.hashed_password.nullable is False
    assert table.c.is_active.nullable is False
    assert table.c.is_superuser.nullable is False


def test_scan_job_model_attributes():
    user_id = uuid.uuid4()
    scan = ScanJob(
        target_url="https://example.com",
        status=ScanStatusEnum.PENDING,
        user_id=user_id,
    )
    assert scan.target_url == "https://example.com"
    assert scan.status == ScanStatusEnum.PENDING
    assert scan.user_id == user_id


def test_scan_job_table_schema_user_id_fk():
    table = ScanJob.__table__
    assert "user_id" in table.c
    fk = list(table.c.user_id.foreign_keys)[0]
    assert fk.target_fullname == "users.id"
    assert fk.ondelete == "CASCADE"


def test_user_scans_relationship_definition():
    user = User(
        email="owner@example.com",
        hashed_password="hash",
    )
    scan = ScanJob(
        target_url="https://example.com",
        owner=user,
    )
    assert scan.owner == user
    assert scan in user.scans
