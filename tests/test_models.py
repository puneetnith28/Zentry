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


def test_scan_status_enum_values_and_helpers():
    expected_values = {"PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"}
    actual_values = {status.value for status in ScanStatusEnum}
    assert actual_values == expected_values

    assert ScanStatusEnum.terminal_statuses() == {
        ScanStatusEnum.COMPLETED,
        ScanStatusEnum.FAILED,
        ScanStatusEnum.CANCELLED,
    }
    assert ScanStatusEnum.active_statuses() == {
        ScanStatusEnum.PENDING,
        ScanStatusEnum.RUNNING,
    }


def test_scan_status_enum_persistence_across_all_values(db_session):
    for status_val in ScanStatusEnum:
        job = ScanJob(
            target_url=f"https://status-{status_val.value.lower()}.example.com",
            status=status_val,
        )
        db_session.add(job)
    db_session.commit()

    saved_jobs = db_session.query(ScanJob).all()
    saved_statuses = {j.status for j in saved_jobs}
    assert saved_statuses == set(ScanStatusEnum)


def test_scan_job_indexes_defined():
    table = ScanJob.__table__
    index_names = {idx.name for idx in table.indexes}
    assert "ix_scan_jobs_user_id_created_at" in index_names
    assert "ix_scan_jobs_created_at" in index_names
    assert "ix_scan_jobs_user_id" in index_names
    assert "ix_scan_jobs_status" in index_names


def test_scan_status_state_machine_valid_transitions():
    valid = ScanStatusEnum.valid_transitions()
    assert valid[ScanStatusEnum.PENDING] == {
        ScanStatusEnum.RUNNING,
        ScanStatusEnum.FAILED,
        ScanStatusEnum.CANCELLED,
    }
    assert valid[ScanStatusEnum.RUNNING] == {
        ScanStatusEnum.COMPLETED,
        ScanStatusEnum.FAILED,
        ScanStatusEnum.CANCELLED,
    }
    assert valid[ScanStatusEnum.COMPLETED] == set()
    assert valid[ScanStatusEnum.FAILED] == set()
    assert valid[ScanStatusEnum.CANCELLED] == set()


def test_scan_job_transition_to_valid():
    job = ScanJob(target_url="https://example.com", status=ScanStatusEnum.PENDING)
    assert job.can_transition_to(ScanStatusEnum.RUNNING) is True
    job.transition_to(ScanStatusEnum.RUNNING)
    assert job.status == ScanStatusEnum.RUNNING

    assert job.can_transition_to(ScanStatusEnum.COMPLETED) is True
    job.transition_to(ScanStatusEnum.COMPLETED)
    assert job.status == ScanStatusEnum.COMPLETED


def test_scan_job_transition_to_invalid_raises():
    import pytest
    from app.db.models import InvalidStateTransitionError

    job = ScanJob(target_url="https://example.com", status=ScanStatusEnum.COMPLETED)
    assert job.can_transition_to(ScanStatusEnum.RUNNING) is False
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        job.transition_to(ScanStatusEnum.RUNNING)
    assert "Cannot transition scan job from COMPLETED to RUNNING" in str(exc_info.value)
    assert exc_info.value.from_status == ScanStatusEnum.COMPLETED
    assert exc_info.value.to_status == ScanStatusEnum.RUNNING

    # Cannot transition from PENDING directly to COMPLETED
    pending_job = ScanJob(target_url="https://example.com", status=ScanStatusEnum.PENDING)
    assert pending_job.can_transition_to(ScanStatusEnum.COMPLETED) is False
    with pytest.raises(InvalidStateTransitionError):
        pending_job.transition_to(ScanStatusEnum.COMPLETED)

    # Terminal states cannot transition to anything
    for term in ScanStatusEnum.terminal_statuses():
        t_job = ScanJob(target_url="https://example.com", status=term)
        for target in ScanStatusEnum:
            assert t_job.can_transition_to(target) is False
            with pytest.raises(InvalidStateTransitionError):
                t_job.transition_to(target)


def test_scan_job_timing_metrics_columns():
    table = ScanJob.__table__
    assert "started_at" in table.c
    assert "finished_at" in table.c
    assert "duration_seconds" in table.c


def test_scan_job_transition_records_timing_metrics():
    from datetime import datetime, timedelta, timezone

    start = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)
    end = start + timedelta(seconds=14.35)

    job = ScanJob(target_url="https://example.com", status=ScanStatusEnum.PENDING)
    assert job.started_at is None
    assert job.finished_at is None
    assert job.duration_seconds is None

    # Transition to RUNNING
    job.transition_to(ScanStatusEnum.RUNNING, timestamp=start)
    assert job.status == ScanStatusEnum.RUNNING
    assert job.started_at == start
    assert job.finished_at is None
    assert job.duration_seconds is None

    # Transition to COMPLETED
    job.transition_to(ScanStatusEnum.COMPLETED, timestamp=end)
    assert job.status == ScanStatusEnum.COMPLETED
    assert job.started_at == start
    assert job.finished_at == end
    assert job.duration_seconds == 14.35


def test_scan_job_transition_to_failed_without_started_at():
    from datetime import datetime, timezone

    failed_time = datetime(2026, 10, 13, 12, 5, 0, tzinfo=timezone.utc)
    job = ScanJob(target_url="https://example.com", status=ScanStatusEnum.PENDING)
    job.transition_to(ScanStatusEnum.FAILED, timestamp=failed_time)
    assert job.status == ScanStatusEnum.FAILED
    assert job.started_at is None
    assert job.finished_at == failed_time
    assert job.duration_seconds is None


