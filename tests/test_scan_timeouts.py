import asyncio
from unittest.mock import patch
import uuid

import pytest

from app.db.models import ScanJob, ScanStatusEnum, User
from app.worker.tasks import _module_result_to_dict, scan_task


def test_module_result_to_dict_handles_timeout():
    err = asyncio.TimeoutError()
    res = _module_result_to_dict(err)
    assert res["status"] == "error"
    assert res["error"]["code"] == "MODULE_TIMEOUT"
    assert "timed out" in res["error"]["message"].lower()
    assert res["findings"] == []


def test_scan_task_marks_failed_on_global_timeout(db_session):
    # Create test scan job
    job = ScanJob(
        target_url="https://timeout-test.example.com",
        status=ScanStatusEnum.PENDING,
        options={"timeout": 5.0},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    # Mock _execute_scan_with_deadline to simulate wall-clock timeout
    with patch(
        "app.worker.tasks._execute_scan_with_deadline",
        side_effect=asyncio.TimeoutError(),
    ):
        scan_task(str(job.id), db=db_session)

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert "exceeded maximum wall-clock execution budget" in job.error_message


def test_scan_task_marks_failed_on_soft_time_limit_exceeded(db_session):
    from celery.exceptions import SoftTimeLimitExceeded

    job = ScanJob(
        target_url="https://soft-timeout.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    with patch(
        "app.worker.tasks._execute_scan_with_deadline",
        side_effect=SoftTimeLimitExceeded(),
    ):
        scan_task(str(job.id), db=db_session)

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert "exceeded maximum worker execution deadline" in job.error_message.lower()
    assert job.finished_at is not None
    assert job.duration_seconds is not None


def test_scan_task_time_limits_configured():
    from app.core.celery_app import celery_app

    assert scan_task.time_limit == 300
    assert scan_task.soft_time_limit == 270
    assert celery_app.conf.task_time_limit == 300
    assert celery_app.conf.task_soft_time_limit == 270


def test_classify_worker_exception_mappings():
    import socket
    from celery.exceptions import SoftTimeLimitExceeded
    import httpx
    from app.core.outbound import ProhibitedDestinationError
    from app.core.target_validation import TargetValidationError
    from app.worker.tasks import classify_worker_exception

    # Policy blocked
    code, msg = classify_worker_exception(ProhibitedDestinationError("Blocked IP"))
    assert code == "POLICY_BLOCKED"
    assert "security policy" in msg.lower()

    code, msg = classify_worker_exception(TargetValidationError("Invalid target"))
    assert code == "POLICY_BLOCKED"

    # Network timeout
    code, msg = classify_worker_exception(SoftTimeLimitExceeded())
    assert code == "NETWORK_TIMEOUT"

    code, msg = classify_worker_exception(asyncio.TimeoutError())
    assert code == "NETWORK_TIMEOUT"

    code, msg = classify_worker_exception(socket.timeout())
    assert code == "NETWORK_TIMEOUT"

    # Target unreachable
    code, msg = classify_worker_exception(socket.gaierror("Name resolution failed"))
    assert code == "TARGET_UNREACHABLE"
    assert "unreachable" in msg.lower()

    code, msg = classify_worker_exception(ConnectionRefusedError())
    assert code == "TARGET_UNREACHABLE"

    # Scanner error (unexpected internal error must be sanitized)
    raw_sensitive_error = RuntimeError("Database connection string leaked: postgres://user:secret@db/internal")
    code, msg = classify_worker_exception(raw_sensitive_error)
    assert code == "SCANNER_ERROR"
    assert "secret" not in msg
    assert "postgres" not in msg
    assert "internal error" in msg.lower()


def test_scan_task_sanitizes_internal_exception(db_session):
    job = ScanJob(
        target_url="https://sanitize-test.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    # Simulate catastrophic internal exception with sensitive traceback info
    with patch(
        "app.worker.tasks._execute_scan_with_deadline",
        side_effect=RuntimeError("Leaked filesystem path /root/.secret_key"),
    ):
        scan_task(str(job.id), db=db_session)

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert job.error_message == "[SCANNER_ERROR] An internal error occurred during scan execution"
    assert "/root/.secret_key" not in job.error_message


def test_is_retryable_error_distinguishes_transient_and_permanent():
    import socket
    from celery.exceptions import SoftTimeLimitExceeded
    from sqlalchemy.exc import DBAPIError, OperationalError
    from app.core.outbound import ProhibitedDestinationError
    from app.core.target_validation import TargetValidationError
    from app.worker.tasks import is_retryable_error

    # Transient errors are retryable
    assert is_retryable_error(OperationalError("select 1", [], Exception("db disconnect"))) is True
    assert is_retryable_error(DBAPIError("select 1", [], Exception("connection reset"))) is True

    # Security policy and timeouts are permanent and MUST NOT be retried
    assert is_retryable_error(ProhibitedDestinationError("SSRF blocked")) is False
    assert is_retryable_error(TargetValidationError("Invalid target")) is False
    assert is_retryable_error(SoftTimeLimitExceeded()) is False
    assert is_retryable_error(asyncio.TimeoutError()) is False
    assert is_retryable_error(ValueError("Invalid syntax")) is False
    assert is_retryable_error(socket.gaierror("Name resolution failed")) is False


def test_scan_task_does_not_retry_policy_blocks(db_session):
    from app.core.outbound import ProhibitedDestinationError

    job = ScanJob(
        target_url="https://policy-blocked.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    with patch.object(scan_task, "retry") as mock_retry:
        with patch(
            "app.worker.tasks._execute_scan_with_deadline",
            side_effect=ProhibitedDestinationError("Blocked loopback destination"),
        ):
            scan_task(str(job.id), db=db_session)

        # Must NOT attempt Celery retry on security policy blocks
        mock_retry.assert_not_called()

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert "[POLICY_BLOCKED]" in job.error_message


def test_scan_task_triggers_retry_on_transient_db_error(db_session):
    from celery.exceptions import Retry
    from sqlalchemy.exc import OperationalError

    job = ScanJob(
        target_url="https://transient-db-err.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    db_err = OperationalError("SELECT 1", [], Exception("connection reset by peer"))
    with patch.object(scan_task, "retry", side_effect=Retry()) as mock_retry:
        with patch(
            "app.worker.tasks._execute_scan_with_deadline",
            side_effect=db_err,
        ):
            with pytest.raises(Retry):
                scan_task(str(job.id), db=db_session)

        mock_retry.assert_called_once()
        _, kwargs = mock_retry.call_args
        assert kwargs.get("max_retries") == 3
        assert kwargs.get("countdown") == 2  # 2 ** 0 * 2


def test_scan_task_exhaustion_marks_failed(db_session):
    from celery.exceptions import MaxRetriesExceededError
    from sqlalchemy.exc import OperationalError

    job = ScanJob(
        target_url="https://max-retries.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    db_err = OperationalError("SELECT 1", [], Exception("database is dead"))
    with patch.object(scan_task, "retry", side_effect=MaxRetriesExceededError()):
        with patch(
            "app.worker.tasks._execute_scan_with_deadline",
            side_effect=db_err,
        ):
            with pytest.raises(MaxRetriesExceededError):
                scan_task(str(job.id), db=db_session)

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert "database connection failed after maximum retry attempts" in job.error_message.lower()


def test_duplicate_task_delivery_on_terminal_scans_ignored(db_session):
    for terminal_status in ScanStatusEnum.terminal_statuses():
        job = ScanJob(
            target_url=f"https://terminal-{terminal_status.value.lower()}.example.com",
            status=terminal_status,
            result_payload={"original": "untouched"},
        )
        db_session.add(job)
        db_session.commit()
        db_session.refresh(job)

        with patch("app.worker.tasks._execute_scan_with_deadline") as mock_exec:
            scan_task(str(job.id), db=db_session)
            mock_exec.assert_not_called()

        db_session.refresh(job)
        assert job.status == terminal_status
        assert job.result_payload == {"original": "untouched"}


def test_duplicate_task_delivery_on_concurrent_running_scan_ignored(db_session):
    job = ScanJob(
        target_url="https://already-running.example.com",
        status=ScanStatusEnum.RUNNING,
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    with patch("app.worker.tasks._execute_scan_with_deadline") as mock_exec:
        scan_task(str(job.id), db=db_session)
        mock_exec.assert_not_called()

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.RUNNING


def test_worker_cooperative_abort_before_execution(db_session):
    job = ScanJob(
        target_url="https://cancelled-before-exec.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()
    job.transition_to(ScanStatusEnum.CANCELLED)
    db_session.commit()

    with patch("app.worker.tasks._execute_scan_with_deadline") as mock_exec:
        scan_task(str(job.id), db=db_session)
        mock_exec.assert_not_called()


def test_worker_cooperative_abort_during_execution(db_session):
    from app.worker.tasks import ScanCancelledError

    job = ScanJob(
        target_url="https://cancelled-during-exec.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    with patch(
        "app.worker.tasks._execute_scan_with_deadline",
        side_effect=ScanCancelledError("User requested abort"),
    ):
        scan_task(str(job.id), db=db_session)

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.CANCELLED
    assert "cancelled by user" in job.error_message.lower()


def test_classify_worker_exception_stale_timeout():
    from app.worker.tasks import StaleJobTimeoutError, classify_worker_exception

    code, msg = classify_worker_exception(StaleJobTimeoutError())
    assert code == "STALE_JOB_TIMEOUT"
    assert "without worker progress" in msg


def test_recover_stale_scans_marks_aged_running_scan_as_failed(db_session):
    from datetime import datetime, timedelta, timezone
    from app.worker.tasks import recover_stale_scans

    job = ScanJob(
        target_url="https://stale-running.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    # Artificially transition to RUNNING with started_at 400s in the past
    job.transition_to(ScanStatusEnum.RUNNING)
    job.started_at = datetime.now(timezone.utc) - timedelta(seconds=400)
    db_session.commit()

    recovered = recover_stale_scans(max_age_seconds=300.0, db=db_session)
    assert recovered == 1

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert "[STALE_JOB_TIMEOUT]" in job.error_message
    assert "Scan exceeded maximum wall-clock execution threshold" in job.error_message
    assert job.finished_at is not None
    assert job.duration_seconds is not None
    assert job.duration_seconds >= 399.0


def test_recover_stale_scans_ignores_fresh_running_scan(db_session):
    from datetime import datetime, timedelta, timezone
    from app.worker.tasks import recover_stale_scans

    job = ScanJob(
        target_url="https://fresh-running.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    job.transition_to(ScanStatusEnum.RUNNING)
    job.started_at = datetime.now(timezone.utc) - timedelta(seconds=15)
    db_session.commit()

    recovered = recover_stale_scans(max_age_seconds=300.0, db=db_session)
    assert recovered == 0

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.RUNNING
    assert job.finished_at is None


def test_recover_stale_scans_marks_aged_pending_scan_as_failed(db_session):
    from datetime import datetime, timedelta, timezone
    from app.worker.tasks import recover_stale_scans

    job = ScanJob(
        target_url="https://stale-pending.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    # Artificially age created_at 700s in the past
    job.created_at = datetime.now(timezone.utc) - timedelta(seconds=700)
    db_session.commit()

    recovered = recover_stale_scans(
        max_age_seconds=300.0, max_pending_age_seconds=600.0, db=db_session
    )
    assert recovered == 1

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert "[STALE_JOB_TIMEOUT]" in job.error_message
    assert "Scan exceeded maximum queue wait threshold" in job.error_message


def test_recover_stale_scans_ignores_terminal_scans(db_session):
    from datetime import datetime, timedelta, timezone
    from app.worker.tasks import recover_stale_scans

    j_comp = ScanJob(target_url="https://comp.example.com", status=ScanStatusEnum.PENDING)
    j_fail = ScanJob(target_url="https://fail.example.com", status=ScanStatusEnum.PENDING)
    j_canc = ScanJob(target_url="https://canc.example.com", status=ScanStatusEnum.PENDING)
    db_session.add_all([j_comp, j_fail, j_canc])
    db_session.commit()

    j_comp.transition_to(ScanStatusEnum.RUNNING)
    j_comp.transition_to(ScanStatusEnum.COMPLETED)
    j_fail.transition_to(ScanStatusEnum.FAILED)
    j_canc.transition_to(ScanStatusEnum.CANCELLED)

    past = datetime.now(timezone.utc) - timedelta(seconds=1000)
    j_comp.created_at = past
    j_fail.created_at = past
    j_canc.created_at = past
    db_session.commit()

    recovered = recover_stale_scans(max_age_seconds=100.0, db=db_session)
    assert recovered == 0

    db_session.refresh(j_comp)
    db_session.refresh(j_fail)
    db_session.refresh(j_canc)
    assert j_comp.status == ScanStatusEnum.COMPLETED
    assert j_fail.status == ScanStatusEnum.FAILED
    assert j_canc.status == ScanStatusEnum.CANCELLED


def test_recover_stale_scans_releases_user_quota(db_session):
    from datetime import datetime, timedelta, timezone
    from app.worker.tasks import recover_stale_scans

    user = User(
        email="stale-quota-test@example.com",
        hashed_password="hash",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    jobs = []
    for i in range(3):
        j = ScanJob(
            user_id=user.id,
            target_url=f"https://quota-stale-{i}.example.com",
            status=ScanStatusEnum.PENDING,
        )
        db_session.add(j)
        jobs.append(j)
    db_session.commit()

    for j in jobs:
        j.transition_to(ScanStatusEnum.RUNNING)
        j.started_at = datetime.now(timezone.utc) - timedelta(seconds=500)
    db_session.commit()

    active_before = (
        db_session.query(ScanJob)
        .filter(
            ScanJob.user_id == user.id,
            ScanJob.status.in_(ScanStatusEnum.active_statuses()),
        )
        .count()
    )
    assert active_before == 3

    recovered = recover_stale_scans(max_age_seconds=300.0, db=db_session)
    assert recovered == 3

    active_after = (
        db_session.query(ScanJob)
        .filter(
            ScanJob.user_id == user.id,
            ScanJob.status.in_(ScanStatusEnum.active_statuses()),
        )
        .count()
    )
    assert active_after == 0






