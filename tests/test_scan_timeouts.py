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




