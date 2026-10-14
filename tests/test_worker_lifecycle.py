import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import uuid

import pytest
from celery.exceptions import MaxRetriesExceededError, Retry, SoftTimeLimitExceeded
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.outbound import ProhibitedDestinationError
from app.core.target_validation import TargetValidationError
from app.db.models import InvalidStateTransitionError, ScanJob, ScanStatusEnum, User
from app.worker.tasks import (
    ScanCancelledError,
    StaleJobTimeoutError,
    classify_worker_exception,
    is_retryable_error,
    is_scan_cancelled,
    recover_stale_scans,
    scan_task,
)


# ==============================================================================
# 1. State Machine & Transition Guards
# ==============================================================================

def test_lifecycle_state_machine_valid_transitions():
    """Verify all legitimate scan status lifecycle transitions."""
    assert ScanStatusEnum.PENDING.can_transition_to(ScanStatusEnum.RUNNING)
    assert ScanStatusEnum.PENDING.can_transition_to(ScanStatusEnum.FAILED)
    assert ScanStatusEnum.PENDING.can_transition_to(ScanStatusEnum.CANCELLED)

    assert ScanStatusEnum.RUNNING.can_transition_to(ScanStatusEnum.COMPLETED)
    assert ScanStatusEnum.RUNNING.can_transition_to(ScanStatusEnum.FAILED)
    assert ScanStatusEnum.RUNNING.can_transition_to(ScanStatusEnum.CANCELLED)

    # Terminal states can never transition to any state
    for terminal in ScanStatusEnum.terminal_statuses():
        for target in ScanStatusEnum:
            assert not terminal.can_transition_to(target)


def test_lifecycle_state_machine_invalid_transitions_raise():
    """Verify that illegal transitions raise InvalidStateTransitionError."""
    job = ScanJob(target_url="https://lifecycle-test.example.com", status=ScanStatusEnum.PENDING)

    # Cannot transition directly from PENDING to COMPLETED
    with pytest.raises(InvalidStateTransitionError):
        job.transition_to(ScanStatusEnum.COMPLETED)

    # Transition to RUNNING then COMPLETED
    job.transition_to(ScanStatusEnum.RUNNING)
    job.transition_to(ScanStatusEnum.COMPLETED)

    # Once COMPLETED, cannot transition to RUNNING or FAILED
    with pytest.raises(InvalidStateTransitionError):
        job.transition_to(ScanStatusEnum.RUNNING)

    with pytest.raises(InvalidStateTransitionError):
        job.transition_to(ScanStatusEnum.FAILED)


# ==============================================================================
# 2. Timestamps and Execution Duration Metrics
# ==============================================================================

def test_execution_timestamps_and_duration_metrics():
    """Verify started_at, finished_at, and duration_seconds are correctly tracked."""
    start_time = datetime(2026, 10, 14, 12, 0, 0, tzinfo=timezone.utc)
    finish_time = datetime(2026, 10, 14, 12, 2, 30, tzinfo=timezone.utc)

    job = ScanJob(target_url="https://timing-test.example.com", status=ScanStatusEnum.PENDING)
    assert job.started_at is None
    assert job.finished_at is None
    assert job.duration_seconds is None

    job.transition_to(ScanStatusEnum.RUNNING, timestamp=start_time)
    assert job.started_at == start_time
    assert job.finished_at is None
    assert job.duration_seconds is None

    job.transition_to(ScanStatusEnum.COMPLETED, timestamp=finish_time)
    assert job.finished_at == finish_time
    assert job.duration_seconds == 150.0


def test_execution_duration_handles_naive_and_aware_datetimes():
    """Verify timezone normalization prevents TypeError during duration computation."""
    naive_start = datetime(2026, 10, 14, 10, 0, 0)
    aware_finish = datetime(2026, 10, 14, 10, 1, 15, tzinfo=timezone.utc)

    job = ScanJob(target_url="https://naive-test.example.com", status=ScanStatusEnum.PENDING)
    job.transition_to(ScanStatusEnum.RUNNING, timestamp=naive_start)
    job.transition_to(ScanStatusEnum.FAILED, timestamp=aware_finish)

    assert job.duration_seconds == 75.0


# ==============================================================================
# 3. Exception Classification & Traceback Sanitization
# ==============================================================================

@pytest.mark.parametrize(
    "exc,expected_code,expected_substr",
    [
        (ProhibitedDestinationError("Private IP 10.0.0.1"), "POLICY_BLOCKED", "security policy"),
        (TargetValidationError("Invalid scheme"), "POLICY_BLOCKED", "security policy"),
        (SoftTimeLimitExceeded(), "NETWORK_TIMEOUT", "deadline"),
        (asyncio.TimeoutError(), "NETWORK_TIMEOUT", "timed out"),
        (TimeoutError(), "NETWORK_TIMEOUT", "timed out"),
        (ConnectionRefusedError("Connection refused on port 443"), "TARGET_UNREACHABLE", "unreachable"),
        (ConnectionResetError("Connection reset"), "TARGET_UNREACHABLE", "unreachable"),
        (StaleJobTimeoutError("Aged out"), "STALE_JOB_TIMEOUT", "without worker progress"),
        (RuntimeError("/var/lib/postgresql/secret.key failed"), "SCANNER_ERROR", "internal error"),
    ],
)
def test_worker_exception_classification_and_sanitization(exc, expected_code, expected_substr):
    code, msg = classify_worker_exception(exc)
    assert code == expected_code
    assert expected_substr in msg
    assert "/var/lib" not in msg
    assert "Traceback" not in msg


# ==============================================================================
# 4. Retry Policy & Transient Failure Identification
# ==============================================================================

def test_retryable_error_identification():
    """Ensure transient database errors are retryable while security and timeout errors are not."""
    # Retryable transient errors
    assert is_retryable_error(OperationalError("could not connect", None, None))
    assert is_retryable_error(DBAPIError("broken pipe", None, None))

    # Non-retryable permanent errors
    assert not is_retryable_error(ProhibitedDestinationError("Blocked"))
    assert not is_retryable_error(TargetValidationError("Invalid"))
    assert not is_retryable_error(SoftTimeLimitExceeded())
    assert not is_retryable_error(ScanCancelledError("Cancelled"))
    assert not is_retryable_error(StaleJobTimeoutError("Stale"))
    assert not is_retryable_error(asyncio.TimeoutError())
    assert not is_retryable_error(TimeoutError())


def test_scan_task_retries_transient_database_error(db_session):
    """Verify scan_task triggers self.retry with backoff on transient OperationalError."""
    job = ScanJob(
        target_url="https://retry-test.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    mock_task = MagicMock()
    mock_task.request.retries = 0
    mock_task.retry.side_effect = Retry("Simulated Celery Retry")

    with patch.object(scan_task, "retry", side_effect=Retry("Simulated Celery Retry")) as mock_retry:
        with patch(
            "app.worker.tasks._execute_scan_with_deadline",
            side_effect=OperationalError("connection lost", None, None),
        ):
            with pytest.raises(Retry):
                scan_task(str(job.id), db=db_session)

        mock_retry.assert_called_once()
        assert mock_retry.call_args[1]["countdown"] == 2


def test_scan_task_fails_when_max_retries_exceeded(db_session):
    """Verify scan_task cleanly transitions to FAILED when MaxRetriesExceededError occurs."""
    job = ScanJob(
        target_url="https://max-retries-test.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    with patch.object(scan_task, "retry", side_effect=MaxRetriesExceededError("Exceeded")):
        with patch(
            "app.worker.tasks._execute_scan_with_deadline",
            side_effect=OperationalError("connection lost", None, None),
        ):
            with pytest.raises(MaxRetriesExceededError):
                scan_task(str(job.id), db=db_session)

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert "[SCANNER_ERROR]" in job.error_message


# ==============================================================================
# 5. Task Idempotency & Deduplication
# ==============================================================================

@pytest.mark.parametrize("terminal_status", [ScanStatusEnum.COMPLETED, ScanStatusEnum.FAILED, ScanStatusEnum.CANCELLED])
def test_idempotency_ignores_terminal_scans(db_session, terminal_status):
    """Ensure duplicate delivery of a Celery message for an already finished scan is a no-op."""
    job = ScanJob(
        target_url="https://idempotent-terminal.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    job.transition_to(ScanStatusEnum.RUNNING)
    job.transition_to(terminal_status)
    original_finished = job.finished_at
    db_session.commit()

    with patch("app.worker.tasks._execute_scan_with_deadline") as mock_exec:
        scan_task(str(job.id), db=db_session)
        mock_exec.assert_not_called()

    db_session.refresh(job)
    assert job.status == terminal_status
    actual_finished = job.finished_at if job.finished_at.tzinfo else job.finished_at.replace(tzinfo=timezone.utc)
    assert actual_finished == original_finished


def test_idempotency_ignores_duplicate_running_task(db_session):
    """Ensure a duplicate task delivery for an already running scan does not execute concurrently."""
    job = ScanJob(
        target_url="https://idempotent-running.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    job.transition_to(ScanStatusEnum.RUNNING)
    db_session.commit()

    with patch.object(scan_task.request, "retries", 0, create=True):
        with patch("app.worker.tasks._execute_scan_with_deadline") as mock_exec:
            scan_task(str(job.id), db=db_session)
            mock_exec.assert_not_called()

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.RUNNING


# ==============================================================================
# 6. Cancellation & Cooperative Abort
# ==============================================================================

def test_cooperative_abort_check_helper(db_session):
    job = ScanJob(target_url="https://abort-check.example.com", status=ScanStatusEnum.PENDING)
    db_session.add(job)
    db_session.commit()

    assert not is_scan_cancelled(db_session, job.id)

    job.transition_to(ScanStatusEnum.CANCELLED)
    db_session.commit()

    assert is_scan_cancelled(db_session, job.id)


def test_worker_cooperative_abort_discards_findings(db_session):
    job = ScanJob(
        target_url="https://discard-findings.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    with patch(
        "app.worker.tasks._execute_scan_with_deadline",
        side_effect=ScanCancelledError("Abort requested"),
    ):
        scan_task(str(job.id), db=db_session)

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.CANCELLED
    assert job.result_payload is None


# ==============================================================================
# 7. Stale Scan Detection and Recovery
# ==============================================================================

def test_stale_scan_recovery_lifecycle(db_session):
    """End-to-end verification of recovering abandoned RUNNING scans."""
    job = ScanJob(
        target_url="https://abandoned-worker.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    # Simulate worker crash: job transitioned to RUNNING 10 minutes ago
    job.transition_to(ScanStatusEnum.RUNNING)
    job.started_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.commit()

    recovered = recover_stale_scans(max_age_seconds=300.0, db=db_session)
    assert recovered == 1

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.FAILED
    assert "[STALE_JOB_TIMEOUT]" in job.error_message
    assert job.finished_at is not None
    assert job.duration_seconds >= 600.0


def test_stale_scan_recovery_preserves_valid_running_jobs(db_session):
    """Verify actively running jobs within the timeout window are not interrupted."""
    job = ScanJob(
        target_url="https://active-legitimate.example.com",
        status=ScanStatusEnum.PENDING,
        options={},
    )
    db_session.add(job)
    db_session.commit()

    job.transition_to(ScanStatusEnum.RUNNING)
    job.started_at = datetime.now(timezone.utc) - timedelta(seconds=20)
    db_session.commit()

    recovered = recover_stale_scans(max_age_seconds=300.0, db=db_session)
    assert recovered == 0

    db_session.refresh(job)
    assert job.status == ScanStatusEnum.RUNNING
    assert job.finished_at is None


def test_celery_worker_concurrency_and_prefetch_limits():
    """Verify Celery configuration enforces bounded concurrency, prefetch=1, and max_tasks_per_child."""
    from app.core.celery_app import celery_app
    from app.core.config import get_settings

    settings = get_settings()
    assert celery_app.conf.worker_prefetch_multiplier == 1
    assert celery_app.conf.worker_prefetch_multiplier == settings.celery_worker_prefetch_multiplier
    assert celery_app.conf.worker_max_tasks_per_child == 50
    assert celery_app.conf.worker_max_tasks_per_child == settings.celery_worker_max_tasks_per_child
    assert celery_app.conf.worker_concurrency == 4
    assert celery_app.conf.worker_concurrency == settings.celery_worker_concurrency

