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

