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
