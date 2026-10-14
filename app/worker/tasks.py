from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from celery.exceptions import MaxRetriesExceededError, Retry, SoftTimeLimitExceeded
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.core.outbound import ProhibitedDestinationError
from app.core.target_validation import TargetValidationError
from app.db.models import ScanJob, ScanStatusEnum
from app.db.session import SessionLocal
from app.services.common import (
    calculate_risk_score,
    extract_module_statuses,
    summarize_findings,
)
from app.services.headers import inspect_headers_async
from app.services.ports import scan_ports_async
from app.services.ssl import inspect_ssl_async
from app.services.subdomain import discover_subdomains_async
from app.services.technology import inspect_technology_async

logger = logging.getLogger(__name__)


def classify_worker_exception(exc: BaseException) -> tuple[str, str]:
    """Map internal exceptions to standardized, client-safe error codes and descriptions.

    Prevents raw traceback, host path, or library error leakage to clients.
    """
    if isinstance(exc, (ProhibitedDestinationError, TargetValidationError)):
        return (
            "POLICY_BLOCKED",
            "Target destination is prohibited by outbound security policy",
        )
    if isinstance(exc, StaleJobTimeoutError):
        return (
            "STALE_JOB_TIMEOUT",
            "Scan exceeded maximum execution duration without worker progress",
        )
    if isinstance(exc, SoftTimeLimitExceeded):
        return (
            "NETWORK_TIMEOUT",
            "Scan task exceeded maximum worker execution deadline",
        )
    cls_name = exc.__class__.__name__
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or "Timeout" in cls_name:
        return (
            "NETWORK_TIMEOUT",
            "Scan execution timed out waiting for target response",
        )
    if (
        isinstance(exc, (ConnectionRefusedError, ConnectionResetError, OSError))
        or cls_name in ("gaierror", "ConnectError")
    ) and not isinstance(exc, (ProhibitedDestinationError, TargetValidationError)):
        return (
            "TARGET_UNREACHABLE",
            "Target host is unreachable or domain name could not be resolved",
        )
    return (
        "SCANNER_ERROR",
        "An internal error occurred during scan execution",
    )


class ScanCancelledError(Exception):
    """Raised when a scan is aborted due to user cancellation."""


class StaleJobTimeoutError(Exception):
    """Raised or referenced when a scan job exceeds maximum allowed wall-clock age without progress."""


TRANSIENT_EXCEPTIONS = (
    OperationalError,
    DBAPIError,
)

NON_RETRYABLE_EXCEPTIONS = (
    ProhibitedDestinationError,
    TargetValidationError,
    SoftTimeLimitExceeded,
    ScanCancelledError,
    StaleJobTimeoutError,
    asyncio.TimeoutError,
    TimeoutError,
)


def is_scan_cancelled(db: Session, scan_id: uuid.UUID) -> bool:
    """Check if the scan has been marked CANCELLED in the database."""
    try:
        current_status = db.query(ScanJob.status).filter(ScanJob.id == scan_id).scalar()
        return current_status == ScanStatusEnum.CANCELLED
    except Exception:
        return False


def is_retryable_error(exc: BaseException) -> bool:
    """Determine whether an error is eligible for automated task retry."""
    if isinstance(exc, NON_RETRYABLE_EXCEPTIONS):
        return False
    return isinstance(exc, TRANSIENT_EXCEPTIONS)


def _module_result_to_dict(result: Any) -> dict[str, Any]:
    """Helper to ensure we always return a standardized dictionary format, even on failure."""
    if isinstance(result, dict):
        return result
    if isinstance(result, (asyncio.TimeoutError, TimeoutError)):
        return {
            "status": "error",
            "error": {"code": "MODULE_TIMEOUT", "message": "Module execution timed out"},
            "findings": [],
        }
    if isinstance(result, BaseException):
        # We caught an unhandled exception during the async scan module
        code, msg = classify_worker_exception(result)
        return {
            "status": "error",
            "error": {"code": code, "message": msg},
            "findings": [],
        }
    # Fallback for weird edge cases
    return {"status": "error", "error": {"code": "UNKNOWN", "message": "Unknown result"}}


async def _run_scan_modules(
    target: str,
    options: dict[str, Any],
    module_timeout: float,
    cancel_check: Any | None = None,
) -> dict[str, Any]:
    """Dynamically construct and execute the scan tasks with per-module timeout bounds."""
    if cancel_check and cancel_check():
        raise ScanCancelledError("Scan was cancelled before module execution")

    modules: dict[str, Any] = {}
    tasks: list[tuple[str, Any]] = []

    # Queue up the modules the user asked for
    if options.get("ssl_scan", True):
        tasks.append(("ssl", inspect_ssl_async(target)))
    if options.get("headers_scan", True):
        tasks.append(("headers", inspect_headers_async(target)))
    if options.get("port_scan", True):
        port_list = options.get("port_list")
        tasks.append(("ports", scan_ports_async(target, ports=port_list)))
    if options.get("tech_scan", True):
        tasks.append(("technology", inspect_technology_async(target)))
    if options.get("subdomain_scan", True):
        tasks.append(("subdomain", discover_subdomains_async(target)))

    if not tasks:
        # User deselected everything, nothing to do
        return modules

    # Run each module with bounded timeout and gather concurrently
    results = await asyncio.gather(
        *[asyncio.wait_for(coro, timeout=module_timeout) for _, coro in tasks],
        return_exceptions=True,
    )

    # Stitch the results back together with their module names
    for (name, _), result in zip(tasks, results):
        modules[name] = _module_result_to_dict(result)

    return modules


async def _execute_scan_with_deadline(
    target: str,
    options: dict[str, Any],
    global_timeout: float,
    module_timeout: float,
    cancel_check: Any | None = None,
) -> dict[str, Any]:
    """Execute scan modules subject to global wall-clock deadline."""
    return await asyncio.wait_for(
        _run_scan_modules(target, options, module_timeout, cancel_check=cancel_check),
        timeout=global_timeout,
    )


@celery_app.task(
    name="app.worker.tasks.scan_task",
    bind=True,
    max_retries=3,
    default_retry_delay=2,
    time_limit=300,
    soft_time_limit=270,
)
def scan_task(self, scan_id: str, db: Session | None = None) -> None:
    """The main background worker process triggered when a new scan is created."""
    settings = get_settings()
    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True
    job = None
    try:
        # Look up the scan job from the database with row locking where supported
        query = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_id))
        try:
            job = query.with_for_update().first()
        except Exception:
            job = query.first()

        if job is None:
            logger.error("Scan job %s not found", scan_id)
            return

        # Idempotency guard: ignore duplicate task delivery if already in a terminal state
        if job.status in ScanStatusEnum.terminal_statuses():
            logger.info(
                "Scan job %s is already in terminal state %s; skipping duplicate execution",
                scan_id,
                job.status.value,
            )
            return

        # Idempotency guard: if scan is already RUNNING and this is not a Celery retry attempt, ignore duplicate
        retries = getattr(getattr(self, "request", None), "retries", 0)
        if job.status == ScanStatusEnum.RUNNING and retries == 0:
            logger.info(
                "Scan job %s is already running in another worker; skipping duplicate execution",
                scan_id,
            )
            return

        # Mark as running so the frontend shows the progress spinner
        if job.status != ScanStatusEnum.RUNNING:
            job.transition_to(ScanStatusEnum.RUNNING)
            db.commit()

        options = job.options or {}
        user_timeout = options.get("timeout")
        global_timeout = (
            float(user_timeout)
            if user_timeout is not None
            else settings.global_scan_timeout_seconds
        )
        module_timeout = min(settings.module_scan_timeout_seconds, global_timeout)

        # Cooperative abort check: abort before launching modules if cancelled
        if is_scan_cancelled(db, job.id):
            logger.info("Scan %s was cancelled before module execution; aborting", scan_id)
            return

        try:
            # Fire off the scan modules asynchronously subject to global wall-clock deadline
            modules = asyncio.run(
                _execute_scan_with_deadline(
                    job.target_url,
                    options,
                    global_timeout=global_timeout,
                    module_timeout=module_timeout,
                    cancel_check=lambda: is_scan_cancelled(db, job.id),
                )
            )

            # Cooperative abort check: discard findings and exit if cancelled while running
            if is_scan_cancelled(db, job.id):
                logger.info("Scan %s was cancelled during execution; discarding findings", scan_id)
                return

            # Tally up the final score (critical, high, medium, etc.) and calculate canonical risk
            summary = summarize_findings(modules)
            module_statuses = extract_module_statuses(modules)
            summary["module_statuses"] = module_statuses
            risk = calculate_risk_score(summary)

            # Format the final JSON response for the database
            payload = {
                "target": job.target_url,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "modules": modules,
                "summary": summary,
                "module_statuses": module_statuses,
                "risk_score": risk.score,
                "risk_level": risk.level,
                "score_version": risk.version,
            }
            job.result_payload = payload
            job.transition_to(ScanStatusEnum.COMPLETED)
            job.error_message = None
        except ScanCancelledError:
            logger.info("Scan %s cancelled cooperatively during execution", scan_id)
            if job.can_transition_to(ScanStatusEnum.CANCELLED):
                job.transition_to(ScanStatusEnum.CANCELLED)
                job.error_message = "Scan was cancelled by user request"
                db.commit()
            return
        except SoftTimeLimitExceeded as exc:
            logger.warning("Scan %s exceeded Celery soft time limit (270s)", scan_id)
            if job.can_transition_to(ScanStatusEnum.FAILED):
                job.transition_to(ScanStatusEnum.FAILED)
            code, msg = classify_worker_exception(exc)
            job.error_message = f"[{code}] {msg}"
        except (asyncio.TimeoutError, TimeoutError) as exc:
            logger.warning("Scan %s timed out after %ss", scan_id, global_timeout)
            if job.can_transition_to(ScanStatusEnum.FAILED):
                job.transition_to(ScanStatusEnum.FAILED)
            code, _ = classify_worker_exception(exc)
            job.error_message = (
                f"[{code}] Scan exceeded maximum wall-clock execution budget of {int(global_timeout)}s"
            )
        except Exception as exc:
            # If this is a transient DB error, re-raise to outer retry handler
            if is_retryable_error(exc):
                raise
            # Catastrophic failure outside the module try/catch
            logger.exception("Scan %s failed with unhandled exception", scan_id)
            if job.can_transition_to(ScanStatusEnum.FAILED):
                job.transition_to(ScanStatusEnum.FAILED)
            code, msg = classify_worker_exception(exc)
            job.error_message = f"[{code}] {msg}"

        # Save the final results to Postgres
        db.commit()
    except Retry:
        raise
    except TRANSIENT_EXCEPTIONS as exc:
        retries = getattr(getattr(self, "request", None), "retries", 0)
        logger.warning(
            "Transient database error for scan %s (attempt %d/3): %s",
            scan_id,
            retries + 1,
            exc,
        )
        if db is not None:
            try:
                db.rollback()
            except Exception:
                pass
        try:
            countdown = min(60, (2 ** retries) * 2)
            raise self.retry(exc=exc, countdown=countdown, max_retries=3)
        except MaxRetriesExceededError:
            logger.error("Scan %s exceeded maximum retries for transient error", scan_id)
            if job is not None and job.can_transition_to(ScanStatusEnum.FAILED):
                job.transition_to(ScanStatusEnum.FAILED)
                job.error_message = "[SCANNER_ERROR] Database connection failed after maximum retry attempts"
                try:
                    db.commit()
                except Exception:
                    pass
            raise
    finally:
        # Always clean up the database connection if created here
        if own_session and db is not None:
            db.close()


def recover_stale_scans(
    max_age_seconds: float | None = None,
    max_pending_age_seconds: float | None = None,
    db: Session | None = None,
) -> int:
    """Detect and recover orphaned/zombie scans stuck in active states past their deadline.

    Scans in RUNNING state older than max_age_seconds (computed from started_at,
    or created_at if started_at is missing) are transitioned to FAILED with
    STALE_JOB_TIMEOUT error code.

    Scans in PENDING state older than max_pending_age_seconds (computed from created_at)
    are also transitioned to FAILED, releasing user active scan concurrency quotas.

    Args:
        max_age_seconds: Maximum allowed seconds for a RUNNING scan before marking stale.
            Defaults to settings.stale_scan_threshold_seconds.
        max_pending_age_seconds: Maximum allowed seconds for a PENDING scan before marking stale.
            Defaults to max_age_seconds * 2.
        db: Optional database session. If None, a dedicated SessionLocal is created and closed.

    Returns:
        The total number of stale scans recovered.
    """
    settings = get_settings()
    if max_age_seconds is None:
        max_age_seconds = getattr(settings, "stale_scan_threshold_seconds", 300.0)
    if max_pending_age_seconds is None:
        max_pending_age_seconds = max_age_seconds * 2.0

    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True

    recovered_count = 0
    now = datetime.now(timezone.utc)
    try:
        query = db.query(ScanJob).filter(
            ScanJob.status.in_([ScanStatusEnum.RUNNING, ScanStatusEnum.PENDING])
        )
        try:
            candidates = query.with_for_update(skip_locked=True).all()
        except Exception:
            candidates = query.all()

        for job in candidates:
            recovered = False
            if job.status == ScanStatusEnum.RUNNING:
                ref_time = job.started_at or job.created_at
                if ref_time is not None:
                    if ref_time.tzinfo is None:
                        ref_time = ref_time.replace(tzinfo=timezone.utc)
                    age = (now - ref_time).total_seconds()
                    if age >= max_age_seconds:
                        if job.can_transition_to(ScanStatusEnum.FAILED):
                            job.transition_to(ScanStatusEnum.FAILED, timestamp=now)
                            job.error_message = (
                                f"[STALE_JOB_TIMEOUT] Scan exceeded maximum wall-clock execution threshold of "
                                f"{int(max_age_seconds)}s and was marked failed by recovery"
                            )
                            recovered = True
            elif job.status == ScanStatusEnum.PENDING:
                ref_time = job.created_at
                if ref_time is not None:
                    if ref_time.tzinfo is None:
                        ref_time = ref_time.replace(tzinfo=timezone.utc)
                    age = (now - ref_time).total_seconds()
                    if age >= max_pending_age_seconds:
                        if job.can_transition_to(ScanStatusEnum.FAILED):
                            job.transition_to(ScanStatusEnum.FAILED, timestamp=now)
                            job.error_message = (
                                f"[STALE_JOB_TIMEOUT] Scan exceeded maximum queue wait threshold of "
                                f"{int(max_pending_age_seconds)}s and was marked failed by recovery"
                            )
                            recovered = True

            if recovered:
                recovered_count += 1

        if recovered_count > 0:
            db.commit()
            logger.info("Recovered %d stale scan(s)", recovered_count)
    except Exception as exc:
        logger.error("Error during stale scan recovery: %s", exc)
        if db is not None:
            try:
                db.rollback()
            except Exception:
                pass
        raise
    finally:
        if own_session and db is not None:
            db.close()

    return recovered_count


@celery_app.task(name="app.worker.tasks.recover_stale_scans_task")
def recover_stale_scans_task() -> int:
    """Periodic Celery task for recovering orphaned/stale scans."""
    return recover_stale_scans()

