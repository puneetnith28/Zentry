from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.core.config import get_settings
from app.db.models import ScanJob, ScanStatusEnum
from app.db.session import SessionLocal
from app.services.common import summarize_findings
from app.services.headers import inspect_headers_async
from app.services.ports import scan_ports_async
from app.services.ssl import inspect_ssl_async
from app.services.subdomain import discover_subdomains_async
from app.services.technology import inspect_technology_async

logger = logging.getLogger(__name__)


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
        return {
            "status": "error",
            "error": {"code": "MODULE_EXCEPTION", "message": str(result)},
            "findings": [],
        }
    # Fallback for weird edge cases
    return {"status": "error", "error": {"code": "UNKNOWN", "message": "Unknown result"}}


async def _run_scan_modules(
    target: str,
    options: dict[str, Any],
    module_timeout: float,
) -> dict[str, Any]:
    """Dynamically construct and execute the scan tasks with per-module timeout bounds."""
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
) -> dict[str, Any]:
    """Execute scan modules subject to global wall-clock deadline."""
    return await asyncio.wait_for(
        _run_scan_modules(target, options, module_timeout),
        timeout=global_timeout,
    )


@celery_app.task(name="app.worker.tasks.scan_task", bind=True, max_retries=0)
def scan_task(self, scan_id: str, db: Session | None = None) -> None:
    """The main background worker process triggered when a new scan is created."""
    settings = get_settings()
    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True
    try:
        # Look up the scan job from the database
        job = db.get(ScanJob, uuid.UUID(scan_id))
        if job is None:
            logger.error("Scan job %s not found", scan_id)
            return

        # Mark as running so the frontend shows the progress spinner
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

        try:
            # Fire off the scan modules asynchronously subject to global wall-clock deadline
            modules = asyncio.run(
                _execute_scan_with_deadline(
                    job.target_url,
                    options,
                    global_timeout=global_timeout,
                    module_timeout=module_timeout,
                )
            )

            # Tally up the final score (critical, high, medium, etc.)
            summary = summarize_findings(modules)

            # Format the final JSON response for the database
            payload = {
                "target": job.target_url,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "modules": modules,
                "summary": summary,
            }
            job.result_payload = payload
            job.transition_to(ScanStatusEnum.COMPLETED)
            job.error_message = None
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("Scan %s timed out after %ss", scan_id, global_timeout)
            if job.can_transition_to(ScanStatusEnum.FAILED):
                job.transition_to(ScanStatusEnum.FAILED)
            job.error_message = (
                f"Scan exceeded maximum wall-clock execution budget of {int(global_timeout)}s"
            )
        except Exception as exc:
            # Catastrophic failure outside the module try/catch
            logger.exception("Scan %s failed", scan_id)
            if job.can_transition_to(ScanStatusEnum.FAILED):
                job.transition_to(ScanStatusEnum.FAILED)
            job.error_message = str(exc)

        # Save the final results to Postgres
        db.commit()
    finally:
        # Always clean up the database connection if created here
        if own_session:
            db.close()
