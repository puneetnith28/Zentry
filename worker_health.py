"""
Worker Health Probe for Docker Container Liveness Monitoring.

Queries Celery inspect API (ping/stats) to determine if active Celery worker processes
are responsive. Exits with 0 if healthy, or 1 if unresponsive or unreachable.
"""

from __future__ import annotations

import logging
import sys

from app.core.celery_app import celery_app

logger = logging.getLogger("worker_health")


def check_worker_health(timeout: float = 5.0) -> bool:
    """
    Ping Celery worker node(s) via the control inspect API.
    Returns True if at least one worker responds with 'pong' or valid stats.
    """
    try:
        insp = celery_app.control.inspect(timeout=timeout)
        ping_res = insp.ping()
        if ping_res and isinstance(ping_res, dict):
            for worker_name, res in ping_res.items():
                if isinstance(res, dict) and res.get("ok") == "pong":
                    return True
                elif res == "pong":
                    return True

        # Fallback to inspecting stats if ping response format differs
        stats = insp.stats()
        if stats and isinstance(stats, dict) and len(stats) > 0:
            return True

        return False
    except Exception as exc:
        logger.error("Worker health check probe failed: %s", exc)
        return False


def main() -> None:
    if check_worker_health():
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
