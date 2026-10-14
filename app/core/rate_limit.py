import math
from threading import Lock
import time
from collections import defaultdict

from fastapi import HTTPException, Request, status

from app.core.config import get_settings


class SlidingWindowRateLimiter:
    """In-memory thread-safe sliding window rate limiter."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._requests: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str, max_requests: int, window_seconds: float = 60.0) -> None:
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return

        now = time.monotonic()
        with self._lock:
            timestamps = self._requests[key]
            cutoff = now - window_seconds
            # Retain only timestamps within the sliding window
            self._requests[key] = [t for t in timestamps if t > cutoff]
            timestamps = self._requests[key]

            if len(timestamps) >= max_requests:
                earliest = timestamps[0]
                retry_after = max(1, math.ceil(earliest + window_seconds - now))
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Maximum {max_requests} requests per {int(window_seconds)}s.",
                    headers={"Retry-After": str(retry_after)},
                )

            self._requests[key].append(now)

    def clear(self) -> None:
        with self._lock:
            self._requests.clear()


from app.core.proxy import get_client_ip

limiter = SlidingWindowRateLimiter()


def rate_limit_login(request: Request) -> None:
    """Rate limit login requests by client host."""
    settings = get_settings()
    host = get_client_ip(request, settings)
    key = f"login:{host}"
    limiter.check(
        key=key,
        max_requests=settings.auth_rate_limit_per_minute,
        window_seconds=60.0,
    )


def rate_limit_scans(request: Request) -> None:
    """Rate limit scan submissions by authorization token or client host."""
    settings = get_settings()
    auth_header = request.headers.get("authorization", "")
    if auth_header:
        key = f"scan:auth:{auth_header}"
    else:
        host = get_client_ip(request, settings)
        key = f"scan:ip:{host}"

    limiter.check(
        key=key,
        max_requests=settings.scan_rate_limit_per_minute,
        window_seconds=60.0,
    )

