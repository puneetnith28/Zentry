from __future__ import annotations

import logging
from typing import Any, Mapping

logger = logging.getLogger(__name__)

SENSITIVE_HEADER_KEYS: frozenset[str] = frozenset({
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
})

SENSITIVE_BODY_KEYS: frozenset[str] = frozenset({
    "password",
    "new_password",
    "old_password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "client_secret",
    "credentials",
})

REDACTED_VALUE: str = "[REDACTED]"


def redact_sensitive_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return a dictionary of headers with sensitive authorization/cookie values redacted."""
    cleaned: dict[str, str] = {}
    for k, v in headers.items():
        lower_k = k.lower().strip()
        if lower_k in SENSITIVE_HEADER_KEYS:
            cleaned[k] = REDACTED_VALUE
        else:
            cleaned[k] = v
    return cleaned


def redact_sensitive_data(data: Any) -> Any:
    """Recursively redact sensitive fields such as passwords and tokens from dictionaries/lists."""
    if isinstance(data, dict):
        cleaned: dict[str, Any] = {}
        for k, v in data.items():
            if str(k).lower().strip() in SENSITIVE_BODY_KEYS:
                cleaned[k] = REDACTED_VALUE
            else:
                cleaned[k] = redact_sensitive_data(v)
        return cleaned
    elif isinstance(data, list):
        return [redact_sensitive_data(item) for item in data]
    return data
