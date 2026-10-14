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


class StructuredJSONFormatter(logging.Formatter):
    """
    Format log records as structured single-line JSON objects with ISO timestamps,
    log levels, logger names, message bodies, caller locations, and diagnostic metadata.
    """

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone

        record_dict: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "caller": {
                "module": record.module,
                "function": record.funcName,
                "line": record.lineno,
            },
        }

        if hasattr(record, "request_id"):
            record_dict["request_id"] = getattr(record, "request_id")

        if record.exc_info:
            record_dict["exception"] = self.formatException(record.exc_info)

        standard_attrs = {
            "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
            "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
            "created", "msecs", "relativeCreated", "thread", "threadName",
            "processName", "process", "message", "request_id", "caller", "exception",
        }
        for k, v in record.__dict__.items():
            if k not in standard_attrs and not k.startswith("_"):
                if str(k).lower().strip() in SENSITIVE_BODY_KEYS:
                    record_dict[k] = REDACTED_VALUE
                else:
                    record_dict[k] = redact_sensitive_data(v)

        return json.dumps(record_dict, default=str)



def configure_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Configure root logger with either structured JSON or standard text log formatting."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(StructuredJSONFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s")
        )
    root_logger.handlers = [handler]

