"""Tests for structured request logging and sensitive credential redaction."""

import logging
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.core.logging import (
    REDACTED_VALUE,
    redact_sensitive_data,
    redact_sensitive_headers,
)
from app.main import app

client = TestClient(app)


def test_redact_sensitive_headers():
    """Verify authorization, cookie, and api-key headers are sanitized."""
    raw_headers = {
        "Authorization": "Bearer secret-token-xyz123",
        "Cookie": "session_id=abcdef123456",
        "Set-Cookie": "auth_token=supersecret; Secure",
        "Proxy-Authorization": "Basic dXNlcjpwYXNz",
        "X-API-Key": "key-secret-999",
        "Content-Type": "application/json",
        "Host": "localhost",
        "User-Agent": "Mozilla/5.0",
    }

    sanitized = redact_sensitive_headers(raw_headers)

    assert sanitized["Authorization"] == REDACTED_VALUE
    assert sanitized["Cookie"] == REDACTED_VALUE
    assert sanitized["Set-Cookie"] == REDACTED_VALUE
    assert sanitized["Proxy-Authorization"] == REDACTED_VALUE
    assert sanitized["X-API-Key"] == REDACTED_VALUE
    assert sanitized["Content-Type"] == "application/json"
    assert sanitized["Host"] == "localhost"
    assert sanitized["User-Agent"] == "Mozilla/5.0"


def test_redact_sensitive_data_nested():
    """Verify sensitive fields in payloads are sanitized recursively."""
    payload = {
        "email": "user@example.com",
        "password": "SuperSecretPassword123!",
        "profile": {
            "name": "Alice",
            "access_token": "token-xyz",
            "refresh_token": "refresh-123",
        },
        "credentials": [
            {"secret": "api-secret-1"},
            {"public_key": "ssh-rsa AAAAB3..."},
        ],
    }

    sanitized = redact_sensitive_data(payload)

    assert sanitized["email"] == "user@example.com"
    assert sanitized["password"] == REDACTED_VALUE
    assert sanitized["profile"]["name"] == "Alice"
    assert sanitized["profile"]["access_token"] == REDACTED_VALUE
    assert sanitized["profile"]["refresh_token"] == REDACTED_VALUE
    assert sanitized["credentials"] == REDACTED_VALUE


def test_structured_request_logging_output(caplog):
    """Verify requests emit structured log records with correlation IDs and no leaked tokens."""
    token = "secret-bearer-jwt-token-777"
    with caplog.at_level(logging.INFO, logger="app.main"):
        response = client.get(
            "/health",
            headers={"Authorization": f"Bearer {token}", "X-Request-ID": "test-corr-id-123"},
        )
        assert response.status_code == 200

    # Ensure structured log messages were emitted
    started_logs = [r for r in caplog.records if "Request started:" in r.message]
    finished_logs = [r for r in caplog.records if "Request finished:" in r.message]

    assert len(started_logs) >= 1
    assert len(finished_logs) >= 1

    assert "test-corr-id-123" in started_logs[0].message
    assert "test-corr-id-123" in finished_logs[0].message
    assert "duration_ms=" in finished_logs[0].message

    # Crucial security check: Token must never appear anywhere in the captured log records
    for record in caplog.records:
        assert token not in record.message


def test_structured_json_formatter_valid_json():
    import json
    import logging
    from app.core.logging import StructuredJSONFormatter

    formatter = StructuredJSONFormatter()
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname="/app/test.py",
        lineno=42,
        msg="Sample log message with %s",
        args=("argument",),
        exc_info=None,
    )
    record.request_id = "req-12345"
    record.custom_field = "custom_value"
    record.password = "secret_pass"

    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test.logger"
    assert parsed["message"] == "Sample log message with argument"
    assert parsed["request_id"] == "req-12345"
    assert parsed["custom_field"] == "custom_value"
    assert parsed["password"] == "[REDACTED]"
    assert parsed["caller"]["line"] == 42
    assert "timestamp" in parsed

