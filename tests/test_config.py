import os
from pathlib import Path
import pytest

from app.core.config import Settings


def test_settings_defaults():
    settings = Settings()
    assert settings.max_request_body_bytes == 65536
    assert settings.rate_limit_enabled is True
    assert settings.auth_rate_limit_per_minute == 10
    assert settings.scan_rate_limit_per_minute == 20
    assert settings.max_active_scans_per_user == 3
    assert settings.global_scan_timeout_seconds == 180.0
    assert settings.module_scan_timeout_seconds == 60.0
    assert settings.max_queue_depth == 100
    assert settings.jwt_algorithm == "HS256"
    assert settings.db_pool_size == 10
    assert settings.db_max_overflow == 20
    assert settings.db_pool_timeout == 30.0
    assert settings.db_pool_recycle_seconds == 1800


def test_settings_environment_variable_overrides(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "131072")
    monkeypatch.setenv("AUTH_RATE_LIMIT_PER_MINUTE", "25")
    monkeypatch.setenv("SCAN_RATE_LIMIT_PER_MINUTE", "50")
    monkeypatch.setenv("MAX_ACTIVE_SCANS_PER_USER", "5")
    monkeypatch.setenv("GLOBAL_SCAN_TIMEOUT_SECONDS", "300.0")
    monkeypatch.setenv("MODULE_SCAN_TIMEOUT_SECONDS", "90.0")
    monkeypatch.setenv("MAX_QUEUE_DEPTH", "250")
    monkeypatch.setenv("DB_POOL_SIZE", "15")
    monkeypatch.setenv("DB_MAX_OVERFLOW", "30")
    monkeypatch.setenv("DB_POOL_TIMEOUT", "45.0")
    monkeypatch.setenv("DB_POOL_RECYCLE_SECONDS", "3600")

    settings = Settings()
    assert settings.max_request_body_bytes == 131072
    assert settings.auth_rate_limit_per_minute == 25
    assert settings.scan_rate_limit_per_minute == 50
    assert settings.max_active_scans_per_user == 5
    assert settings.global_scan_timeout_seconds == 300.0
    assert settings.module_scan_timeout_seconds == 90.0
    assert settings.max_queue_depth == 250
    assert settings.db_pool_size == 15
    assert settings.db_max_overflow == 30
    assert settings.db_pool_timeout == 45.0
    assert settings.db_pool_recycle_seconds == 3600


def test_env_example_matches_settings():
    env_example_path = Path(__file__).resolve().parent.parent / ".env.example"
    assert env_example_path.exists(), ".env.example file must exist in project root"
    content = env_example_path.read_text()

    required_keys = [
        "DATABASE_URL",
        "CELERY_BROKER_URL",
        "DB_POOL_SIZE",
        "DB_MAX_OVERFLOW",
        "DB_POOL_TIMEOUT",
        "DB_POOL_RECYCLE_SECONDS",
        "JWT_SECRET_KEY",
        "JWT_ALGORITHM",
        "ACCESS_TOKEN_EXPIRE_MINUTES",
        "CORS_ORIGINS",
        "BLOCK_PRIVATE_TARGETS",
        "MAX_REQUEST_BODY_BYTES",
        "RATE_LIMIT_ENABLED",
        "AUTH_RATE_LIMIT_PER_MINUTE",
        "SCAN_RATE_LIMIT_PER_MINUTE",
        "MAX_ACTIVE_SCANS_PER_USER",
        "GLOBAL_SCAN_TIMEOUT_SECONDS",
        "MODULE_SCAN_TIMEOUT_SECONDS",
        "MAX_QUEUE_DEPTH",
    ]
    for key in required_keys:
        assert f"{key}=" in content, f"Key {key} missing from .env.example"
