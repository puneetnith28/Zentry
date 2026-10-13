from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = (
        "postgresql://postgres:securepassword123@localhost:5432/security_scanner"
    )
    celery_broker_url: str = "redis://localhost:6379/0"
    api_key: str | None = None
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
    ]
    cors_allow_methods: list[str] = ["GET", "POST", "OPTIONS"]
    cors_allow_headers: list[str] = [
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
    ]
    block_private_targets: bool = True
    outbound_proxy_url: str | None = None
    outbound_trust_env: bool = False
    jwt_secret_key: str = "zentry-dev-insecure-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24
    max_request_body_bytes: int = 64 * 1024
    rate_limit_enabled: bool = True
    auth_rate_limit_per_minute: int = 10
    scan_rate_limit_per_minute: int = 20
    max_active_scans_per_user: int = 3
    global_scan_timeout_seconds: float = 180.0
    module_scan_timeout_seconds: float = 60.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
