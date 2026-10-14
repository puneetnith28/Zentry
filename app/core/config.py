from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = Field(
        default="postgresql://postgres:securepassword123@localhost:5432/security_scanner",
        description="PostgreSQL connection URL.",
    )
    celery_broker_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis broker URL for Celery background tasks.",
    )
    api_key: str | None = Field(
        default=None,
        description="Legacy API key (deprecated in favor of JWT authentication).",
    )
    cors_origins: list[str] = Field(
        default=[
            "http://localhost:3000",
            "http://localhost:5173",
            "http://localhost:8000",
        ],
        description="Allowed CORS origins for browser clients.",
    )
    cors_allow_methods: list[str] = Field(
        default=["GET", "POST", "OPTIONS"],
        description="Allowed HTTP methods for CORS requests.",
    )
    cors_allow_headers: list[str] = Field(
        default=[
            "Authorization",
            "Content-Type",
            "Accept",
            "Origin",
            "X-Requested-With",
        ],
        description="Allowed HTTP headers for CORS requests.",
    )
    block_private_targets: bool = Field(
        default=True,
        description="Enforce outbound policy blocking private, loopback, and cloud metadata targets.",
    )
    outbound_proxy_url: str | None = Field(
        default=None,
        description="Optional upstream HTTP/HTTPS proxy URL for outbound scanning.",
    )
    outbound_trust_env: bool = Field(
        default=False,
        description="Whether to trust ambient environment proxy settings (HTTP_PROXY, HTTPS_PROXY).",
    )
    jwt_secret_key: str = Field(
        default="zentry-dev-insecure-secret-key-change-in-production",
        description="Secret key used for signing and verifying JWT tokens.",
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="Cryptographic algorithm for JWT tokens (HS256).",
    )
    access_token_expire_minutes: int = Field(
        default=60 * 24,
        description="JWT access token validity duration in minutes (default 24 hours).",
    )
    max_request_body_bytes: int = Field(
        default=64 * 1024,
        description="Maximum allowed HTTP request body size in bytes (default 64 KB = 65536 bytes).",
    )
    rate_limit_enabled: bool = Field(
        default=True,
        description="Toggle sliding-window rate limiting on API endpoints.",
    )
    auth_rate_limit_per_minute: int = Field(
        default=10,
        description="Maximum authentication attempts (login/register) allowed per minute per client IP.",
    )
    scan_rate_limit_per_minute: int = Field(
        default=20,
        description="Maximum scan creation requests allowed per minute per client IP.",
    )
    max_active_scans_per_user: int = Field(
        default=3,
        description="Maximum concurrent active (PENDING or RUNNING) scans allowed per standard user.",
    )
    global_scan_timeout_seconds: float = Field(
        default=180.0,
        description="Hard wall-clock timeout in seconds for an entire scan job execution.",
    )
    module_scan_timeout_seconds: float = Field(
        default=60.0,
        description="Hard wall-clock timeout in seconds for an individual scanner module.",
    )
    stale_scan_threshold_seconds: float = Field(
        default=300.0,
        ge=60.0,
        description="Wall-clock threshold in seconds after which active scans are considered orphaned and recovered as FAILED.",
    )
    max_queue_depth: int = Field(
        default=100,
        description="Maximum Celery queue depth threshold before rejecting submissions with 503 backpressure.",
    )
    db_pool_size: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Database connection pool size.",
    )
    db_max_overflow: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Maximum overflow connections allowed beyond db_pool_size.",
    )
    db_pool_timeout: float = Field(
        default=30.0,
        ge=1.0,
        description="Seconds to wait before timing out on connection checkout from pool.",
    )
    db_pool_recycle_seconds: int = Field(
        default=1800,
        ge=60,
        description="Recycle connections after this duration in seconds to prevent stale TCP sockets.",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
