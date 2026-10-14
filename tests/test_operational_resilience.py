"""
Comprehensive Operational Resilience and Resource Exhaustion Test Suite.

Simulates infrastructure disconnections, broker outages, database failovers,
unbounded network streams, and graceful degradation under operational stress.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import httpx
import pytest
import redis
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.celery_app import celery_app, get_queue_depth
from app.core.config import get_settings
from app.core.outbound import (
    ResponseBodyTooLargeError,
    SafeStreamReader,
    parse_bounded_json,
)
from app.db.session import check_db_connectivity, create_app_engine, dispose_db, get_db
from app.main import app, lifespan


# ==============================================================================
# 1. Database Disconnection & Retry Resilience
# ==============================================================================

def test_database_connectivity_transient_failure_recovery():
    """Verify that transient database disconnects recover within max_retries without fatal crash."""
    with patch("app.db.session.time.sleep") as mock_sleep, \
         patch("app.db.session.engine.connect") as mock_connect:
        mock_conn = MagicMock()
        # Fail twice with OperationalError, then connect successfully on third attempt
        mock_connect.side_effect = [
            OperationalError("connection reset by peer", None, None),
            OperationalError("server closed the connection unexpectedly", None, None),
            MagicMock(__enter__=MagicMock(return_value=mock_conn), __exit__=MagicMock()),
        ]

        check_db_connectivity(max_retries=5, retry_interval=0.01)

        assert mock_connect.call_count == 3
        assert mock_sleep.call_count == 2
        mock_conn.execute.assert_called_once()


def test_database_operational_error_in_session_guarantees_rollback():
    """Verify that an OperationalError during database session execution triggers clean rollback."""
    with patch("app.db.session.SessionLocal") as mock_session_cls:
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        gen = get_db()
        db = next(gen)
        assert db == mock_session

        with pytest.raises(OperationalError):
            gen.throw(OperationalError("database node restart", None, None))

        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()


def test_database_engine_dispose_resilience():
    """Verify dispose_db handles clean disposal and logs any warning without raising."""
    with patch("app.db.session.engine.dispose") as mock_dispose:
        # Normal disposal
        dispose_db()
        mock_dispose.assert_called_once()

    # Disposal when engine raises an unexpected error
    with patch("app.db.session.engine.dispose") as mock_dispose:
        mock_dispose.side_effect = RuntimeError("engine already disposed")
        # Should not raise
        dispose_db()


# ==============================================================================
# 2. Redis Broker Disconnect & Backpressure Degradation
# ==============================================================================

def test_redis_disconnect_queue_depth_safe_degradation():
    """Verify get_queue_depth returns 0 gracefully when Redis broker is unreachable."""
    with patch("redis.Redis.from_url") as mock_redis_cls:
        mock_redis = MagicMock()
        mock_redis.llen.side_effect = redis.ConnectionError("Redis connection refused on 6379")
        mock_redis_cls.return_value = mock_redis

        depth = get_queue_depth("celery")
        assert depth == 0


def test_redis_timeout_queue_depth_safe_degradation():
    """Verify get_queue_depth handles socket timeout without hanging."""
    with patch("redis.Redis.from_url") as mock_redis_cls:
        mock_redis = MagicMock()
        mock_redis.llen.side_effect = redis.TimeoutError("Redis socket read timeout")
        mock_redis_cls.return_value = mock_redis

        depth = get_queue_depth("celery")
        assert depth == 0


# ==============================================================================
# 3. Health Probes Operational Degradation
# ==============================================================================

def test_health_probe_reports_503_when_database_disconnected(client):
    """Verify health endpoint reports HTTP 503 and accurate component status on database outage."""
    with patch("app.db.session.engine.connect") as mock_connect:
        mock_connect.side_effect = OperationalError("connection refused", None, None)
        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["components"]["database"]["status"] == "unhealthy"
        assert data["components"]["broker"]["status"] == "healthy"


def test_health_probe_reports_503_when_broker_disconnected(client):
    """Verify health endpoint reports HTTP 503 and accurate component status on Redis broker outage."""
    with patch("redis.Redis.from_url") as mock_redis_cls:
        mock_redis = MagicMock()
        mock_redis.ping.side_effect = redis.ConnectionError("connection refused")
        mock_redis_cls.return_value = mock_redis

        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["components"]["database"]["status"] == "healthy"
        assert data["components"]["broker"]["status"] == "unhealthy"


# ==============================================================================
# 4. Outbound Streaming & Payload Resource Hardening
# ==============================================================================

@pytest.mark.asyncio
async def test_streaming_decompression_bomb_resource_exhaustion_prevention():
    """Verify SafeStreamReader halts streaming before memory exhaustion on infinite stream."""
    async def infinite_chunk_generator():
        while True:
            yield b"0" * 16384  # 16 KB chunks

    reader = SafeStreamReader(max_bytes=64 * 1024)  # 64 KB limit
    with pytest.raises(ResponseBodyTooLargeError) as exc_info:
        await reader.read_all(stream=infinite_chunk_generator())

    assert "exceeded limit of 65536 bytes" in str(exc_info.value)
    # Ensure it halted promptly without consuming unbound memory
    assert reader.bytes_read <= 64 * 1024 + 16384


def test_external_response_oversized_payload_rejected_before_parsing():
    """Verify that oversized JSON responses are blocked before deserialization into memory."""
    oversized_body = b"[" + (b'{"key":"val"},' * 50000) + b'{"key":"val"}]'
    res = httpx.Response(
        status_code=200,
        content=oversized_body,
        headers={"content-length": str(len(oversized_body))},
    )

    with pytest.raises(ResponseBodyTooLargeError) as exc_info:
        parse_bounded_json(res, max_bytes=10000)

    assert "exceeds JSON parsing limit" in str(exc_info.value)


# ==============================================================================
# 5. Full Lifespan Graceful Startup and Shutdown Cycle
# ==============================================================================

@pytest.mark.asyncio
async def test_lifespan_graceful_shutdown_releases_all_resources():
    """Verify the entire application lifecycle starts up and cleanly tears down resources."""
    with patch("app.main.init_db") as mock_init_db, \
         patch("app.db.session.dispose_db") as mock_dispose_db, \
         patch("app.core.celery_app.celery_app.close") as mock_celery_close, \
         patch("app.worker.tasks.recover_stale_scans"):

        async with lifespan(app):
            mock_init_db.assert_called_once()
            mock_dispose_db.assert_not_called()
            mock_celery_close.assert_not_called()

        # After lifespan exits, shutdown cleanup handlers must execute
        mock_dispose_db.assert_called_once()
        mock_celery_close.assert_called_once()
