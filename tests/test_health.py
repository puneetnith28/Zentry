from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy.exc import OperationalError



def test_health_all_healthy(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["components"]["database"]["status"] == "healthy"
    assert data["components"]["broker"]["status"] == "healthy"


def test_health_database_failure(client):
    with patch("app.db.session.engine.connect") as mock_connect:
        mock_connect.side_effect = OperationalError("connection refused", None, None)
        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["components"]["database"]["status"] == "unhealthy"
        assert data["components"]["broker"]["status"] == "healthy"


def test_health_broker_failure(client):
    with patch("redis.Redis.from_url") as mock_redis:
        mock_instance = MagicMock()
        mock_instance.ping.side_effect = ConnectionError("redis unavailable")
        mock_redis.return_value = mock_instance

        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["components"]["database"]["status"] == "healthy"
        assert data["components"]["broker"]["status"] == "unhealthy"


def test_health_all_dependencies_failing(client):
    with patch("app.db.session.engine.connect") as mock_connect, \
         patch("redis.Redis.from_url") as mock_redis:
        mock_connect.side_effect = OperationalError("db down", None, None)
        mock_instance = MagicMock()
        mock_instance.ping.side_effect = ConnectionError("broker down")
        mock_redis.return_value = mock_instance

        response = client.get("/health")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["components"]["database"]["status"] == "unhealthy"
        assert data["components"]["broker"]["status"] == "unhealthy"


@pytest.mark.asyncio
async def test_lifespan_startup_and_graceful_shutdown():
    from app.main import app, lifespan

    with patch("app.main.init_db") as mock_init_db, \
         patch("app.db.session.dispose_db") as mock_dispose_db, \
         patch("app.core.celery_app.celery_app.close") as mock_celery_close, \
         patch("app.worker.tasks.recover_stale_scans"):
        async with lifespan(app):
            mock_init_db.assert_called_once()
            mock_dispose_db.assert_not_called()
            mock_celery_close.assert_not_called()

        mock_dispose_db.assert_called_once()
        mock_celery_close.assert_called_once()


