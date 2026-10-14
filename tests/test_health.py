from unittest.mock import MagicMock, patch
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

