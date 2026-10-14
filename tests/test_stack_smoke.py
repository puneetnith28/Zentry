import json
import urllib.request
import pytest
from app.core.config import get_settings


@pytest.mark.security
def test_stack_health_endpoint():
    """Verify application health probe returns healthy status for both DB and broker."""
    settings = get_settings()
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["components"]["database"]["status"] == "healthy"
    assert data["components"]["broker"]["status"] == "healthy"


def test_cors_headers_on_health():
    """Verify security headers and allowed origin headers."""
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.options(
        "/health",
        headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"


def test_api_docs_available():
    """Verify OpenAPI documentation and json schema endpoints are operational."""
    from app.main import app
    from fastapi.testclient import TestClient

    client = TestClient(app)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert "paths" in schema
    assert "/health" in schema["paths"]
