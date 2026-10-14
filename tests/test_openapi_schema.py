import pytest
from app.main import app


def test_openapi_schema_generation():
    schema = app.openapi()
    assert schema["info"]["title"] == "Zentry Security Scanner API"
    assert schema["info"]["version"] == "1.0.0"
    assert "components" in schema
    assert "securitySchemes" in schema["components"]
    assert "BearerAuth" in schema["components"]["securitySchemes"]
    assert "ApiKeyAuth" in schema["components"]["securitySchemes"]
    assert len(schema["tags"]) >= 4

    paths = schema["paths"]
    assert "/api/v1/auth/login" in paths
    assert "/api/v1/auth/register" in paths
    assert "/api/v1/scans/" in paths
    assert "/api/v1/reports/{scan_id}/pdf" in paths
    assert "/health" in paths


