"""
Integration tests for the FastAPI application.

Tests real HTTP endpoints using FastAPI's TestClient.
Database calls are mocked — no PostgreSQL required for these tests.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a TestClient for the FastAPI app."""
    with patch("backend.models.database.check_connection", return_value=True), \
         patch("backend.models.database.create_tables"):
        from backend.main import app
        with TestClient(app) as c:
            yield c


@pytest.mark.integration
class TestHealthEndpoint:
    """Tests for GET /health"""

    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_returns_json(self, client):
        response = client.get("/health")
        data = response.json()
        assert isinstance(data, dict)

    def test_health_has_status_key(self, client):
        response = client.get("/health")
        assert "status" in response.json()

    def test_health_has_version(self, client):
        response = client.get("/health")
        assert "version" in response.json()

    def test_health_version_format(self, client):
        response = client.get("/health")
        version = response.json()["version"]
        parts = version.split(".")
        assert len(parts) == 3

    def test_health_has_database_key(self, client):
        response = client.get("/health")
        assert "database" in response.json()

    def test_health_db_connected(self, client):
        """With mocked DB, health should report True."""
        response = client.get("/health")
        assert response.json()["database"] is True


@pytest.mark.integration
class TestRootEndpoint:
    """Tests for GET /"""

    def test_root_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_root_has_name(self, client):
        response = client.get("/")
        assert "name" in response.json()

    def test_root_name_is_reconxploit(self, client):
        response = client.get("/")
        assert "ReconXploit" in response.json()["name"]

    def test_root_has_docs_link(self, client):
        response = client.get("/")
        assert "docs" in response.json()

    def test_root_docs_points_to_docs(self, client):
        response = client.get("/")
        assert response.json()["docs"] == "/docs"


@pytest.mark.integration
class TestOpenAPIDocumentation:
    """Tests that FastAPI auto-documentation is available."""

    def test_openapi_json_accessible(self, client):
        response = client.get("/openapi.json")
        assert response.status_code == 200

    def test_openapi_has_info(self, client):
        response = client.get("/openapi.json")
        assert "info" in response.json()

    def test_openapi_title_is_reconxploit(self, client):
        response = client.get("/openapi.json")
        assert "ReconXploit" in response.json()["info"]["title"]

    def test_docs_endpoint_accessible(self, client):
        response = client.get("/docs")
        assert response.status_code == 200


@pytest.mark.integration
class TestNotFoundRoutes:
    """Tests for routes that don't exist."""

    def test_unknown_route_returns_404(self, client):
        response = client.get("/does-not-exist")
        assert response.status_code == 404

    def test_unknown_api_route_returns_404(self, client):
        response = client.get("/api/v1/nonexistent")
        assert response.status_code == 404
