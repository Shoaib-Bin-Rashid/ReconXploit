"""
Integration tests for Phase 11 — structured error handlers in FastAPI.
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    with patch("backend.models.database.check_connection", return_value=True):
        from backend.main import app
        return TestClient(app, raise_server_exceptions=False)


class TestHTTPExceptionHandler:
    def test_404_has_error_shape(self, client):
        r = client.get("/api/v1/this-route-does-not-exist-anywhere")
        assert r.status_code == 404
        body = r.json()
        assert body["error"] is True
        assert body["status"] == 404
        assert "message" in body
        assert "path" in body

    def test_root_is_ok(self, client):
        r = client.get("/")
        assert r.status_code == 200


class TestValidationExceptionHandler:
    def test_validation_error_has_errors_array(self, client):
        # POST /targets requires a domain field; send empty JSON → 422
        r = client.post("/api/v1/targets", json={})
        assert r.status_code == 422
        body = r.json()
        assert body["error"] is True
        assert body["status"] == 422
        assert isinstance(body["errors"], list)
        assert len(body["errors"]) > 0
        err = body["errors"][0]
        assert "field" in err
        assert "message" in err

    def test_validation_error_has_path(self, client):
        r = client.post("/api/v1/targets", json={})
        body = r.json()
        assert "/api/v1/targets" in body["path"]


class TestHealthEndpoint:
    def test_health_returns_status_key(self, client):
        r = client.get("/health")
        body = r.json()
        assert "status" in body
        assert "database" in body
        assert "version" in body
