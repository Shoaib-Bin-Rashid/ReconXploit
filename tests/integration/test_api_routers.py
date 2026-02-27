"""
Tests for new FastAPI router endpoints (Targets, Scans, Vulns, Subdomains, Dashboard, Scheduler).
All DB calls are mocked — no PostgreSQL required.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    with patch("backend.models.database.check_connection", return_value=True), \
         patch("backend.models.database.create_tables"):
        from backend.main import app
        with TestClient(app) as c:
            yield c


# ─────────────────────────────────────────────
# Root + Health
# ─────────────────────────────────────────────

class TestRoot:
    def test_root_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_root_has_endpoints(self, client):
        data = r = client.get("/").json()
        assert "endpoints" in data
        assert "targets" in data["endpoints"]

    def test_health_200(self, client):
        r = client.get("/health")
        assert r.status_code in (200, 503)

    def test_health_has_status(self, client):
        r = client.get("/health")
        assert "status" in r.json()

    def test_docs_accessible(self, client):
        r = client.get("/docs")
        assert r.status_code == 200


# ─────────────────────────────────────────────
# Targets
# ─────────────────────────────────────────────

class TestTargetsRouter:
    @patch("backend.api.targets.get_db_context")
    def test_list_targets_empty(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.order_by.return_value\
               .offset.return_value.limit.return_value.all.return_value = []
        mock_db.query.return_value.order_by.return_value\
               .offset.return_value.limit.return_value.all.return_value = []
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/targets")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @patch("backend.api.targets.get_db_context")
    def test_create_target_409_duplicate(self, mock_ctx, client):
        mock_db = MagicMock()
        existing = MagicMock()
        existing.domain = "example.com"
        mock_db.query.return_value.filter.return_value.first.return_value = existing
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.post("/api/v1/targets", json={"domain": "example.com"})
        assert r.status_code == 409

    @patch("backend.api.targets.get_db_context")
    def test_get_target_404(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/targets/notexist.com")
        assert r.status_code == 404

    @patch("backend.api.targets.get_db_context")
    def test_delete_target_404(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.delete("/api/v1/targets/notexist.com")
        assert r.status_code == 404

    @patch("backend.api.targets.get_db_context")
    def test_update_target_invalid_status(self, mock_ctx, client):
        mock_db = MagicMock()
        target = MagicMock()
        target.id = "t1"
        target.domain = "example.com"
        target.status = "active"
        mock_db.query.return_value.filter.return_value.first.return_value = target
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.patch("/api/v1/targets/example.com", json={"status": "invalid_status"})
        assert r.status_code == 400

    def test_create_target_missing_domain(self, client):
        r = client.post("/api/v1/targets", json={})
        assert r.status_code == 422


# ─────────────────────────────────────────────
# Scans
# ─────────────────────────────────────────────

class TestScansRouter:
    @patch("backend.api.scans.get_db_context")
    def test_list_scans_empty(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.order_by.return_value\
               .offset.return_value.limit.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.order_by.return_value\
               .offset.return_value.limit.return_value.all.return_value = []
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/scans")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @patch("backend.api.scans.get_db_context")
    def test_trigger_scan_404_unknown_domain(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.post("/api/v1/scans", json={"domain": "unknown.com", "mode": "quick"})
        assert r.status_code == 404

    @patch("backend.api.scans.get_db_context")
    def test_get_scan_404(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/scans/nonexistent-scan-id")
        assert r.status_code == 404

    def test_trigger_scan_missing_domain(self, client):
        r = client.post("/api/v1/scans", json={})
        assert r.status_code == 422


# ─────────────────────────────────────────────
# Vulnerabilities
# ─────────────────────────────────────────────

class TestVulnsRouter:
    @patch("backend.api.vulnerabilities.get_db_context")
    def test_list_vulns_empty(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.order_by.return_value\
               .offset.return_value.limit.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.order_by.return_value\
               .offset.return_value.limit.return_value.all.return_value = []
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/vulns")
        assert r.status_code == 200

    @patch("backend.api.vulnerabilities.get_db_context")
    def test_vuln_stats(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/vulns/stats")
        assert r.status_code == 200
        data = r.json()
        assert "total" in data
        assert "critical" in data

    @patch("backend.api.vulnerabilities.get_db_context")
    def test_vuln_404(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/vulns/nonexistent-id")
        assert r.status_code == 404


# ─────────────────────────────────────────────
# Subdomains
# ─────────────────────────────────────────────

class TestSubdomainsRouter:
    @patch("backend.api.subdomains.get_db_context")
    def test_list_subdomains_empty(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.order_by.return_value\
               .offset.return_value.limit.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.order_by.return_value\
               .offset.return_value.limit.return_value.all.return_value = []
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/subdomains")
        assert r.status_code == 200

    @patch("backend.api.subdomains.get_db_context")
    def test_live_hosts_404_unknown_target(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/subdomains/target/notexist.com/live")
        assert r.status_code == 404


# ─────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────

class TestDashboardRouter:
    @patch("backend.api.dashboard.get_db_context")
    def test_overview_shape(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/dashboard/overview")
        assert r.status_code == 200
        data = r.json()
        for key in ("total_targets", "total_vulns", "critical_vulns", "scans_today"):
            assert key in data

    @patch("backend.api.dashboard.get_db_context")
    def test_recent_changes_list(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value\
               .order_by.return_value.limit.return_value.all.return_value = []
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/dashboard/recent-changes")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @patch("backend.api.dashboard.get_db_context")
    def test_top_risks_list(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/dashboard/top-risks")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    @patch("backend.api.dashboard.get_db_context")
    def test_activity_has_date_points(self, mock_ctx, client):
        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.count.return_value = 0
        mock_db.query.return_value.filter.return_value\
               .filter.return_value.count.return_value = 0
        mock_ctx.return_value.__enter__ = lambda s: mock_db
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        r = client.get("/api/v1/dashboard/activity?days=7")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)
        assert len(data) == 7
        assert "date" in data[0]


# ─────────────────────────────────────────────
# Scheduler
# ─────────────────────────────────────────────

class TestSchedulerRouter:
    def test_scheduler_status(self, client):
        r = client.get("/api/v1/scheduler/status")
        assert r.status_code == 200
        data = r.json()
        assert "total_targets" in data
        assert "running" in data

    def test_scheduler_targets_list(self, client):
        r = client.get("/api/v1/scheduler/targets")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_run_now_missing_domain(self, client):
        r = client.post("/api/v1/scheduler/run-now", json={})
        assert r.status_code == 422

    def test_add_scheduler_target_then_409(self, client):
        import time
        domain = f"scheduler-test-{int(time.time()*1000)}.com"
        # First add
        r1 = client.post("/api/v1/scheduler/targets", json={"domain": domain, "mode": "quick"})
        assert r1.status_code == 201
        # Second add → conflict
        r2 = client.post("/api/v1/scheduler/targets", json={"domain": domain, "mode": "quick"})
        assert r2.status_code == 409

    def test_update_scheduler_target_404(self, client):
        r = client.patch("/api/v1/scheduler/targets/totally-unknown-domain.com", json={"mode": "quick"})
        assert r.status_code == 404
