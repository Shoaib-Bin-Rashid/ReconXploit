"""
Unit tests for backend/tasks/scan_tasks.py — Phase 12 Celery tasks.
All tests run eagerly (CELERY_TASK_ALWAYS_EAGER=True) without a real broker.
"""

import uuid
import pytest
from unittest.mock import patch, MagicMock, call
from datetime import datetime


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def no_db(monkeypatch):
    """Prevent any real DB calls."""
    monkeypatch.setattr(
        "backend.models.database.get_db_context",
        lambda: _NullCtx(),
    )


class _NullCtx:
    """Context manager that yields a mock DB session."""
    def __enter__(self):
        session = MagicMock()
        session.query.return_value.filter.return_value.first.return_value = None
        session.query.return_value.filter.return_value.all.return_value = []
        return session
    def __exit__(self, *args):
        pass


@pytest.fixture()
def scan_id():
    return str(uuid.uuid4())


@pytest.fixture()
def domain():
    return "example.com"


# ──────────────────────────────────────────────────────────────────────────────
# PHASE_PROGRESS constants
# ──────────────────────────────────────────────────────────────────────────────

class TestPhaseProgress:
    def test_all_phases_present(self):
        from backend.tasks.scan_tasks import PHASE_PROGRESS
        expected = {"discovery", "validation", "ports", "vulns", "js", "changes", "risk", "alerts", "screenshots"}
        assert expected == set(PHASE_PROGRESS.keys())

    def test_progress_values_in_range(self):
        from backend.tasks.scan_tasks import PHASE_PROGRESS
        for phase, val in PHASE_PROGRESS.items():
            assert 0 <= val <= 100, f"{phase} has out-of-range progress {val}"

    def test_discovery_before_screenshots(self):
        from backend.tasks.scan_tasks import PHASE_PROGRESS
        assert PHASE_PROGRESS["discovery"] < PHASE_PROGRESS["screenshots"]


# ──────────────────────────────────────────────────────────────────────────────
# _set_status helper
# ──────────────────────────────────────────────────────────────────────────────

class TestSetStatus:
    def test_does_not_raise_when_scan_not_found(self, scan_id):
        from backend.tasks.scan_tasks import _set_status
        _set_status(scan_id, "running")  # scan returns None from mock — should not raise

    def test_does_not_raise_on_completed(self, scan_id):
        from backend.tasks.scan_tasks import _set_status
        _set_status(scan_id, "completed", stats={"subdomains_found": 10})

    def test_does_not_raise_on_failed(self, scan_id):
        from backend.tasks.scan_tasks import _set_status
        _set_status(scan_id, "failed", error="something went wrong")

    def test_updates_existing_scan(self, scan_id):
        mock_scan = MagicMock()
        mock_scan.start_time = datetime(2024, 1, 1, 0, 0, 0)

        class _Ctx:
            def __enter__(self):
                s = MagicMock()
                s.query.return_value.filter.return_value.first.return_value = mock_scan
                return s
            def __exit__(self, *a): pass

        with patch("backend.tasks.scan_tasks.get_db_context", _Ctx):
            from backend.tasks.scan_tasks import _set_status
            _set_status(scan_id, "completed", stats={"x": 1})

        assert mock_scan.status == "completed"
        assert mock_scan.stats == {"x": 1}


# ──────────────────────────────────────────────────────────────────────────────
# _build_scan_data helper
# ──────────────────────────────────────────────────────────────────────────────

class TestBuildScanData:
    def test_returns_dict_with_required_keys(self, scan_id, domain):
        from backend.tasks.scan_tasks import _build_scan_data
        stats = {"subdomains_found": 5}
        data = _build_scan_data(scan_id, domain, stats)
        assert data["domain"] == domain
        assert data["stats"] == stats
        assert "vulnerabilities" in data
        assert "ports" in data
        assert "js_findings" in data
        assert "changes" in data

    def test_returns_lists_when_db_empty(self, scan_id, domain):
        from backend.tasks.scan_tasks import _build_scan_data
        data = _build_scan_data(scan_id, domain, {})
        assert isinstance(data["vulnerabilities"], list)
        assert isinstance(data["ports"], list)


# ──────────────────────────────────────────────────────────────────────────────
# _progress helper
# ──────────────────────────────────────────────────────────────────────────────

class TestProgress:
    def test_calls_update_state(self, domain):
        from backend.tasks.scan_tasks import _progress
        mock_task = MagicMock()
        _progress(mock_task, "discovery", domain)
        mock_task.update_state.assert_called_once()
        call_kwargs = mock_task.update_state.call_args[1]
        assert call_kwargs["state"] == "PROGRESS"
        assert call_kwargs["meta"]["phase"] == "discovery"
        assert call_kwargs["meta"]["domain"] == domain

    def test_does_not_raise_on_update_state_error(self, domain):
        from backend.tasks.scan_tasks import _progress
        mock_task = MagicMock()
        mock_task.update_state.side_effect = RuntimeError("no broker")
        _progress(mock_task, "discovery", domain)  # should not raise


# ──────────────────────────────────────────────────────────────────────────────
# run_full_scan task
# ──────────────────────────────────────────────────────────────────────────────

class TestRunFullScan:
    def _mock_all_modules(self):
        """Return a dict of patches for all 9 phase modules."""
        patches = {}
        modules = {
            "backend.modules.discovery.SubdomainDiscovery": MagicMock(return_value=MagicMock(run=MagicMock(return_value=10))),
            "backend.modules.validation.LiveHostValidator": MagicMock(return_value=MagicMock(
                run=MagicMock(return_value=5),
                get_live_urls=MagicMock(return_value=[{"url": "http://sub.example.com"}])
            )),
            "backend.modules.port_scan.PortScanner": MagicMock(return_value=MagicMock(run=MagicMock(return_value=3))),
            "backend.modules.vuln_scan.VulnerabilityScanner": MagicMock(return_value=MagicMock(run=MagicMock(return_value=2))),
            "backend.modules.js_analysis.JsAnalyzer": MagicMock(return_value=MagicMock(run=MagicMock(return_value=4))),
            "backend.modules.change_detection.ChangeDetector": MagicMock(return_value=MagicMock(run=MagicMock(return_value=1))),
            "backend.modules.risk_scoring.RiskScorer": MagicMock(return_value=MagicMock(run=MagicMock(return_value=55))),
            "backend.modules.alerts.AlertManager": MagicMock(return_value=MagicMock(run=MagicMock(return_value=None))),
            "backend.modules.screenshots.ScreenshotEngine": MagicMock(return_value=MagicMock(run=MagicMock(return_value=5))),
        }
        return modules

    def test_returns_stats_dict(self, scan_id, domain):
        from backend.tasks.scan_tasks import run_full_scan
        with patch("backend.tasks.scan_tasks._set_status"), \
             patch("backend.tasks.scan_tasks._progress"):
            result = run_full_scan.apply(args=[scan_id, domain, "quick", []]).result
        assert isinstance(result, dict)
        assert "subdomains_found" in result

    def test_sets_running_then_completed_on_success(self, scan_id, domain):
        status_calls = []
        def track_status(sid, status, **kw):
            status_calls.append(status)

        from backend.tasks.scan_tasks import run_full_scan
        with patch("backend.tasks.scan_tasks._set_status", side_effect=track_status), \
             patch("backend.tasks.scan_tasks._progress"):
            run_full_scan.apply(args=[scan_id, domain, "quick", []]).result

        assert status_calls[0] == "running"
        assert "completed" in status_calls

    def test_sets_failed_on_exception(self, scan_id, domain):
        status_calls = []
        def track_status(sid, status, **kw):
            status_calls.append(status)

        from backend.tasks.scan_tasks import run_full_scan
        with patch("backend.tasks.scan_tasks._set_status", side_effect=track_status), \
             patch("backend.tasks.scan_tasks._progress"), \
             patch(
                 "backend.modules.discovery.SubdomainDiscovery",
                 side_effect=RuntimeError("tool exploded")
             ):
            with pytest.raises(RuntimeError):
                run_full_scan.apply(args=[scan_id, domain, "full", ["discovery"]]).result

        assert "failed" in status_calls

    def test_skip_phases_not_in_list(self, scan_id, domain):
        from backend.tasks.scan_tasks import run_full_scan

        # DB must return subdomains so validation phase proceeds
        mock_sub = MagicMock()
        mock_sub.subdomain = "sub.example.com"

        class _SubCtx:
            def __enter__(self):
                s = MagicMock()
                s.query.return_value.filter.return_value.first.return_value = None
                s.query.return_value.filter.return_value.all.return_value = [mock_sub]
                return s
            def __exit__(self, *a): pass

        mock_validator = MagicMock()
        mock_validator.run.return_value = 1
        mock_validator.get_live_urls.return_value = [{"url": "http://example.com"}]

        with patch("backend.tasks.scan_tasks._set_status"), \
             patch("backend.tasks.scan_tasks._progress"), \
             patch("backend.tasks.scan_tasks.get_db_context", lambda: _SubCtx()), \
             patch("backend.modules.validation.LiveHostValidator", return_value=mock_validator):
            with patch("backend.modules.port_scan.PortScanner") as mock_ps:
                mock_ps.return_value.run.return_value = 2
                run_full_scan.apply(args=[scan_id, domain, "custom", ["validation", "ports"]]).result
            mock_ps.assert_called_once()

    def test_all_phases_flag_runs_discovery(self, scan_id, domain):
        from backend.tasks.scan_tasks import run_full_scan
        with patch("backend.tasks.scan_tasks._set_status"), \
             patch("backend.tasks.scan_tasks._progress"), \
             patch("backend.tasks.scan_tasks._build_scan_data", return_value={}):
            with patch("backend.modules.discovery.SubdomainDiscovery") as mock_disc:
                mock_disc.return_value.run.return_value = 5
                # None → phases defaults to ["all"]
                run_full_scan.apply(args=[scan_id, domain, "full", None]).result
            mock_disc.assert_called_once_with(domain, scan_id)


# ──────────────────────────────────────────────────────────────────────────────
# check_scheduled_scans beat task
# ──────────────────────────────────────────────────────────────────────────────

class TestCheckScheduledScans:
    def test_runs_without_error_when_no_targets(self):
        from backend.tasks.scan_tasks import check_scheduled_scans
        mock_state = MagicMock()
        mock_state.all.return_value = {}
        with patch("backend.modules.scheduler.SchedulerState", return_value=mock_state):
            check_scheduled_scans.apply().result  # should not raise

    def test_skips_disabled_targets(self):
        from backend.tasks.scan_tasks import check_scheduled_scans
        mock_state = MagicMock()
        mock_state.all.return_value = {
            "disabled.com": {"status": "disabled", "next_run": "2000-01-01T00:00:00"}
        }
        with patch("backend.modules.scheduler.SchedulerState", return_value=mock_state), \
             patch("backend.tasks.scan_tasks.run_full_scan") as mock_rfs:
            check_scheduled_scans.apply().result
        mock_rfs.delay.assert_not_called()

    def test_skips_targets_with_no_next_run(self):
        from backend.tasks.scan_tasks import check_scheduled_scans
        mock_state = MagicMock()
        mock_state.all.return_value = {
            "example.com": {"status": "active", "next_run": None}
        }
        with patch("backend.modules.scheduler.SchedulerState", return_value=mock_state), \
             patch("backend.tasks.scan_tasks.run_full_scan") as mock_rfs:
            check_scheduled_scans.apply().result
        mock_rfs.delay.assert_not_called()

    def test_skips_targets_not_yet_due(self):
        from backend.tasks.scan_tasks import check_scheduled_scans
        future = "2099-12-31T23:59:59"
        mock_state = MagicMock()
        mock_state.all.return_value = {
            "example.com": {"status": "active", "next_run": future}
        }
        with patch("backend.modules.scheduler.SchedulerState", return_value=mock_state), \
             patch("backend.tasks.scan_tasks.run_full_scan") as mock_rfs:
            check_scheduled_scans.apply().result
        mock_rfs.delay.assert_not_called()
