"""
Integration tests for Phase 6 — Change Detection.
Uses SQLite in-memory DB + tmp_path for snapshots.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from backend.modules.change_detection import ChangeDetector

# ─── Sample data ───────────────────────────────────────────

PREV_SNAPSHOT = {
    "domain": "example.com",
    "scan_id": "prev-scan",
    "timestamp": "2026-02-25T00:00:00",
    "subdomains": ["api.example.com"],
    "live_hosts": [
        {"url": "https://api.example.com", "status_code": 200, "server": "nginx", "waf": ""}
    ],
    "ports": [
        {"host": "1.2.3.4", "port": 80, "service": "http", "version": "nginx/1.18", "sensitive": False}
    ],
    "vulnerabilities": [],
    "js_findings": [],
}

CURRENT_DATA = {
    "subdomains":      ["api.example.com", "new.example.com"],
    "live_hosts":      [
        {"url": "https://api.example.com", "status_code": 200,
         "server_header": "nginx", "waf_detected": "Cloudflare"},
        {"url": "https://new.example.com",  "status_code": 200,
         "server_header": "Apache", "waf_detected": ""},
    ],
    "ports": [
        {"host": "1.2.3.4", "port": 80,   "service_name": "http",  "service_version": "nginx/1.20"},
        {"host": "1.2.3.4", "port": 3306, "service_name": "mysql", "service_version": "8.0"},
    ],
    "vulnerabilities": [
        {"template_id": "CVE-2021-44228", "matched_at": "https://api.example.com",
         "severity": "critical", "vulnerability_name": "Log4Shell"},
    ],
    "js_findings": [
        {"finding_type": "aws_access_key", "finding_value": "AKIAXXX", "risk_level": "critical"},
        {"finding_type": "admin_endpoint", "finding_value": "/admin",   "risk_level": "high"},
    ],
}


@pytest.mark.integration
class TestChangeDetectionDBStorage:

    def test_changes_stored_in_db(self, sqlite_session, tmp_path):
        from backend.models.models import Change, Target, Scan

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))

        cd = ChangeDetector("example.com", scan.id)
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch("backend.modules.change_detection.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            cd.run(CURRENT_DATA)

        stored = sqlite_session.query(Change).filter(Change.scan_id == scan.id).all()
        assert len(stored) > 0

    def test_significant_changes_flagged_in_db(self, sqlite_session, tmp_path):
        from backend.models.models import Change, Target, Scan

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))

        cd = ChangeDetector("example.com", scan.id)
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch("backend.modules.change_detection.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            cd.run(CURRENT_DATA)

        sig = sqlite_session.query(Change).filter(
            Change.scan_id == scan.id,
            Change.is_significant == True,
        ).all()
        assert len(sig) > 0

    def test_critical_vuln_change_has_correct_severity(self, sqlite_session, tmp_path):
        from backend.models.models import Change, Target, Scan

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))

        cd = ChangeDetector("example.com", scan.id)
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch("backend.modules.change_detection.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            cd.run(CURRENT_DATA)

        crit = sqlite_session.query(Change).filter(
            Change.scan_id == scan.id,
            Change.change_type == "new_vulnerability_critical",
        ).first()
        assert crit is not None
        assert crit.severity == "critical"

    def test_sensitive_port_change_stored(self, sqlite_session, tmp_path):
        from backend.models.models import Change, Target, Scan

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))

        cd = ChangeDetector("example.com", scan.id)
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch("backend.modules.change_detection.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            cd.run(CURRENT_DATA)

        mysql_change = sqlite_session.query(Change).filter(
            Change.scan_id == scan.id,
            Change.change_type == "new_sensitive_port",
        ).first()
        assert mysql_change is not None
        assert mysql_change.is_significant is True


@pytest.mark.integration
class TestChangeDetectionFileStorage:

    def test_file_storage_called_on_first_scan(self, tmp_path):
        snap_file = tmp_path / "snap.json"
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes") as mock_save, \
             patch.object(cd, "_store_changes", return_value=0):
            cd.run(CURRENT_DATA)
        mock_save.assert_called_once_with("example.com", [])

    def test_file_storage_called_on_second_scan(self, tmp_path):
        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))
        cd = ChangeDetector("example.com", "scan-002")
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes") as mock_save, \
             patch.object(cd, "_store_changes", return_value=0):
            cd.run(CURRENT_DATA)
        mock_save.assert_called_once()
        # Changes list passed should be non-empty
        saved_changes = mock_save.call_args[0][1]
        assert len(saved_changes) > 0

    def test_snapshot_updated_after_run(self, tmp_path):
        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))
        cd = ChangeDetector("example.com", "scan-new")
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch.object(cd, "_store_changes", return_value=0):
            cd.run(CURRENT_DATA)
        updated = json.loads(snap_file.read_text())
        assert updated["scan_id"] == "scan-new"
        assert "new.example.com" in updated["subdomains"]


@pytest.mark.integration
class TestPhase6Pipeline:

    def test_phase6_returns_changes(self):
        with patch("backend.modules.change_detection.ChangeDetector") as MockCD:
            instance = MagicMock()
            instance.run.return_value = 5
            instance.get_results.return_value = [
                {"change_type": "new_vulnerability_critical", "severity": "critical",
                 "is_significant": True, "asset_id": "CVE-2021-44228@https://x.com"},
                {"change_type": "new_sensitive_port", "severity": "high",
                 "is_significant": True, "asset_id": "1.2.3.4:3306"},
                {"change_type": "new_subdomain", "severity": "low",
                 "is_significant": False, "asset_id": "new.example.com"},
            ]
            instance.get_significant.return_value = [
                {"change_type": "new_vulnerability_critical", "severity": "critical",
                 "is_significant": True},
                {"change_type": "new_sensitive_port", "severity": "high",
                 "is_significant": True},
            ]
            MockCD.return_value = instance

            from reconxp import run_phase_changes
            results = run_phase_changes("example.com", "scan-123", {
                "subdomains": [], "live_hosts": [], "ports": [],
                "vulnerabilities": [], "js_findings": [],
            })

        assert len(results) == 3

    def test_phase6_first_scan_no_changes(self):
        with patch("backend.modules.change_detection.ChangeDetector") as MockCD:
            instance = MagicMock()
            instance.run.return_value = 0
            instance.get_results.return_value = []
            instance.get_significant.return_value = []
            MockCD.return_value = instance

            from reconxp import run_phase_changes
            results = run_phase_changes("example.com", "scan-123", {
                "subdomains": [], "live_hosts": [], "ports": [],
                "vulnerabilities": [], "js_findings": [],
            })

        assert results == []
