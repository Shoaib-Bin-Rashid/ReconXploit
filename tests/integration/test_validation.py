"""
Integration tests for Phase 2 — Live Host Validation.
Uses SQLite in-memory DB. All subprocess calls mocked.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

SAMPLE_OUTPUT = "\n".join([
    json.dumps({
        "url": "https://api.example.com", "status_code": 200,
        "title": "API Portal", "webserver": "nginx",
        "host_ip": "93.184.216.34", "content_length": 1024,
        "time": "64ms", "tech": ["Nginx"],
        "cdn": False, "cdn_name": "", "cdn_type": "",
    }),
    json.dumps({
        "url": "https://admin.example.com", "status_code": 401,
        "title": "Admin Panel", "webserver": "Apache",
        "host_ip": "93.184.216.35", "content_length": 256,
        "time": "120ms", "tech": ["Apache", "PHP"],
        "cdn": True, "cdn_name": "cloudflare", "cdn_type": "cdn",
    }),
]) + "\n"


@pytest.mark.integration
class TestLiveHostDBStorage:

    def test_live_hosts_stored_in_db(self, sqlite_session):
        from backend.modules.validation import LiveHostValidator
        from backend.models.models import LiveHost, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        validator = LiveHostValidator("example.com", scan.id)

        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.validation.save_live_hosts"), \
             patch("backend.modules.validation.get_db_context") as mock_ctx:
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_OUTPUT, stderr="")
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            validator.run(["api.example.com", "admin.example.com"])

        stored = sqlite_session.query(LiveHost).filter(LiveHost.scan_id == scan.id).all()
        assert len(stored) == 2

    def test_live_host_fields_correct(self, sqlite_session):
        from backend.modules.validation import LiveHostValidator
        from backend.models.models import LiveHost, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        single = json.dumps({
            "url": "https://api.example.com", "status_code": 200,
            "title": "API Portal", "webserver": "nginx",
            "host_ip": "1.2.3.4", "content_length": 512,
            "time": "50ms", "tech": ["Nginx"],
            "cdn": False, "cdn_name": "", "cdn_type": "",
        }) + "\n"

        validator = LiveHostValidator("example.com", scan.id)
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.validation.save_live_hosts"), \
             patch("backend.modules.validation.get_db_context") as mock_ctx:
            mock_run.return_value = MagicMock(returncode=0, stdout=single, stderr="")
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            validator.run(["api.example.com"])

        host = sqlite_session.query(LiveHost).filter(
            LiveHost.url == "https://api.example.com"
        ).first()
        assert host.status_code == 200
        assert host.title == "API Portal"
        assert host.server_header == "nginx"

    def test_no_duplicates_in_same_scan(self, sqlite_session):
        from backend.modules.validation import LiveHostValidator
        from backend.models.models import LiveHost, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        same_line = json.dumps({
            "url": "https://api.example.com", "status_code": 200,
            "title": "API", "webserver": "nginx", "host_ip": "1.2.3.4",
            "content_length": 100, "time": "10ms", "tech": [],
            "cdn": False, "cdn_name": "", "cdn_type": "",
        })
        double = f"{same_line}\n{same_line}\n"

        validator = LiveHostValidator("example.com", scan.id)
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.validation.save_live_hosts"), \
             patch("backend.modules.validation.get_db_context") as mock_ctx:
            mock_run.return_value = MagicMock(returncode=0, stdout=double, stderr="")
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            validator.run(["api.example.com"])

        hosts = sqlite_session.query(LiveHost).filter(
            LiveHost.url == "https://api.example.com"
        ).all()
        assert len(hosts) == 1


@pytest.mark.integration
class TestPhase2Pipeline:

    def test_phase2_returns_results(self):
        with patch("backend.modules.validation.LiveHostValidator") as MockV:
            instance = MagicMock()
            instance.run.return_value = 2
            instance.get_results.return_value = [
                {"url": "https://api.example.com", "status_code": 200},
                {"url": "https://admin.example.com", "status_code": 401},
            ]
            MockV.return_value = instance

            from reconxp import run_phase_live_hosts
            results = run_phase_live_hosts("example.com", "scan-123", ["api.example.com"])

        assert len(results) == 2

    def test_phase2_empty_subdomains(self):
        with patch("backend.modules.validation.LiveHostValidator") as MockV:
            instance = MagicMock()
            instance.run.return_value = 0
            instance.get_results.return_value = []
            MockV.return_value = instance

            from reconxp import run_phase_live_hosts
            results = run_phase_live_hosts("example.com", "scan-123", [])

        assert results == []
