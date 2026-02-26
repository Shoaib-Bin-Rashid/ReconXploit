"""
Integration tests for Phase 5 — JS Intelligence.
Uses SQLite in-memory DB. All network calls mocked.
"""

import pytest
from unittest.mock import patch, MagicMock

from backend.modules.js_analysis import JsAnalyzer

LIVE_HOSTS = [
    {"url": "https://api.example.com", "ip": "1.2.3.4"},
]

JS_CONTENT = """
var apiKey = "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const GRAPHQL = '/graphql';
const ADMIN   = '/admin/dashboard';
"""


def _make_mock_resp(content: str):
    mock_resp = MagicMock()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read.return_value = content.encode()
    return mock_resp


@pytest.mark.integration
class TestJsIntelligenceDBStorage:

    def test_findings_stored_in_db(self, sqlite_session):
        from backend.models.models import JsIntelligence, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        ja = JsAnalyzer("example.com", scan.id)

        with patch.object(ja, "_collect_urls", return_value=["https://api.example.com/app.js"]), \
             patch.object(ja, "_filter_js_urls", return_value=["https://api.example.com/app.js"]), \
             patch("urllib.request.urlopen", return_value=_make_mock_resp(JS_CONTENT)), \
             patch("backend.modules.js_analysis.save_js_findings"), \
             patch("backend.modules.js_analysis.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            ja.run(LIVE_HOSTS)

        stored = sqlite_session.query(JsIntelligence).filter(
            JsIntelligence.scan_id == scan.id
        ).all()
        assert len(stored) > 0

    def test_secret_finding_fields(self, sqlite_session):
        from backend.models.models import JsIntelligence, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        ja = JsAnalyzer("example.com", scan.id)

        with patch.object(ja, "_collect_urls", return_value=["https://api.example.com/app.js"]), \
             patch.object(ja, "_filter_js_urls", return_value=["https://api.example.com/app.js"]), \
             patch("urllib.request.urlopen", return_value=_make_mock_resp(
                 # AIza + exactly 35 chars = valid Google API key
                 'var k = "AIzaSyCTEST' + '0' * 28 + '";'
             )), \
             patch("backend.modules.js_analysis.save_js_findings"), \
             patch("backend.modules.js_analysis.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            ja.run(LIVE_HOSTS)

        finding = sqlite_session.query(JsIntelligence).filter(
            JsIntelligence.finding_type == "google_api_key"
        ).first()
        assert finding is not None
        assert finding.secret_type == "google_api_key"
        assert finding.risk_level == "high"
        assert finding.source_url == "https://api.example.com/app.js"

    def test_no_duplicate_findings_in_same_scan(self, sqlite_session):
        from backend.models.models import JsIntelligence, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        js_content = 'var k = "AIzaSyCTEST' + '0' * 28 + '";'
        ja = JsAnalyzer("example.com", scan.id)

        with patch.object(ja, "_collect_urls", return_value=["https://api.example.com/app.js"]), \
             patch.object(ja, "_filter_js_urls", return_value=["https://api.example.com/app.js"]), \
             patch("urllib.request.urlopen", return_value=_make_mock_resp(js_content)), \
             patch("backend.modules.js_analysis.save_js_findings"), \
             patch("backend.modules.js_analysis.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            # Run twice — should not duplicate
            ja.run(LIVE_HOSTS)
            ja.run(LIVE_HOSTS)

        findings = sqlite_session.query(JsIntelligence).filter(
            JsIntelligence.scan_id == scan.id,
            JsIntelligence.finding_type == "google_api_key",
        ).all()
        assert len(findings) == 1

    def test_endpoint_stored_without_secret_type(self, sqlite_session):
        from backend.models.models import JsIntelligence, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        ja = JsAnalyzer("example.com", scan.id)

        with patch.object(ja, "_collect_urls", return_value=["https://api.example.com/app.js"]), \
             patch.object(ja, "_filter_js_urls", return_value=["https://api.example.com/app.js"]), \
             patch("urllib.request.urlopen", return_value=_make_mock_resp(
                 "const GQL = '/graphql';"
             )), \
             patch("backend.modules.js_analysis.save_js_findings"), \
             patch("backend.modules.js_analysis.get_db_context") as mock_ctx:
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            ja.run(LIVE_HOSTS)

        finding = sqlite_session.query(JsIntelligence).filter(
            JsIntelligence.finding_type == "graphql_endpoint"
        ).first()
        assert finding is not None
        assert finding.secret_type is None


@pytest.mark.integration
class TestJsFileStorage:

    def test_file_storage_called(self):
        ja = JsAnalyzer("example.com", "scan-123")
        with patch.object(ja, "_collect_urls", return_value=[]), \
             patch.object(ja, "_filter_js_urls", return_value=[]), \
             patch.object(ja, "_store_results", return_value=0), \
             patch("backend.modules.js_analysis.save_js_findings") as mock_save:
            ja.run(LIVE_HOSTS)
        mock_save.assert_called_once_with("example.com", [])

    def test_file_storage_receives_findings(self):
        ja = JsAnalyzer("example.com", "scan-123")
        expected = [
            {"source_url": "https://api.example.com/app.js",
             "js_file_url": "https://api.example.com/app.js",
             "finding_type": "api_endpoint", "finding_value": "/api/v1",
             "secret_type": None, "risk_level": "low", "context": None},
        ]
        with patch.object(ja, "_collect_urls", return_value=["https://api.example.com/app.js"]), \
             patch.object(ja, "_filter_js_urls", return_value=["https://api.example.com/app.js"]), \
             patch.object(ja, "_analyze_js_file", return_value=expected), \
             patch.object(ja, "_store_results", return_value=1), \
             patch("backend.modules.js_analysis.save_js_findings") as mock_save:
            ja.run(LIVE_HOSTS)
        saved = mock_save.call_args[0][1]
        assert len(saved) == 1
        assert saved[0]["finding_type"] == "api_endpoint"


@pytest.mark.integration
class TestPhase5Pipeline:

    def test_phase5_returns_results(self):
        with patch("backend.modules.js_analysis.JsAnalyzer") as MockJA:
            instance = MagicMock()
            instance.run.return_value = 3
            instance.get_secrets.return_value = [{"finding_type": "aws_access_key"}]
            instance.get_endpoints.return_value = [
                {"finding_type": "api_endpoint"},
                {"finding_type": "graphql_endpoint"},
            ]
            instance.get_results.return_value = [
                {"finding_type": "aws_access_key", "risk_level": "critical"},
                {"finding_type": "api_endpoint",   "risk_level": "low"},
                {"finding_type": "graphql_endpoint", "risk_level": "medium"},
            ]
            MockJA.return_value = instance

            from reconxp import run_phase_js
            results = run_phase_js("example.com", "scan-123", LIVE_HOSTS)

        assert len(results) == 3

    def test_phase5_empty_live_hosts(self):
        with patch("backend.modules.js_analysis.JsAnalyzer") as MockJA:
            instance = MagicMock()
            instance.run.return_value = 0
            instance.get_secrets.return_value = []
            instance.get_endpoints.return_value = []
            instance.get_results.return_value = []
            MockJA.return_value = instance

            from reconxp import run_phase_js
            results = run_phase_js("example.com", "scan-123", [])

        assert results == []
