"""
Integration tests for Phase 4 — Vulnerability Scanning.
Uses SQLite in-memory DB. All subprocess calls mocked.
"""

import json
import pytest
from unittest.mock import patch, MagicMock


def make_nuclei_line(template_id, name, severity, matched_at, cve=None, cvss=None):
    data = {
        "template-id": template_id,
        "matched-at": matched_at,
        "info": {
            "name": name, "severity": severity,
            "description": f"Desc of {name}", "remediation": f"Fix {name}",
            "tags": [], "classification": {},
        }
    }
    if cve:
        data["info"]["classification"]["cve-id"] = [cve]
    if cvss:
        data["info"]["classification"]["cvss-score"] = cvss
    return json.dumps(data)


SAMPLE_OUTPUT = "\n".join([
    make_nuclei_line("CVE-2021-44228", "Log4Shell", "critical",
                     "https://api.example.com", cve="CVE-2021-44228", cvss=10.0),
    make_nuclei_line("xss-reflected", "Reflected XSS", "high",
                     "https://api.example.com/search"),
    make_nuclei_line("missing-csp", "Missing CSP", "medium",
                     "https://admin.example.com"),
]) + "\n"

LIVE_HOSTS = [
    {"url": "https://api.example.com", "ip": "1.2.3.4", "status_code": 200},
    {"url": "https://admin.example.com", "ip": "1.2.3.5", "status_code": 200},
]


@pytest.mark.integration
class TestVulnScanDBStorage:

    def test_vulns_stored_in_db(self, sqlite_session):
        from backend.modules.vuln_scan import VulnerabilityScanner
        from backend.models.models import Vulnerability, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        vs = VulnerabilityScanner("example.com", scan.id)

        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.vuln_scan.save_vulnerabilities"), \
             patch("backend.modules.vuln_scan.get_db_context") as mock_ctx:
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_OUTPUT, stderr="")
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            vs.run(LIVE_HOSTS)

        stored = sqlite_session.query(Vulnerability).filter(
            Vulnerability.scan_id == scan.id
        ).all()
        assert len(stored) == 3

    def test_critical_vuln_fields(self, sqlite_session):
        from backend.modules.vuln_scan import VulnerabilityScanner
        from backend.models.models import Vulnerability, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        vs = VulnerabilityScanner("example.com", scan.id)

        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.vuln_scan.save_vulnerabilities"), \
             patch("backend.modules.vuln_scan.get_db_context") as mock_ctx:
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_OUTPUT, stderr="")
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            vs.run(LIVE_HOSTS)

        vuln = sqlite_session.query(Vulnerability).filter(
            Vulnerability.template_id == "CVE-2021-44228"
        ).first()

        assert vuln is not None
        assert vuln.severity == "critical"
        assert vuln.cve_id == "CVE-2021-44228"
        assert float(vuln.cvss_score) == 10.0
        assert vuln.status == "new"

    def test_no_duplicate_findings_in_same_scan(self, sqlite_session):
        from backend.modules.vuln_scan import VulnerabilityScanner
        from backend.models.models import Vulnerability, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        single = make_nuclei_line("xss-reflected", "XSS", "high",
                                  "https://api.example.com/search") + "\n"
        vs = VulnerabilityScanner("example.com", scan.id)

        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.vuln_scan.save_vulnerabilities"), \
             patch("backend.modules.vuln_scan.get_db_context") as mock_ctx:
            mock_run.return_value = MagicMock(returncode=0, stdout=single, stderr="")
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            vs.run(LIVE_HOSTS)
            vs.run(LIVE_HOSTS)  # run twice

        stored = sqlite_session.query(Vulnerability).filter(
            Vulnerability.template_id == "xss-reflected"
        ).all()
        assert len(stored) == 1

    def test_status_defaults_to_new(self, sqlite_session):
        from backend.modules.vuln_scan import VulnerabilityScanner
        from backend.models.models import Vulnerability, Scan, Target

        target = Target(domain="example.com", status="active")
        sqlite_session.add(target)
        sqlite_session.flush()
        scan = Scan(target_id=target.id, scan_type="full", status="running")
        sqlite_session.add(scan)
        sqlite_session.flush()

        single = make_nuclei_line("test-template", "Test", "medium",
                                  "https://api.example.com") + "\n"
        vs = VulnerabilityScanner("example.com", scan.id)

        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.vuln_scan.save_vulnerabilities"), \
             patch("backend.modules.vuln_scan.get_db_context") as mock_ctx:
            mock_run.return_value = MagicMock(returncode=0, stdout=single, stderr="")
            mock_ctx.return_value.__enter__ = lambda s: sqlite_session
            mock_ctx.return_value.__exit__ = MagicMock(return_value=False)
            vs.run(LIVE_HOSTS)

        vuln = sqlite_session.query(Vulnerability).filter(
            Vulnerability.template_id == "test-template"
        ).first()
        assert vuln.status == "new"


@pytest.mark.integration
class TestVulnScanFileStorage:

    def test_file_storage_called(self):
        from backend.modules.vuln_scan import VulnerabilityScanner
        vs = VulnerabilityScanner("example.com", "scan-123")
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.vuln_scan.save_vulnerabilities") as mock_save, \
             patch.object(vs, "_store_results", return_value=3):
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_OUTPUT, stderr="")
            vs.run(LIVE_HOSTS)
        mock_save.assert_called_once_with("example.com", vs.results)

    def test_file_storage_receives_sorted_results(self):
        from backend.modules.vuln_scan import VulnerabilityScanner
        vs = VulnerabilityScanner("example.com", "scan-123")
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.vuln_scan.save_vulnerabilities") as mock_save, \
             patch.object(vs, "_store_results", return_value=3):
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_OUTPUT, stderr="")
            vs.run(LIVE_HOSTS)
        saved = mock_save.call_args[0][1]
        severities = [r["severity"] for r in saved]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        assert severities == sorted(severities, key=lambda s: order.get(s, 5))


@pytest.mark.integration
class TestPhase4Pipeline:

    def test_phase4_returns_results(self):
        with patch("backend.modules.vuln_scan.VulnerabilityScanner") as MockVS:
            instance = MagicMock()
            instance.run.return_value = 3
            instance.get_summary.return_value = {"critical": 1, "high": 1, "medium": 1}
            instance.get_results.return_value = [
                {"severity": "critical", "template_id": "a", "matched_at": "https://x.com"},
                {"severity": "high",     "template_id": "b", "matched_at": "https://y.com"},
                {"severity": "medium",   "template_id": "c", "matched_at": "https://z.com"},
            ]
            MockVS.return_value = instance

            from reconxp import run_phase_vulns
            results = run_phase_vulns("example.com", "scan-123", LIVE_HOSTS)

        assert len(results) == 3

    def test_phase4_with_no_live_hosts(self):
        with patch("backend.modules.vuln_scan.VulnerabilityScanner") as MockVS:
            instance = MagicMock()
            instance.run.return_value = 0
            instance.get_summary.return_value = {}
            instance.get_results.return_value = []
            MockVS.return_value = instance

            from reconxp import run_phase_vulns
            results = run_phase_vulns("example.com", "scan-123", [])

        assert results == []
