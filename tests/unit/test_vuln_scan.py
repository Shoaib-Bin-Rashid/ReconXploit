"""
Unit tests for backend/modules/vuln_scan.py
All subprocess and DB calls mocked. No real nuclei required.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

# ─────────────────────────────────────────────
# SAMPLE DATA
# ─────────────────────────────────────────────

def make_nuclei_line(template_id, name, severity, matched_at,
                     cve=None, cvss=None, description="", tags=None):
    data = {
        "template-id": template_id,
        "matched-at": matched_at,
        "info": {
            "name": name,
            "severity": severity,
            "description": description,
            "remediation": f"Update {name}",
            "tags": tags or [],
            "classification": {},
        }
    }
    if cve:
        data["info"]["classification"]["cve-id"] = [cve]
    if cvss:
        data["info"]["classification"]["cvss-score"] = cvss
    return json.dumps(data)


CRITICAL_LINE = make_nuclei_line(
    "CVE-2021-44228", "Log4Shell RCE", "critical",
    "https://api.example.com", cve="CVE-2021-44228", cvss=10.0
)
HIGH_LINE = make_nuclei_line(
    "xss-reflected", "Reflected XSS", "high",
    "https://api.example.com/search?q=test"
)
MEDIUM_LINE = make_nuclei_line(
    "missing-csp", "Missing CSP Header", "medium",
    "https://admin.example.com"
)
INFO_LINE = make_nuclei_line(
    "tech-detect", "Technology Detection", "info",
    "https://api.example.com"
)

SAMPLE_OUTPUT = "\n".join([CRITICAL_LINE, HIGH_LINE, MEDIUM_LINE, INFO_LINE]) + "\n"

SAMPLE_LIVE_HOSTS = [
    {"url": "https://api.example.com", "ip": "1.2.3.4", "status_code": 200},
    {"url": "https://admin.example.com", "ip": "1.2.3.5", "status_code": 200},
]


@pytest.fixture
def scanner():
    from backend.modules.vuln_scan import VulnerabilityScanner
    return VulnerabilityScanner("example.com", "scan-vuln-001")


# ─────────────────────────────────────────────
# INIT
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestVulnScannerInit:
    def test_init_domain(self, scanner):
        assert scanner.domain == "example.com"

    def test_init_scan_id(self, scanner):
        assert scanner.scan_id == "scan-vuln-001"

    def test_init_empty_results(self, scanner):
        assert scanner.results == []

    def test_get_results_empty(self, scanner):
        assert scanner.get_results() == []

    def test_get_summary_empty(self, scanner):
        assert scanner.get_summary() == {}

    def test_get_critical_and_high_empty(self, scanner):
        assert scanner.get_critical_and_high() == []


# ─────────────────────────────────────────────
# URL EXTRACTION
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestExtractUrls:
    def test_extracts_urls(self, scanner):
        urls = scanner._extract_urls(SAMPLE_LIVE_HOSTS)
        assert "https://api.example.com" in urls
        assert "https://admin.example.com" in urls

    def test_deduplicates_urls(self, scanner):
        hosts = [{"url": "https://x.com"}, {"url": "https://x.com"}]
        assert len(scanner._extract_urls(hosts)) == 1

    def test_skips_empty_urls(self, scanner):
        hosts = [{"url": ""}, {"url": None}, {"url": "https://x.com"}]
        assert scanner._extract_urls(hosts) == ["https://x.com"]

    def test_empty_list(self, scanner):
        assert scanner._extract_urls([]) == []


# ─────────────────────────────────────────────
# NUCLEI RUNNER
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestRunNuclei:
    def test_returns_stdout(self, scanner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output\n", stderr="")
            assert scanner._run_nuclei(["https://x.com"], "full") == "output\n"

    def test_passes_urls_via_stdin(self, scanner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner._run_nuclei(["https://a.com", "https://b.com"], "full")
            assert mock_run.call_args[1]["input"] == "https://a.com\nhttps://b.com"

    def test_nuclei_not_found_returns_empty(self, scanner):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert scanner._run_nuclei(["https://x.com"], "full") == ""

    def test_timeout_returns_empty(self, scanner):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nuclei", timeout=3600)):
            assert scanner._run_nuclei(["https://x.com"], "full") == ""

    def test_quick_mode_adds_severity_flag(self, scanner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner._run_nuclei(["https://x.com"], "quick")
            cmd = mock_run.call_args[0][0]
            assert "-severity" in cmd
            idx = cmd.index("-severity")
            assert "critical" in cmd[idx + 1]
            assert "high" in cmd[idx + 1]

    def test_deep_mode_adds_intrusive_flag(self, scanner):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            scanner._run_nuclei(["https://x.com"], "deep")
            cmd = mock_run.call_args[0][0]
            assert "-include-tags" in cmd


# ─────────────────────────────────────────────
# PARSER
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestParseResults:
    def test_parses_template_id(self, scanner):
        results = scanner._parse_results(CRITICAL_LINE)
        assert results[0]["template_id"] == "CVE-2021-44228"

    def test_parses_name(self, scanner):
        results = scanner._parse_results(CRITICAL_LINE)
        assert results[0]["name"] == "Log4Shell RCE"

    def test_parses_severity(self, scanner):
        results = scanner._parse_results(CRITICAL_LINE)
        assert results[0]["severity"] == "critical"

    def test_parses_matched_at(self, scanner):
        results = scanner._parse_results(CRITICAL_LINE)
        assert results[0]["matched_at"] == "https://api.example.com"

    def test_parses_cve_id(self, scanner):
        results = scanner._parse_results(CRITICAL_LINE)
        assert results[0]["cve_id"] == "CVE-2021-44228"

    def test_parses_cvss_score(self, scanner):
        results = scanner._parse_results(CRITICAL_LINE)
        assert results[0]["cvss_score"] == 10.0

    def test_no_cve_gives_none(self, scanner):
        results = scanner._parse_results(HIGH_LINE)
        assert results[0]["cve_id"] is None

    def test_results_sorted_by_severity(self, scanner):
        results = scanner._parse_results(SAMPLE_OUTPUT)
        severities = [r["severity"] for r in results]
        order = {"critical": 0, "high": 1, "medium": 2, "info": 4}
        assert severities == sorted(severities, key=lambda s: order.get(s, 5))

    def test_empty_output_returns_empty(self, scanner):
        assert scanner._parse_results("") == []

    def test_invalid_json_skipped(self, scanner):
        assert scanner._parse_results("not json\nalso bad\n") == []

    def test_missing_template_id_skipped(self, scanner):
        line = json.dumps({"matched-at": "https://x.com", "info": {}})
        assert scanner._parse_results(line) == []

    def test_missing_matched_at_skipped(self, scanner):
        line = json.dumps({"template-id": "test", "info": {}})
        assert scanner._parse_results(line) == []

    def test_unknown_severity_normalized_to_info(self, scanner):
        line = make_nuclei_line("t", "Test", "supersecret", "https://x.com")
        results = scanner._parse_results(line)
        assert results[0]["severity"] == "info"

    def test_parses_multiple_findings(self, scanner):
        assert len(scanner._parse_results(SAMPLE_OUTPUT)) == 4


# ─────────────────────────────────────────────
# CVE / CVSS EXTRACTION
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestCveExtraction:
    def test_extracts_cve_from_classification(self, scanner):
        info = {"classification": {"cve-id": ["CVE-2021-44228"]}}
        assert scanner._extract_cve(info) == "CVE-2021-44228"

    def test_extracts_cve_from_tags(self, scanner):
        info = {"classification": {}, "tags": ["cve-2022-1234", "rce"]}
        result = scanner._extract_cve(info)
        assert result == "CVE-2022-1234"

    def test_returns_none_if_no_cve(self, scanner):
        assert scanner._extract_cve({"classification": {}, "tags": []}) is None

    def test_extracts_cvss_score(self, scanner):
        info = {"classification": {"cvss-score": 9.8}}
        assert scanner._extract_cvss(info) == 9.8

    def test_returns_none_if_no_cvss(self, scanner):
        assert scanner._extract_cvss({"classification": {}}) is None


# ─────────────────────────────────────────────
# SUMMARY / ACCESSORS
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestSummaryAndAccessors:
    def setup_method(self):
        from backend.modules.vuln_scan import VulnerabilityScanner
        self.scanner = VulnerabilityScanner("example.com", "scan-001")
        self.scanner.results = [
            {"severity": "critical", "template_id": "a", "matched_at": "https://x.com"},
            {"severity": "critical", "template_id": "b", "matched_at": "https://y.com"},
            {"severity": "high",     "template_id": "c", "matched_at": "https://z.com"},
            {"severity": "info",     "template_id": "d", "matched_at": "https://w.com"},
        ]

    def test_get_summary(self):
        s = self.scanner.get_summary()
        assert s["critical"] == 2
        assert s["high"] == 1
        assert s["info"] == 1

    def test_get_by_severity(self):
        assert len(self.scanner.get_by_severity("critical")) == 2

    def test_get_critical_and_high(self):
        assert len(self.scanner.get_critical_and_high()) == 3

    def test_get_results_returns_all(self):
        assert len(self.scanner.get_results()) == 4


# ─────────────────────────────────────────────
# RUN METHOD
# ─────────────────────────────────────────────

@pytest.mark.unit
class TestRunMethod:
    def test_returns_zero_for_empty_hosts(self, scanner):
        with patch("backend.modules.vuln_scan.save_vulnerabilities"):
            assert scanner.run([]) == 0

    def test_run_calls_file_storage(self, scanner):
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.vuln_scan.save_vulnerabilities") as mock_save, \
             patch.object(scanner, "_store_results", return_value=4):
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_OUTPUT, stderr="")
            scanner.run(SAMPLE_LIVE_HOSTS)
        mock_save.assert_called_once()

    def test_run_populates_results(self, scanner):
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.vuln_scan.save_vulnerabilities"), \
             patch.object(scanner, "_store_results", return_value=4):
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_OUTPUT, stderr="")
            scanner.run(SAMPLE_LIVE_HOSTS)
        assert len(scanner.get_results()) == 4

    def test_run_survives_nuclei_not_found(self, scanner):
        with patch("subprocess.run", side_effect=FileNotFoundError), \
             patch("backend.modules.vuln_scan.save_vulnerabilities"):
            assert scanner.run(SAMPLE_LIVE_HOSTS) == 0
