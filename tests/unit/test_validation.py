"""
Unit tests for backend/modules/validation.py
All subprocess and DB calls mocked. No real network required.
"""

import json
import pytest
from unittest.mock import patch, MagicMock

SAMPLE_HTTPX_LINE = json.dumps({
    "url": "https://api.example.com", "status_code": 200,
    "title": "API Portal", "webserver": "nginx",
    "host_ip": "93.184.216.34", "content_length": 1024,
    "time": "120.5ms", "tech": ["Nginx", "React"],
    "cdn": True, "cdn_name": "cloudflare", "cdn_type": "waf",
})

SAMPLE_HTTPX_LINE_HTTP = json.dumps({
    "url": "http://admin.example.com", "status_code": 401,
    "title": "Admin Login", "webserver": "Apache",
    "host_ip": "10.0.0.1", "content_length": 512,
    "time": "45ms", "tech": ["Apache", "PHP"],
    "cdn": False, "cdn_name": "", "cdn_type": "",
})


@pytest.fixture
def validator():
    from backend.modules.validation import LiveHostValidator
    return LiveHostValidator("example.com", "scan-abc-123")


@pytest.mark.unit
class TestLiveHostValidatorInit:
    def test_init_sets_domain(self, validator):
        assert validator.domain == "example.com"

    def test_init_sets_scan_id(self, validator):
        assert validator.scan_id == "scan-abc-123"

    def test_init_empty_results(self, validator):
        assert validator.results == []

    def test_get_live_urls_initially_empty(self, validator):
        assert validator.get_live_urls() == []

    def test_get_results_initially_empty(self, validator):
        assert validator.get_results() == []


@pytest.mark.unit
class TestRunHttpx:
    def test_returns_stdout_on_success(self, validator):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output\n", stderr="")
            result = validator._run_httpx(["sub.example.com"])
        assert result == "output\n"

    def test_passes_subdomains_via_stdin(self, validator):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            validator._run_httpx(["a.example.com", "b.example.com"])
            assert mock_run.call_args[1]["input"] == "a.example.com\nb.example.com"

    def test_httpx_not_found_returns_empty(self, validator):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert validator._run_httpx(["sub.example.com"]) == ""

    def test_timeout_returns_empty(self, validator):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="httpx", timeout=600)):
            assert validator._run_httpx(["sub.example.com"]) == ""

    def test_nonzero_exit_still_returns_stdout(self, validator):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="partial\n", stderr="err")
            assert validator._run_httpx(["sub.example.com"]) == "partial\n"


@pytest.mark.unit
class TestParseResults:
    def test_parses_url(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE)[0]["url"] == "https://api.example.com"

    def test_parses_status_code(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE)[0]["status_code"] == 200

    def test_parses_title(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE)[0]["title"] == "API Portal"

    def test_parses_server(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE)[0]["server"] == "nginx"

    def test_parses_ip(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE)[0]["ip"] == "93.184.216.34"

    def test_parses_tech_stack(self, validator):
        result = validator._parse_results(SAMPLE_HTTPX_LINE)[0]
        assert "Nginx" in result["technology_stack"]

    def test_detects_cdn(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE)[0]["cdn"] == "cloudflare"

    def test_detects_waf(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE)[0]["waf"] == "cloudflare"

    def test_no_cdn_gives_none(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE_HTTP)[0]["cdn"] is None

    def test_https_sets_tls_info(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE)[0]["tls_info"]["enabled"] is True

    def test_http_tls_info_empty(self, validator):
        assert validator._parse_results(SAMPLE_HTTPX_LINE_HTTP)[0]["tls_info"] == {}

    def test_fingerprint_hash_is_64_chars(self, validator):
        assert len(validator._parse_results(SAMPLE_HTTPX_LINE)[0]["fingerprint_hash"]) == 64

    def test_fingerprint_hash_deterministic(self, validator):
        r1 = validator._parse_results(SAMPLE_HTTPX_LINE)[0]["fingerprint_hash"]
        r2 = validator._parse_results(SAMPLE_HTTPX_LINE)[0]["fingerprint_hash"]
        assert r1 == r2

    def test_empty_line_skipped(self, validator):
        assert validator._parse_results("\n\n") == []

    def test_invalid_json_skipped(self, validator):
        assert validator._parse_results("not json") == []

    def test_missing_url_skipped(self, validator):
        line = json.dumps({"status_code": 200})
        assert validator._parse_results(line) == []

    def test_multiple_lines_parsed(self, validator):
        raw = f"{SAMPLE_HTTPX_LINE}\n{SAMPLE_HTTPX_LINE_HTTP}\n"
        assert len(validator._parse_results(raw)) == 2


@pytest.mark.unit
class TestParseResponseTime:
    def test_parses_milliseconds(self, validator):
        assert validator._parse_response_time("120.5ms") == 120

    def test_parses_seconds(self, validator):
        assert validator._parse_response_time("1.5s") == 1500

    def test_empty_string_returns_zero(self, validator):
        assert validator._parse_response_time("") == 0

    def test_none_returns_zero(self, validator):
        assert validator._parse_response_time(None) == 0

    def test_invalid_returns_zero(self, validator):
        assert validator._parse_response_time("garbage") == 0


@pytest.mark.unit
class TestRunMethod:
    def test_returns_zero_for_empty_subdomains(self, validator):
        with patch("backend.modules.validation.save_live_hosts"):
            assert validator.run([]) == 0

    def test_run_calls_file_storage(self, validator):
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.validation.save_live_hosts") as mock_save, \
             patch.object(validator, "_store_results", return_value=1):
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_HTTPX_LINE + "\n", stderr="")
            validator.run(["api.example.com"])
        mock_save.assert_called_once()

    def test_run_populates_results(self, validator):
        raw = f"{SAMPLE_HTTPX_LINE}\n{SAMPLE_HTTPX_LINE_HTTP}\n"
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.validation.save_live_hosts"), \
             patch.object(validator, "_store_results", return_value=2):
            mock_run.return_value = MagicMock(returncode=0, stdout=raw, stderr="")
            validator.run(["api.example.com", "admin.example.com"])
        assert len(validator.get_results()) == 2

    def test_get_live_urls_after_run(self, validator):
        with patch("subprocess.run") as mock_run, \
             patch("backend.modules.validation.save_live_hosts"), \
             patch.object(validator, "_store_results", return_value=1):
            mock_run.return_value = MagicMock(returncode=0, stdout=SAMPLE_HTTPX_LINE + "\n", stderr="")
            validator.run(["api.example.com"])
        assert "https://api.example.com" in validator.get_live_urls()

    def test_run_survives_httpx_not_found(self, validator):
        with patch("subprocess.run", side_effect=FileNotFoundError), \
             patch("backend.modules.validation.save_live_hosts"):
            assert validator.run(["sub.example.com"]) == 0
