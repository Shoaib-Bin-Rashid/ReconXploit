"""
Unit tests for Phase 5 — JS Intelligence Module.
All network calls and subprocess calls are mocked.
"""

import pytest
from unittest.mock import patch, MagicMock

from backend.modules.js_analysis import (
    JsAnalyzer,
    SECRET_PATTERNS,
    ENDPOINT_PATTERNS,
    RISK_LEVELS,
)

LIVE_HOSTS = [
    {"url": "https://api.example.com", "ip": "1.2.3.4"},
    {"url": "https://app.example.com", "ip": "1.2.3.5"},
]

# Fake keys constructed via concatenation so GitHub secret scanning
# never sees a complete key literal in source code.
_STRIPE_LIVE_FAKE  = "sk" + "_live_" + "abcdef1234567890abcdef12"
_STRIPE_TEST_FAKE  = "sk" + "_test_" + "abcdef1234567890abcdef12"

JS_WITH_SECRETS = (
    "var config = {\n"
    f'  stripeKey: "{_STRIPE_LIVE_FAKE}",\n'
    '  dbUrl: "mongodb://admin:s3cr3t@db.example.com:27017/prod",\n'
    '  jwt: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    '.eyJ1c2VyIjoic2hvYWliIn0.signature12345"\n'
    "};"
)

JS_WITH_ENDPOINTS = """
const API_BASE = '/api/v1/users';
const GRAPHQL  = '/graphql';
const ADMIN    = '/admin/dashboard';
const SWAGGER  = '/swagger/index.html';
const DEBUG    = '/debug/pprof';
"""

JS_CLEAN = "var x = 1 + 2; console.log(x);"

HTML_WITH_SCRIPTS = """
<html>
<head>
  <script src="/static/app.min.js"></script>
  <script src="https://api.example.com/bundle.js"></script>
</head>
<body><a href="/about">About</a></body>
</html>
"""


# ─────────────────────────────────────────────────────────────
# Initialization
# ─────────────────────────────────────────────────────────────

class TestJsAnalyzerInit:
    def test_init_defaults(self):
        ja = JsAnalyzer("example.com", "scan-001")
        assert ja.domain == "example.com"
        assert ja.scan_id == "scan-001"
        assert ja.mode == "full"
        assert ja.results == []

    def test_init_custom_mode(self):
        ja = JsAnalyzer("example.com", "scan-001", mode="quick")
        assert ja.mode == "quick"

    def test_get_results_empty_initially(self):
        ja = JsAnalyzer("example.com", "scan-001")
        assert ja.get_results() == []

    def test_get_summary_empty_initially(self):
        ja = JsAnalyzer("example.com", "scan-001")
        assert ja.get_summary() == {}


# ─────────────────────────────────────────────────────────────
# gau / waybackurls runners
# ─────────────────────────────────────────────────────────────

class TestUrlHarvesting:
    def test_run_gau_success(self):
        ja = JsAnalyzer("example.com", "scan-001")
        mock_result = MagicMock(
            returncode=0,
            stdout="https://api.example.com/app.js\nhttps://api.example.com/main.js\n",
        )
        with patch("subprocess.run", return_value=mock_result):
            urls = ja._run_gau("example.com")
        assert len(urls) == 2
        assert "https://api.example.com/app.js" in urls

    def test_run_gau_not_installed(self):
        ja = JsAnalyzer("example.com", "scan-001")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            urls = ja._run_gau("example.com")
        assert urls == []

    def test_run_gau_timeout(self):
        import subprocess
        ja = JsAnalyzer("example.com", "scan-001")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("gau", 10)):
            urls = ja._run_gau("example.com")
        assert urls == []

    def test_run_waybackurls_success(self):
        ja = JsAnalyzer("example.com", "scan-001")
        mock_result = MagicMock(
            returncode=0,
            stdout="https://example.com/old.js\nhttps://example.com/legacy.js\n",
        )
        with patch("subprocess.run", return_value=mock_result):
            urls = ja._run_waybackurls("example.com")
        assert len(urls) == 2

    def test_run_waybackurls_not_installed(self):
        ja = JsAnalyzer("example.com", "scan-001")
        with patch("subprocess.run", side_effect=FileNotFoundError):
            urls = ja._run_waybackurls("example.com")
        assert urls == []

    def test_run_gau_empty_lines_filtered(self):
        ja = JsAnalyzer("example.com", "scan-001")
        mock_result = MagicMock(returncode=0, stdout="\n\nhttps://x.com/a.js\n\n")
        with patch("subprocess.run", return_value=mock_result):
            urls = ja._run_gau("example.com")
        assert urls == ["https://x.com/a.js"]


# ─────────────────────────────────────────────────────────────
# HTML crawling
# ─────────────────────────────────────────────────────────────

class TestHtmlCrawl:
    def test_crawl_extracts_script_src(self):
        ja = JsAnalyzer("example.com", "scan-001")
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = HTML_WITH_SCRIPTS.encode()

        with patch("urllib.request.urlopen", return_value=mock_resp):
            links = ja._crawl_html_for_links("https://api.example.com")

        assert any("app.min.js" in l for l in links)
        assert any("bundle.js" in l for l in links)

    def test_crawl_error_returns_empty(self):
        ja = JsAnalyzer("example.com", "scan-001")
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            links = ja._crawl_html_for_links("https://api.example.com")
        assert links == []

    def test_crawl_empty_url_returns_empty(self):
        ja = JsAnalyzer("example.com", "scan-001")
        assert ja._crawl_html_for_links("") == []


# ─────────────────────────────────────────────────────────────
# JS URL filtering
# ─────────────────────────────────────────────────────────────

class TestJsUrlFiltering:
    def test_keeps_js_urls_on_same_domain(self):
        ja = JsAnalyzer("example.com", "scan-001")
        urls = [
            "https://api.example.com/app.js",
            "https://api.example.com/main.min.js",
        ]
        result = ja._filter_js_urls(urls)
        assert len(result) == 2

    def test_excludes_non_js_urls(self):
        ja = JsAnalyzer("example.com", "scan-001")
        urls = [
            "https://api.example.com/image.png",
            "https://api.example.com/style.css",
            "https://api.example.com/app.js",
        ]
        result = ja._filter_js_urls(urls)
        assert len(result) == 1
        assert "app.js" in result[0]

    def test_excludes_different_domain(self):
        ja = JsAnalyzer("example.com", "scan-001")
        urls = ["https://cdn.other.com/vendor.js"]
        result = ja._filter_js_urls(urls)
        assert result == []

    def test_deduplicates_same_url(self):
        ja = JsAnalyzer("example.com", "scan-001")
        urls = [
            "https://api.example.com/app.js",
            "https://api.example.com/app.js",
            "https://api.example.com/app.js?v=1",
        ]
        result = ja._filter_js_urls(urls)
        assert len(result) == 1

    def test_strips_query_string_for_dedup(self):
        ja = JsAnalyzer("example.com", "scan-001")
        urls = [
            "https://api.example.com/bundle.js?v=abc",
            "https://api.example.com/bundle.js?v=xyz",
        ]
        result = ja._filter_js_urls(urls)
        assert len(result) == 1


# ─────────────────────────────────────────────────────────────
# Secret extraction
# ─────────────────────────────────────────────────────────────

class TestSecretExtraction:
    def _findings(self, content):
        ja = JsAnalyzer("example.com", "scan-001")
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = content.encode()
        with patch("urllib.request.urlopen", return_value=mock_resp):
            return ja._analyze_js_file("https://api.example.com/app.js")

    def test_detects_aws_access_key(self):
        # AKIA + exactly 16 uppercase/digit chars = 20-char AWS access key
        findings = self._findings('var k = "AKIAIOSFODNN7EXAMPLE";')
        types = [f["finding_type"] for f in findings]
        assert "aws_access_key" in types

    def test_detects_stripe_live_key(self):
        findings = self._findings(f'stripe.init("{_STRIPE_LIVE_FAKE}");')
        types = [f["finding_type"] for f in findings]
        assert "stripe_live_key" in types

    def test_detects_google_api_key(self):
        # AIza + exactly 35 alphanumeric chars = 39-char Google API key
        google_key = "AIza" + "SyCTEST" + "0" * 28   # 4 + 7 + 28 = 39
        findings = self._findings(f'var k="{google_key}";')
        types = [f["finding_type"] for f in findings]
        assert "google_api_key" in types

    def test_detects_jwt_token(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoic2hvYWliIn0.signature12345"
        findings = self._findings(f'var token="{jwt}";')
        types = [f["finding_type"] for f in findings]
        assert "jwt_token" in types

    def test_detects_db_connection_string(self):
        findings = self._findings('var db="mongodb://admin:pass@db.example.com/prod";')
        types = [f["finding_type"] for f in findings]
        assert "db_connection" in types

    def test_clean_js_has_no_secrets(self):
        findings = self._findings(JS_CLEAN)
        secret_types = {p[0] for p in SECRET_PATTERNS}
        found_secrets = [f for f in findings if f["finding_type"] in secret_types]
        assert found_secrets == []

    def test_secret_risk_level_is_critical_for_aws(self):
        findings = self._findings('var k = "AKIAIOSFODNN7EXAMPLE";')
        aws = [f for f in findings if f["finding_type"] == "aws_access_key"]
        assert aws[0]["risk_level"] == "critical"

    def test_stripe_live_key_risk_is_critical(self):
        findings = self._findings(f'stripe.init("{_STRIPE_LIVE_FAKE}");')
        stripe = [f for f in findings if f["finding_type"] == "stripe_live_key"]
        assert stripe[0]["risk_level"] == "critical"


# ─────────────────────────────────────────────────────────────
# Endpoint extraction
# ─────────────────────────────────────────────────────────────

class TestEndpointExtraction:
    def _findings(self, content):
        ja = JsAnalyzer("example.com", "scan-001")
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = content.encode()
        with patch("urllib.request.urlopen", return_value=mock_resp):
            return ja._analyze_js_file("https://api.example.com/app.js")

    def test_detects_graphql_endpoint(self):
        findings = self._findings("const ep = '/graphql';")
        types = [f["finding_type"] for f in findings]
        assert "graphql_endpoint" in types

    def test_detects_admin_endpoint(self):
        findings = self._findings("var panel = '/admin/dashboard';")
        types = [f["finding_type"] for f in findings]
        assert "admin_endpoint" in types

    def test_detects_swagger_endpoint(self):
        findings = self._findings("var docs = '/swagger/index.html';")
        types = [f["finding_type"] for f in findings]
        assert "swagger_endpoint" in types

    def test_detects_api_endpoint(self):
        findings = self._findings("var api = '/api/v1/users';")
        types = [f["finding_type"] for f in findings]
        assert "api_endpoint" in types

    def test_detects_s3_bucket(self):
        findings = self._findings(
            "var cdn = 'https://my-bucket.s3.amazonaws.com/assets/';"
        )
        types = [f["finding_type"] for f in findings]
        assert "s3_bucket" in types

    def test_detects_debug_endpoint(self):
        findings = self._findings("var dbg = '/debug/pprof';")
        types = [f["finding_type"] for f in findings]
        assert "debug_endpoint" in types

    def test_admin_endpoint_risk_is_high(self):
        findings = self._findings("var panel = '/admin/dashboard';")
        admins = [f for f in findings if f["finding_type"] == "admin_endpoint"]
        assert admins[0]["risk_level"] == "high"


# ─────────────────────────────────────────────────────────────
# Redaction
# ─────────────────────────────────────────────────────────────

class TestRedaction:
    def test_sensitive_secrets_are_redacted(self):
        ja = JsAnalyzer("example.com", "scan-001")
        result = ja._redact("mypassword123", "password")
        assert "mypassword123" not in result
        assert "REDACTED" in result

    def test_aws_key_is_redacted(self):
        ja = JsAnalyzer("example.com", "scan-001")
        result = ja._redact("AKIAIOSFODNN7EXAMPLE1", "aws_secret_key")
        assert "AKIAIOSFODNN7EXAMPLE1" not in result
        assert "REDACTED" in result

    def test_partial_redaction_for_api_keys(self):
        ja = JsAnalyzer("example.com", "scan-001")
        key = "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        result = ja._redact(key, "google_api_key")
        assert result.startswith(key[:6])
        assert "***" in result or "*" in result

    def test_short_value_redacted(self):
        ja = JsAnalyzer("example.com", "scan-001")
        result = ja._redact("short", "generic_api_key")
        assert "***" in result


# ─────────────────────────────────────────────────────────────
# Context extraction
# ─────────────────────────────────────────────────────────────

class TestContextExtraction:
    def test_extracts_context_around_value(self):
        content = "var config = { apiKey: 'AKIAIOSFODNN7EXAMPLE1', region: 'us-east-1' };"
        ctx = JsAnalyzer._extract_context(content, "AKIAIOSFODNN7EXAMPLE1")
        assert ctx is not None
        assert "apiKey" in ctx

    def test_returns_none_if_not_found(self):
        ctx = JsAnalyzer._extract_context("var x = 1;", "missing_value")
        assert ctx is None

    def test_context_max_length(self):
        content = "a" * 100 + "TARGET" + "b" * 100
        ctx = JsAnalyzer._extract_context(content, "TARGET")
        assert len(ctx) <= 200


# ─────────────────────────────────────────────────────────────
# Fetch JS content
# ─────────────────────────────────────────────────────────────

class TestFetchJsContent:
    def test_fetch_returns_content(self):
        ja = JsAnalyzer("example.com", "scan-001")
        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"var x = 1;"
        with patch("urllib.request.urlopen", return_value=mock_resp):
            content = ja._fetch_js_content("https://api.example.com/app.js")
        assert content == "var x = 1;"

    def test_fetch_error_returns_none(self):
        ja = JsAnalyzer("example.com", "scan-001")
        with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
            content = ja._fetch_js_content("https://api.example.com/app.js")
        assert content is None


# ─────────────────────────────────────────────────────────────
# get_secrets / get_endpoints helpers
# ─────────────────────────────────────────────────────────────

class TestResultHelpers:
    def test_get_secrets_filters_correctly(self):
        ja = JsAnalyzer("example.com", "scan-001")
        ja.results = [
            {"finding_type": "aws_access_key", "secret_type": "aws_access_key",
             "finding_value": "AKIA...", "risk_level": "critical"},
            {"finding_type": "api_endpoint",   "secret_type": None,
             "finding_value": "/api/v1", "risk_level": "low"},
        ]
        secrets = ja.get_secrets()
        assert len(secrets) == 1
        assert secrets[0]["finding_type"] == "aws_access_key"

    def test_get_endpoints_filters_correctly(self):
        ja = JsAnalyzer("example.com", "scan-001")
        ja.results = [
            {"finding_type": "aws_access_key", "secret_type": "aws_access_key",
             "finding_value": "AKIA...", "risk_level": "critical"},
            {"finding_type": "api_endpoint", "secret_type": None,
             "finding_value": "/api/v1", "risk_level": "low"},
        ]
        endpoints = ja.get_endpoints()
        assert len(endpoints) == 1
        assert endpoints[0]["finding_type"] == "api_endpoint"

    def test_get_summary_counts_by_type(self):
        ja = JsAnalyzer("example.com", "scan-001")
        ja.results = [
            {"finding_type": "api_endpoint", "finding_value": "/api/v1"},
            {"finding_type": "api_endpoint", "finding_value": "/api/v2"},
            {"finding_type": "aws_access_key", "finding_value": "AKIA..."},
        ]
        summary = ja.get_summary()
        assert summary["api_endpoint"] == 2
        assert summary["aws_access_key"] == 1


# ─────────────────────────────────────────────────────────────
# run() — top-level orchestration
# ─────────────────────────────────────────────────────────────

class TestJsAnalyzerRun:
    def test_run_returns_count(self):
        ja = JsAnalyzer("example.com", "scan-001")
        with patch.object(ja, "_collect_urls", return_value=[
                "https://api.example.com/app.js"
             ]), \
             patch.object(ja, "_filter_js_urls", return_value=[
                "https://api.example.com/app.js"
             ]), \
             patch.object(ja, "_analyze_js_file", return_value=[
                {"source_url": "https://api.example.com/app.js",
                 "js_file_url": "https://api.example.com/app.js",
                 "finding_type": "api_endpoint", "finding_value": "/api/v1",
                 "secret_type": None, "risk_level": "low", "context": None}
             ]), \
             patch.object(ja, "_store_results", return_value=1), \
             patch("backend.modules.js_analysis.save_js_findings"):
            count = ja.run(LIVE_HOSTS)
        assert count == 1

    def test_run_deduplicates_findings(self):
        ja = JsAnalyzer("example.com", "scan-001")
        dup_finding = {
            "source_url": "https://api.example.com/app.js",
            "js_file_url": "https://api.example.com/app.js",
            "finding_type": "api_endpoint",
            "finding_value": "/api/v1",
            "secret_type": None, "risk_level": "low", "context": None,
        }
        with patch.object(ja, "_collect_urls", return_value=[
                "https://api.example.com/app.js",
                "https://api.example.com/app.js",
             ]), \
             patch.object(ja, "_filter_js_urls", return_value=[
                "https://api.example.com/app.js",
             ]), \
             patch.object(ja, "_analyze_js_file", return_value=[dup_finding, dup_finding]), \
             patch.object(ja, "_store_results", return_value=1), \
             patch("backend.modules.js_analysis.save_js_findings"):
            ja.run(LIVE_HOSTS)
        assert len(ja.results) == 1

    def test_run_calls_file_storage(self):
        ja = JsAnalyzer("example.com", "scan-001")
        with patch.object(ja, "_collect_urls", return_value=[]), \
             patch.object(ja, "_filter_js_urls", return_value=[]), \
             patch.object(ja, "_store_results", return_value=0), \
             patch("backend.modules.js_analysis.save_js_findings") as mock_save:
            ja.run(LIVE_HOSTS)
        mock_save.assert_called_once_with("example.com", [])

    def test_run_no_live_hosts(self):
        ja = JsAnalyzer("example.com", "scan-001")
        with patch.object(ja, "_collect_urls", return_value=[]), \
             patch.object(ja, "_filter_js_urls", return_value=[]), \
             patch.object(ja, "_store_results", return_value=0), \
             patch("backend.modules.js_analysis.save_js_findings"):
            count = ja.run([])
        assert count == 0

    def test_run_sorts_by_risk(self):
        ja = JsAnalyzer("example.com", "scan-001")
        findings = [
            {"source_url": "https://a.example.com/x.js", "js_file_url": "https://a.example.com/x.js",
             "finding_type": "api_endpoint", "finding_value": "/api", "secret_type": None,
             "risk_level": "low", "context": None},
            {"source_url": "https://a.example.com/x.js", "js_file_url": "https://a.example.com/x.js",
             "finding_type": "aws_access_key", "finding_value": "AKIAXXX",
             "secret_type": "aws_access_key", "risk_level": "critical", "context": None},
        ]
        with patch.object(ja, "_collect_urls", return_value=["https://a.example.com/x.js"]), \
             patch.object(ja, "_filter_js_urls", return_value=["https://a.example.com/x.js"]), \
             patch.object(ja, "_analyze_js_file", return_value=findings), \
             patch.object(ja, "_store_results", return_value=2), \
             patch("backend.modules.js_analysis.save_js_findings"):
            ja.run(LIVE_HOSTS)
        assert ja.results[0]["risk_level"] == "critical"
