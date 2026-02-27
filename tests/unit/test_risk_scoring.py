"""Unit tests for Phase 7 — Risk Scoring module."""
import pytest
from unittest.mock import patch, MagicMock
from backend.modules.risk_scoring import RiskScorer, DEFAULT_WEIGHTS, SCORE_CAP


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _scorer(domain="example.com", scan_id="scan-001"):
    return RiskScorer(domain, scan_id)


def _make_vuln(severity="medium", url="https://example.com"):
    return {"vulnerability_name": "test", "severity": severity, "matched_at": url}


def _make_host(url="https://example.com", waf=""):
    return {"url": url, "waf": waf, "waf_detected": bool(waf)}


def _make_port(sensitive=True):
    return {"port": 3306, "service": "mysql", "is_sensitive": sensitive}


def _make_js(finding_type="aws_access_key"):
    return {"finding_type": finding_type, "value": "test"}


# ─────────────────────────────────────────────
# Constructor
# ─────────────────────────────────────────────

class TestRiskScorerInit:
    def test_creates_with_domain_and_scan_id(self):
        s = _scorer()
        assert s.domain  == "example.com"
        assert s.scan_id == "scan-001"
        assert s.overall == 0
        assert s.breakdown == {}

    def test_weights_loaded(self):
        s = _scorer()
        assert "vuln_critical" in s._weights
        assert s._weights["vuln_critical"] > 0

    def test_get_label_defaults_info(self):
        s = _scorer()
        assert s.get_label() == "INFO"

    def test_initial_scores_empty(self):
        s = _scorer()
        assert s.get_scores() == []

    def test_initial_breakdown_empty(self):
        s = _scorer()
        assert s.get_breakdown() == {}


# ─────────────────────────────────────────────
# DEFAULT_WEIGHTS
# ─────────────────────────────────────────────

class TestDefaultWeights:
    def test_critical_higher_than_high(self):
        assert DEFAULT_WEIGHTS["vuln_critical"] > DEFAULT_WEIGHTS["vuln_high"]

    def test_high_higher_than_medium(self):
        assert DEFAULT_WEIGHTS["vuln_high"] > DEFAULT_WEIGHTS["vuln_medium"]

    def test_all_positive(self):
        for k, v in DEFAULT_WEIGHTS.items():
            assert v > 0, f"{k} should be positive"

    def test_js_secret_weight_present(self):
        assert "js_secret" in DEFAULT_WEIGHTS

    def test_no_waf_weight_present(self):
        assert "no_waf" in DEFAULT_WEIGHTS


# ─────────────────────────────────────────────
# Vulnerability Scoring
# ─────────────────────────────────────────────

class TestVulnScoring:
    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_critical_vuln_adds_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"vulnerabilities": [_make_vuln("critical")]})
        assert s.overall > 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_no_vulns_zero_vuln_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"vulnerabilities": []})
        assert s.breakdown.get("vulnerabilities", 0) == 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_multiple_vulns_accumulate(self, mock_store, mock_file):
        s = _scorer()
        s.run({"vulnerabilities": [
            _make_vuln("critical"), _make_vuln("high"), _make_vuln("medium"),
        ]})
        assert s.breakdown["vulnerabilities"] > DEFAULT_WEIGHTS["vuln_medium"]

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_vuln_score_capped_at_60(self, mock_store, mock_file):
        s = _scorer()
        # 20 critical vulns — raw = 20*40 = 800, should cap at 60
        s.run({"vulnerabilities": [_make_vuln("critical") for _ in range(20)]})
        assert s.breakdown["vulnerabilities"] <= 60

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_critical_higher_than_low(self, mock_store, mock_file):
        s1 = _scorer()
        s2 = _scorer()
        s1.run({"vulnerabilities": [_make_vuln("critical")]})
        s2.run({"vulnerabilities": [_make_vuln("low")]})
        assert s1.overall > s2.overall


# ─────────────────────────────────────────────
# Sensitive Port Scoring
# ─────────────────────────────────────────────

class TestPortScoring:
    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_sensitive_port_adds_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"ports": [_make_port(sensitive=True)]})
        assert s.breakdown.get("sensitive_ports", 0) > 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_non_sensitive_port_no_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"ports": [_make_port(sensitive=False)]})
        assert s.breakdown.get("sensitive_ports", 0) == 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_port_score_capped_at_40(self, mock_store, mock_file):
        s = _scorer()
        s.run({"ports": [_make_port(sensitive=True) for _ in range(10)]})
        assert s.breakdown["sensitive_ports"] <= 40

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_empty_ports_no_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"ports": []})
        assert s.breakdown.get("sensitive_ports", 0) == 0


# ─────────────────────────────────────────────
# JS Intelligence Scoring
# ─────────────────────────────────────────────

class TestJsScoring:
    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_aws_key_adds_js_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"js_findings": [_make_js("aws_access_key")]})
        assert s.breakdown.get("js_intelligence", 0) > 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_admin_endpoint_adds_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"js_findings": [_make_js("admin_endpoint")]})
        assert s.breakdown.get("js_intelligence", 0) > 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_js_score_capped_at_40(self, mock_store, mock_file):
        s = _scorer()
        s.run({"js_findings": [_make_js("aws_access_key") for _ in range(10)]})
        assert s.breakdown["js_intelligence"] <= 40

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_plain_endpoint_no_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"js_findings": [{"finding_type": "endpoint", "value": "/api"}]})
        assert s.breakdown.get("js_intelligence", 0) == 0


# ─────────────────────────────────────────────
# WAF Absence Scoring
# ─────────────────────────────────────────────

class TestWafScoring:
    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_no_waf_adds_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"live_hosts": [_make_host(waf="")]})
        assert s.breakdown.get("no_waf", 0) > 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_waf_present_no_score(self, mock_store, mock_file):
        s = _scorer()
        s.run({"live_hosts": [_make_host(waf="Cloudflare")]})
        assert s.breakdown.get("no_waf", 0) == 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_no_waf_score_capped_at_20(self, mock_store, mock_file):
        s = _scorer()
        hosts = [_make_host(waf="") for _ in range(10)]
        s.run({"live_hosts": hosts})
        assert s.breakdown["no_waf"] <= 20


# ─────────────────────────────────────────────
# Overall Score & Label
# ─────────────────────────────────────────────

class TestOverallScore:
    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_empty_scan_score_zero(self, mock_store, mock_file):
        s = _scorer()
        result = s.run({})
        assert result == 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_overall_capped_at_100(self, mock_store, mock_file):
        s = _scorer()
        s.run({
            "vulnerabilities": [_make_vuln("critical") for _ in range(20)],
            "ports":           [_make_port() for _ in range(5)],
            "js_findings":     [_make_js("aws_access_key") for _ in range(5)],
            "live_hosts":      [_make_host(waf="") for _ in range(5)],
        })
        assert s.overall <= SCORE_CAP

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_returns_int(self, mock_store, mock_file):
        s = _scorer()
        result = s.run({})
        assert isinstance(result, int)

    @pytest.mark.parametrize("score,expected", [
        (80,  "CRITICAL"),
        (79,  "HIGH"),
        (60,  "HIGH"),
        (59,  "MEDIUM"),
        (40,  "MEDIUM"),
        (39,  "LOW"),
        (20,  "LOW"),
        (19,  "INFO"),
        (0,   "INFO"),
    ])
    def test_label_thresholds(self, score, expected):
        s = _scorer()
        s.overall = score
        assert s.get_label() == expected


# ─────────────────────────────────────────────
# Score Records
# ─────────────────────────────────────────────

class TestScoreRecords:
    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_scan_record_always_present(self, mock_store, mock_file):
        s = _scorer()
        s.run({})
        scan_records = [r for r in s.scores if r["asset_type"] == "scan"]
        assert len(scan_records) == 1

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_per_host_record_created(self, mock_store, mock_file):
        s = _scorer()
        s.run({"live_hosts": [_make_host("https://sub.example.com")]})
        host_records = [r for r in s.scores if r["asset_type"] == "live_host"]
        assert len(host_records) == 1
        assert host_records[0]["asset_id"] == "https://sub.example.com"

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_host_score_below_100(self, mock_store, mock_file):
        s = _scorer()
        s.run({"live_hosts": [_make_host()]})
        for rec in s.scores:
            assert rec["score"] <= 100

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.RiskScorer._store_scores")
    def test_file_saved_called(self, mock_store, mock_file):
        s = _scorer()
        s.run({})
        mock_file.assert_called_once()
