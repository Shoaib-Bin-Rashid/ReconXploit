"""Integration tests for Phase 7a — Risk Scoring (DB)."""
import pytest
from unittest.mock import patch
from backend.modules.risk_scoring import RiskScorer


DOMAIN  = "riskscore-test.com"
SCAN_ID = "scan-risk-001"


def _make_vuln(severity="medium", url="https://riskscore-test.com"):
    return {"vulnerability_name": "test", "severity": severity, "matched_at": url}


def _make_host(url="https://riskscore-test.com", waf=""):
    return {"url": url, "waf": waf, "waf_detected": bool(waf)}


def _make_port(sensitive=True):
    return {"port": 3306, "service": "mysql", "is_sensitive": sensitive}


# ─────────────────────────────────────────────
# DB Integration
# ─────────────────────────────────────────────

class TestRiskScoreDBIntegration:
    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.get_db_context")
    def test_stores_to_db(self, mock_ctx, mock_file, sqlite_session):
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        scorer = RiskScorer(DOMAIN, SCAN_ID)
        score  = scorer.run({
            "vulnerabilities": [_make_vuln("high")],
            "live_hosts":      [_make_host()],
        })
        assert score >= 0

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.get_db_context")
    def test_handles_missing_target(self, mock_ctx, mock_file, sqlite_session):
        """Should not crash when target is not in DB."""
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        scorer = RiskScorer("unknown-target.com", "scan-xyz")
        score  = scorer.run({"vulnerabilities": [_make_vuln()]})
        assert isinstance(score, int)

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.get_db_context")
    def test_file_saved(self, mock_ctx, mock_file, sqlite_session):
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        scorer = RiskScorer(DOMAIN, SCAN_ID)
        scorer.run({"vulnerabilities": [_make_vuln("critical")]})
        mock_file.assert_called_once()
        args = mock_file.call_args[0]
        assert args[0] == DOMAIN      # domain
        assert args[1] >= 0           # overall score

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.get_db_context")
    def test_breakdown_has_expected_keys(self, mock_ctx, mock_file, sqlite_session):
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        scorer = RiskScorer(DOMAIN, SCAN_ID)
        scorer.run({
            "vulnerabilities": [_make_vuln("critical")],
            "ports":           [_make_port()],
            "js_findings":     [{"finding_type": "aws_access_key", "value": "test"}],
            "live_hosts":      [_make_host()],
        })
        bd = scorer.get_breakdown()
        assert "vulnerabilities"     in bd
        assert "sensitive_ports"     in bd
        assert "js_intelligence"     in bd
        assert "no_waf"              in bd

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.get_db_context")
    def test_db_error_does_not_crash(self, mock_ctx, mock_file, sqlite_session):
        """DB errors should be caught and not propagate."""
        mock_ctx.side_effect = Exception("DB connection failed")

        scorer = RiskScorer(DOMAIN, SCAN_ID)
        score  = scorer.run({"vulnerabilities": [_make_vuln()]})
        assert isinstance(score, int)

    @patch("backend.modules.risk_scoring.save_risk_scores")
    @patch("backend.modules.risk_scoring.get_db_context")
    def test_scores_list_contains_scan_record(self, mock_ctx, mock_file, sqlite_session):
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__ = lambda s, *a: False

        scorer = RiskScorer(DOMAIN, SCAN_ID)
        scorer.run({"live_hosts": [_make_host()]})
        types = [r["asset_type"] for r in scorer.get_scores()]
        assert "scan" in types
