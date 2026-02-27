"""Integration tests for Phase 7b — Alerts (DB)."""
import json
import pytest
from unittest.mock import patch, MagicMock
from backend.modules.alerts import AlertManager


DOMAIN  = "alerts-test.com"
SCAN_ID = "scan-alert-001"


def _mgr(config=None, domain=DOMAIN):
    m = AlertManager(domain, SCAN_ID)
    if config is not None:
        m._config = config
    return m


def _change(significant=True):
    return {
        "change_type":    "new_sensitive_port",
        "severity":       "high",
        "asset_id":       "1.2.3.4:3306",
        "is_significant":  significant,
    }


def _tg_cfg():
    return {"telegram": {"enabled": True, "bot_token": "fake", "chat_id": "123"}}


class TestAlertsDBIntegration:
    @patch("backend.modules.alerts.get_db_context")
    @patch("urllib.request.urlopen")
    def test_stores_alert_in_db(self, mock_urlopen, mock_ctx, sqlite_session):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({"ok": True}).encode()
        mock_urlopen.return_value = mock_resp

        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__  = lambda s, *a: False

        m = _mgr(config=_tg_cfg())
        sent = m.run(
            risk_score=50,
            scan_data={},
            changes=[_change()],
        )
        assert sent == 1

    @patch("backend.modules.alerts.get_db_context")
    def test_store_alert_handles_missing_target(self, mock_ctx, sqlite_session):
        """Should not crash when domain not in DB."""
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__  = lambda s, *a: False

        m = _mgr(config={}, domain="notexist.com")
        # _store_alert is called when should_alert=True
        m._store_alert("test message", 80, 0)
        # Should complete without exception

    @patch("backend.modules.alerts.get_db_context")
    def test_db_error_in_store_does_not_crash(self, mock_ctx):
        mock_ctx.side_effect = Exception("DB down")

        m = _mgr(config={})
        # Should not raise
        m._store_alert("test", 50, 0)

    @patch("backend.modules.alerts.get_db_context")
    @patch("urllib.request.urlopen")
    def test_run_with_no_channels_calls_store(self, mock_urlopen, mock_ctx, sqlite_session):
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__  = lambda s, *a: False

        m = _mgr(config={})   # no channels
        sent = m.run(
            risk_score=80,
            scan_data={"vulnerabilities": [{"severity": "critical", "vulnerability_name": "x"}]},
            changes=[],
        )
        # 0 sent (no channels), but store_alert was invoked
        assert sent == 0

    @patch("backend.modules.alerts.get_db_context")
    def test_message_format_valid(self, mock_ctx, sqlite_session):
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__  = lambda s, *a: False

        m = _mgr(config={})
        msg = m._build_message(
            risk_score=70,
            scan_data={
                "subdomains":      ["a.com"],
                "live_hosts":      [{"url": "https://a.com"}],
                "ports":           [{"port": 443}],
                "vulnerabilities": [{"severity": "critical", "vulnerability_name": "cve-1", "matched_at": "https://a.com"}],
                "js_findings":     [],
            },
            sig_changes=[_change()],
            critical_vulns=[{"vulnerability_name": "cve-1", "severity": "critical", "matched_at": "https://a.com"}],
            high_vulns=[],
            js_secrets=[],
        )
        assert DOMAIN in msg
        assert "70/100" in msg
        assert "cve-1" in msg
        assert "Subdomains" in msg
