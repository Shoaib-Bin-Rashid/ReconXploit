"""Unit tests for Phase 7b — Alerts module."""
import json
import pytest
from unittest.mock import patch, MagicMock, call
from backend.modules.alerts import AlertManager, ALERT_SCORE_THRESHOLD, MAX_FINDINGS_IN_MSG


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _manager(domain="example.com", config=None):
    m = AlertManager(domain, "scan-001")
    if config is not None:
        m._config = config
    return m


def _make_change(change_type="new_sensitive_port", severity="high", significant=True):
    return {
        "change_type":   change_type,
        "severity":      severity,
        "asset_id":      "192.168.1.1:3306",
        "is_significant": significant,
    }


def _make_vuln(severity="critical", url="https://example.com"):
    return {"vulnerability_name": "test-vuln", "severity": severity, "matched_at": url}


def _make_js_secret(secret_type="aws_access_key"):
    return {"finding_type": secret_type, "secret_type": secret_type, "value": "test"}


def _telegram_config():
    return {
        "telegram": {"enabled": True, "bot_token": "fake_token", "chat_id": "123456"},
    }


def _discord_config():
    return {
        "discord": {"enabled": True, "webhook_url": "https://discord.com/api/webhooks/fake"},
    }


def _slack_config():
    return {
        "slack": {"enabled": True, "webhook_url": "https://hooks.slack.com/services/fake"},
    }


# ─────────────────────────────────────────────
# Constructor
# ─────────────────────────────────────────────

class TestAlertManagerInit:
    def test_stores_domain(self):
        m = _manager()
        assert m.domain == "example.com"

    def test_stores_scan_id(self):
        m = _manager()
        assert m.scan_id == "scan-001"

    def test_initial_sent_empty(self):
        m = _manager()
        assert m.get_sent() == []

    def test_is_enabled_false_by_default(self):
        m = _manager(config={})
        assert not m._is_enabled("telegram")
        assert not m._is_enabled("discord")
        assert not m._is_enabled("slack")


# ─────────────────────────────────────────────
# Should-Alert Logic
# ─────────────────────────────────────────────

class TestShouldAlert:
    @patch("backend.modules.alerts.AlertManager._store_alert")
    def test_no_alert_below_threshold_no_findings(self, mock_store):
        m = _manager(config={})
        result = m.run(
            risk_score=10,
            scan_data={},
            changes=[],
        )
        assert result == 0
        mock_store.assert_not_called()

    @patch("backend.modules.alerts.AlertManager._store_alert")
    def test_alert_triggered_by_risk_score(self, mock_store):
        m = _manager(config={})
        # No channels configured — but should_alert=True so store_alert IS called
        result = m.run(
            risk_score=ALERT_SCORE_THRESHOLD,
            scan_data={},
            changes=[],
        )
        mock_store.assert_called_once()

    @patch("backend.modules.alerts.AlertManager._store_alert")
    def test_alert_triggered_by_significant_change(self, mock_store):
        m = _manager(config={})
        result = m.run(
            risk_score=0,
            scan_data={},
            changes=[_make_change()],
        )
        mock_store.assert_called_once()

    @patch("backend.modules.alerts.AlertManager._store_alert")
    def test_alert_triggered_by_critical_vuln(self, mock_store):
        m = _manager(config={})
        result = m.run(
            risk_score=0,
            scan_data={"vulnerabilities": [_make_vuln("critical")]},
            changes=[],
        )
        mock_store.assert_called_once()

    @patch("backend.modules.alerts.AlertManager._store_alert")
    def test_alert_triggered_by_js_secret(self, mock_store):
        m = _manager(config={})
        result = m.run(
            risk_score=0,
            scan_data={"js_findings": [_make_js_secret()]},
            changes=[],
        )
        mock_store.assert_called_once()

    @patch("backend.modules.alerts.AlertManager._store_alert")
    def test_non_significant_change_no_trigger(self, mock_store):
        m = _manager(config={})
        result = m.run(
            risk_score=0,
            scan_data={},
            changes=[_make_change(significant=False)],
        )
        assert result == 0
        mock_store.assert_not_called()


# ─────────────────────────────────────────────
# Message Builder
# ─────────────────────────────────────────────

class TestMessageBuilder:
    def test_message_contains_domain(self):
        m = _manager()
        msg = m._build_message(50, {}, [], [], [], [])
        assert "example.com" in msg

    def test_message_contains_risk_score(self):
        m = _manager()
        msg = m._build_message(75, {}, [], [], [], [])
        assert "75/100" in msg

    def test_message_contains_significant_change(self):
        m = _manager()
        changes = [_make_change("new_sensitive_port")]
        msg = m._build_message(50, {}, changes, [], [], [])
        assert "new_sensitive_port" in msg

    def test_message_contains_critical_vuln(self):
        m = _manager()
        vulns = [_make_vuln("critical")]
        msg = m._build_message(80, {}, [], vulns, [], [])
        assert "test-vuln" in msg
        assert "CRITICAL" in msg.upper()

    def test_message_contains_js_secret(self):
        m = _manager()
        secrets = [_make_js_secret("aws_access_key")]
        msg = m._build_message(60, {}, [], [], [], secrets)
        assert "AWS" in msg.upper() or "aws" in msg.lower()

    def test_message_contains_summary(self):
        m = _manager()
        scan_data = {
            "subdomains":      ["a.com", "b.com"],
            "live_hosts":      [{"url": "https://a.com"}],
            "ports":           [{"port": 80}],
            "vulnerabilities": [],
            "js_findings":     [],
        }
        msg = m._build_message(30, scan_data, [], [], [], [])
        assert "Subdomains" in msg
        assert "2" in msg   # 2 subdomains

    def test_change_list_truncated_at_max(self):
        m = _manager()
        changes = [_make_change() for _ in range(MAX_FINDINGS_IN_MSG + 5)]
        msg = m._build_message(50, {}, changes, [], [], [])
        assert "more" in msg.lower()

    @pytest.mark.parametrize("score,expected_label", [
        (85, "CRITICAL"),
        (65, "HIGH"),
        (50, "MEDIUM"),
        (30, "LOW"),
        (10, "INFO"),
    ])
    def test_risk_label(self, score, expected_label):
        assert expected_label in AlertManager._risk_label(score)


# ─────────────────────────────────────────────
# Telegram Sender
# ─────────────────────────────────────────────

class TestTelegramSender:
    @patch("urllib.request.urlopen")
    def test_sends_telegram_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({"ok": True}).encode()
        mock_urlopen.return_value = mock_resp

        m = _manager(config=_telegram_config())
        result = m._send_telegram("test message")
        assert result is True
        mock_urlopen.assert_called_once()

    @patch("urllib.request.urlopen")
    def test_telegram_api_error_returns_false(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({"ok": False, "error": "bad"}).encode()
        mock_urlopen.return_value = mock_resp

        m = _manager(config=_telegram_config())
        result = m._send_telegram("test message")
        assert result is False

    def test_telegram_no_token_returns_false(self):
        m = _manager(config={"telegram": {"enabled": True, "bot_token": "", "chat_id": ""}})
        result = m._send_telegram("test")
        assert result is False

    @patch("urllib.request.urlopen", side_effect=Exception("network error"))
    def test_telegram_exception_returns_false(self, mock_urlopen):
        m = _manager(config=_telegram_config())
        result = m._send_telegram("test")
        assert result is False

    def test_telegram_disabled_channel_skipped(self):
        m = _manager(config={"telegram": {"enabled": False, "bot_token": "tok", "chat_id": "1"}})
        assert not m._is_enabled("telegram")


# ─────────────────────────────────────────────
# Discord Sender
# ─────────────────────────────────────────────

class TestDiscordSender:
    @patch("urllib.request.urlopen")
    def test_sends_discord_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        m = _manager(config=_discord_config())
        result = m._send_discord("test message")
        assert result is True

    def test_discord_no_url_returns_false(self):
        m = _manager(config={"discord": {"enabled": True, "webhook_url": ""}})
        result = m._send_discord("test")
        assert result is False

    @patch("urllib.request.urlopen", side_effect=Exception("network error"))
    def test_discord_exception_returns_false(self, mock_urlopen):
        m = _manager(config=_discord_config())
        result = m._send_discord("test")
        assert result is False


# ─────────────────────────────────────────────
# Slack Sender
# ─────────────────────────────────────────────

class TestSlackSender:
    @patch("urllib.request.urlopen")
    def test_sends_slack_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        m = _manager(config=_slack_config())
        result = m._send_slack("test message")
        assert result is True

    def test_slack_no_url_returns_false(self):
        m = _manager(config={"slack": {"enabled": True, "webhook_url": ""}})
        result = m._send_slack("test")
        assert result is False

    @patch("urllib.request.urlopen", side_effect=Exception("network error"))
    def test_slack_exception_returns_false(self, mock_urlopen):
        m = _manager(config=_slack_config())
        result = m._send_slack("test")
        assert result is False


# ─────────────────────────────────────────────
# Full run() — channel counting
# ─────────────────────────────────────────────

class TestRunChannelCount:
    @patch("backend.modules.alerts.AlertManager._store_alert")
    @patch("urllib.request.urlopen")
    def test_telegram_channel_counted(self, mock_urlopen, mock_store):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({"ok": True}).encode()
        mock_urlopen.return_value = mock_resp

        m = _manager(config=_telegram_config())
        result = m.run(
            risk_score=50,
            scan_data={},
            changes=[_make_change()],
        )
        assert result == 1

    @patch("backend.modules.alerts.AlertManager._store_alert")
    @patch("urllib.request.urlopen")
    def test_all_channels_count(self, mock_urlopen, mock_store):
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = json.dumps({"ok": True}).encode()
        mock_urlopen.return_value = mock_resp

        config = {**_telegram_config(), **_discord_config(), **_slack_config()}
        m = _manager(config=config)
        result = m.run(
            risk_score=50,
            scan_data={},
            changes=[_make_change()],
        )
        assert result == 3

    @patch("backend.modules.alerts.AlertManager._store_alert")
    def test_no_channels_returns_zero(self, mock_store):
        m = _manager(config={})
        result = m.run(
            risk_score=80,
            scan_data={},
            changes=[_make_change()],
        )
        assert result == 0
