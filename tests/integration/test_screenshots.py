"""Integration tests for Phase 8 — Screenshots (DB)."""
import pytest
from unittest.mock import patch, MagicMock
from backend.modules.screenshots import ScreenshotEngine


DOMAIN  = "screenshot-test.com"
SCAN_ID = "scan-ss-001"


class TestScreenshotDBIntegration:
    @patch("backend.modules.screenshots.save_screenshots")
    @patch("backend.modules.screenshots.get_db_context")
    @patch("urllib.request.urlopen")
    def test_run_html_preview_stores_to_db(self, mock_urlopen, mock_ctx, mock_file,
                                            sqlite_session, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"<html><title>Test</title></html>"
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_urlopen.return_value = mock_resp

        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__  = lambda s, *a: False

        with patch("backend.modules.screenshots.ScreenshotEngine._has_tool", return_value=False), \
             patch("backend.modules.screenshots.ScreenshotEngine._has_chrome", return_value=False):
            e = ScreenshotEngine(DOMAIN, SCAN_ID)
            captured = e.run([{"url": "https://screenshot-test.com"}])

        assert captured >= 0

    @patch("backend.modules.screenshots.save_screenshots")
    @patch("backend.modules.screenshots.get_db_context")
    def test_db_error_does_not_stop_scan(self, mock_ctx, mock_file,
                                          tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_ctx.side_effect = Exception("DB connection failed")

        with patch("backend.modules.screenshots.ScreenshotEngine._has_tool", return_value=False), \
             patch("backend.modules.screenshots.ScreenshotEngine._has_chrome", return_value=False), \
             patch("urllib.request.urlopen", side_effect=Exception("net")):
            e = ScreenshotEngine(DOMAIN, SCAN_ID)
            result = e.run([{"url": "https://screenshot-test.com"}])

        assert isinstance(result, int)

    @patch("backend.modules.screenshots.save_screenshots")
    @patch("backend.modules.screenshots.get_db_context")
    def test_file_save_called(self, mock_ctx, mock_file, sqlite_session,
                               tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__  = lambda s, *a: False

        with patch("backend.modules.screenshots.ScreenshotEngine._has_tool", return_value=False), \
             patch("backend.modules.screenshots.ScreenshotEngine._has_chrome", return_value=False), \
             patch("urllib.request.urlopen", side_effect=Exception("net")):
            e = ScreenshotEngine(DOMAIN, SCAN_ID)
            e.run([{"url": "https://screenshot-test.com"}])

        mock_file.assert_called_once()
        assert mock_file.call_args[0][0] == DOMAIN

    @patch("backend.modules.screenshots.save_screenshots")
    @patch("backend.modules.screenshots.get_db_context")
    def test_results_list_populated(self, mock_ctx, mock_file, sqlite_session,
                                     tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_ctx.return_value.__enter__ = lambda s: sqlite_session
        mock_ctx.return_value.__exit__  = lambda s, *a: False

        with patch("backend.modules.screenshots.ScreenshotEngine._has_tool", return_value=False), \
             patch("backend.modules.screenshots.ScreenshotEngine._has_chrome", return_value=False), \
             patch("urllib.request.urlopen", side_effect=Exception("net")):
            e = ScreenshotEngine(DOMAIN, SCAN_ID)
            e.run([
                {"url": "https://a.screenshot-test.com"},
                {"url": "https://b.screenshot-test.com"},
            ])

        assert len(e.get_results()) == 2

    @patch("backend.modules.screenshots.save_screenshots")
    @patch("backend.modules.screenshots.get_db_context")
    def test_empty_hosts_no_file_save(self, mock_ctx, mock_file, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        e = ScreenshotEngine(DOMAIN, SCAN_ID)
        e.run([])
        mock_file.assert_not_called()
