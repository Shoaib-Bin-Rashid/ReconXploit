"""Unit tests for Phase 8 — Screenshot module."""
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from backend.modules.screenshots import ScreenshotEngine, SCREENSHOTS_DIR, TIMEOUT_SECONDS, MAX_URLS


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _engine(domain="example.com", scan_id="scan-001"):
    return ScreenshotEngine(domain, scan_id)


def _host(url="https://example.com"):
    return {"url": url, "status_code": 200}


# ─────────────────────────────────────────────
# Constructor
# ─────────────────────────────────────────────

class TestScreenshotEngineInit:
    def test_domain_stored(self):
        e = _engine()
        assert e.domain == "example.com"

    def test_scan_id_stored(self):
        e = _engine()
        assert e.scan_id == "scan-001"

    def test_results_initially_empty(self):
        e = _engine()
        assert e.get_results() == []

    def test_gallery_initially_empty(self):
        e = _engine()
        assert e.get_gallery() == []

    def test_output_dir_created(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        e = ScreenshotEngine("newdomain.com", "scan-x")
        assert (tmp_path / "data" / "screenshots" / "newdomain.com").exists()


# ─────────────────────────────────────────────
# URL Extraction
# ─────────────────────────────────────────────

class TestUrlExtraction:
    def test_extracts_urls_from_hosts(self):
        e = _engine()
        hosts = [_host("https://a.com"), _host("https://b.com")]
        urls = e._extract_urls(hosts)
        assert urls == ["https://a.com", "https://b.com"]

    def test_deduplicates_urls(self):
        e = _engine()
        hosts = [_host("https://a.com"), _host("https://a.com")]
        urls = e._extract_urls(hosts)
        assert len(urls) == 1

    def test_skips_empty_urls(self):
        e = _engine()
        hosts = [{"url": ""}, {"url": "   "}, _host("https://a.com")]
        urls = e._extract_urls(hosts)
        assert urls == ["https://a.com"]

    def test_preserves_order(self):
        e = _engine()
        hosts = [_host("https://z.com"), _host("https://a.com"), _host("https://m.com")]
        urls = e._extract_urls(hosts)
        assert urls == ["https://z.com", "https://a.com", "https://m.com"]

    def test_handles_empty_list(self):
        e = _engine()
        assert e._extract_urls([]) == []


# ─────────────────────────────────────────────
# URL to Slug
# ─────────────────────────────────────────────

class TestUrlToSlug:
    def test_removes_https(self):
        slug = ScreenshotEngine._url_to_slug("https://example.com")
        assert "https" not in slug

    def test_removes_http(self):
        slug = ScreenshotEngine._url_to_slug("http://example.com")
        assert "http" not in slug

    def test_replaces_dots(self):
        slug = ScreenshotEngine._url_to_slug("https://sub.example.com")
        assert "." not in slug

    def test_replaces_slashes(self):
        slug = ScreenshotEngine._url_to_slug("https://example.com/path")
        assert "/" not in slug

    def test_max_length_80(self):
        long_url = "https://" + "a" * 200 + ".com"
        slug = ScreenshotEngine._url_to_slug(long_url)
        assert len(slug) <= 80

    def test_only_safe_chars(self):
        slug = ScreenshotEngine._url_to_slug("https://example.com:8080/path?q=1")
        for c in slug:
            assert c.isalnum() or c in "_-"


# ─────────────────────────────────────────────
# Base Record
# ─────────────────────────────────────────────

class TestBaseRecord:
    def test_has_required_keys(self):
        e = _engine()
        rec = e._base_record("https://example.com")
        for key in ("url", "domain", "file_path", "file_size_bytes",
                    "page_title", "status_code", "tool", "error", "captured_at"):
            assert key in rec

    def test_url_set(self):
        e = _engine()
        rec = e._base_record("https://example.com")
        assert rec["url"] == "https://example.com"

    def test_domain_extracted(self):
        e = _engine()
        rec = e._base_record("https://sub.example.com")
        assert rec["domain"] == "sub.example.com"

    def test_defaults_none(self):
        e = _engine()
        rec = e._base_record("https://example.com")
        assert rec["file_path"] is None
        assert rec["tool"] is None


# ─────────────────────────────────────────────
# Run — no hosts
# ─────────────────────────────────────────────

class TestRunNoHosts:
    @patch("backend.modules.screenshots.ScreenshotEngine._store_results")
    @patch("backend.utils.file_storage.save_screenshots")
    def test_empty_hosts_returns_zero(self, mock_file, mock_store):
        e = _engine()
        result = e.run([])
        assert result == 0
        mock_store.assert_not_called()

    @patch("backend.modules.screenshots.ScreenshotEngine._store_results")
    @patch("backend.utils.file_storage.save_screenshots")
    def test_no_url_hosts_returns_zero(self, mock_file, mock_store):
        e = _engine()
        result = e.run([{"url": ""}, {"url": "   "}])
        assert result == 0


# ─────────────────────────────────────────────
# URL Cap
# ─────────────────────────────────────────────

class TestUrlCap:
    @patch("backend.modules.screenshots.ScreenshotEngine._run_html_preview")
    @patch("backend.modules.screenshots.ScreenshotEngine._has_chrome", return_value=False)
    @patch("backend.modules.screenshots.ScreenshotEngine._has_tool",   return_value=False)
    @patch("backend.modules.screenshots.ScreenshotEngine._store_results")
    @patch("backend.modules.screenshots.save_screenshots")
    def test_caps_at_max_urls(self, mock_file, mock_store, mock_tool, mock_chrome, mock_preview):
        mock_preview.return_value = []
        e = _engine()
        many_hosts = [_host(f"https://h{i}.com") for i in range(MAX_URLS + 50)]
        e.run(many_hosts)
        called_urls = mock_preview.call_args[0][0]
        assert len(called_urls) <= MAX_URLS


# ─────────────────────────────────────────────
# HTML Preview Fallback
# ─────────────────────────────────────────────

class TestHtmlPreviewFallback:
    @patch("urllib.request.urlopen")
    def test_preview_success(self, mock_urlopen, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"<html><title>Test Title</title></html>"
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_urlopen.return_value = mock_resp

        e = ScreenshotEngine("example.com", "scan-1")
        results = e._run_html_preview(["https://example.com"])
        assert len(results) == 1
        assert results[0]["page_title"] == "Test Title"
        assert results[0]["status_code"] == 200
        assert results[0]["tool"] == "html-preview"

    @patch("urllib.request.urlopen")
    def test_preview_http_error(self, mock_urlopen, tmp_path, monkeypatch):
        import urllib.error
        monkeypatch.chdir(tmp_path)
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://example.com", code=403, msg="Forbidden", hdrs={}, fp=None
        )
        e = ScreenshotEngine("example.com", "scan-1")
        results = e._run_html_preview(["https://example.com"])
        assert results[0]["status_code"] == 403

    @patch("urllib.request.urlopen")
    def test_preview_network_error(self, mock_urlopen, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_urlopen.side_effect = Exception("Connection refused")
        e = ScreenshotEngine("example.com", "scan-1")
        results = e._run_html_preview(["https://example.com"])
        assert "Connection refused" in results[0]["error"]

    @patch("urllib.request.urlopen")
    def test_preview_creates_file(self, mock_urlopen, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"<html><title>T</title></html>"
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_urlopen.return_value = mock_resp

        e = ScreenshotEngine("example.com", "scan-1")
        results = e._run_html_preview(["https://example.com"])
        assert results[0]["file_path"] is not None
        assert Path(results[0]["file_path"]).exists()

    @patch("urllib.request.urlopen")
    def test_preview_multiple_urls(self, mock_urlopen, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b"<html><title>T</title></html>"
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_urlopen.return_value = mock_resp

        e = ScreenshotEngine("example.com", "scan-1")
        results = e._run_html_preview([
            "https://a.example.com",
            "https://b.example.com",
        ])
        assert len(results) == 2


# ─────────────────────────────────────────────
# gowitness — not found
# ─────────────────────────────────────────────

class TestGowitnessFallback:
    @patch("backend.modules.screenshots.ScreenshotEngine._run_html_preview")
    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_falls_back_on_file_not_found(self, mock_run, mock_preview, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_preview.return_value = [{"url": "https://example.com", "file_path": None}]
        e = ScreenshotEngine("example.com", "scan-1")
        e._run_gowitness(["https://example.com"])
        mock_preview.assert_called_once()

    @patch("backend.modules.screenshots.ScreenshotEngine._run_html_preview")
    @patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired(cmd="gowitness", timeout=10))
    def test_falls_back_on_timeout(self, mock_run, mock_preview, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_preview.return_value = []
        e = ScreenshotEngine("example.com", "scan-1")
        e._run_gowitness(["https://example.com"])
        mock_preview.assert_called_once()


# ─────────────────────────────────────────────
# Tool detection
# ─────────────────────────────────────────────

class TestToolDetection:
    def test_has_tool_returns_bool(self):
        result = ScreenshotEngine._has_tool("totally_fake_tool_xyz")
        assert result is False

    def test_has_chrome_returns_bool(self):
        result = ScreenshotEngine._has_chrome()
        assert isinstance(result, bool)

    def test_find_chrome_none_or_str(self):
        result = ScreenshotEngine._find_chrome()
        assert result is None or isinstance(result, str)


# ─────────────────────────────────────────────
# Gallery filter
# ─────────────────────────────────────────────

class TestGallery:
    def test_gallery_returns_only_captured(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        e = ScreenshotEngine("example.com", "scan-1")
        e.results = [
            {"url": "https://a.com", "file_path": "data/screenshots/a.png"},
            {"url": "https://b.com", "file_path": None},
            {"url": "https://c.com", "preview": True, "file_path": "data/x.txt"},
        ]
        gallery = e.get_gallery()
        assert len(gallery) == 2
        urls = [r["url"] for r in gallery]
        assert "https://b.com" not in urls


# ─────────────────────────────────────────────
# DB Storage
# ─────────────────────────────────────────────

class TestDbStorage:
    @patch("backend.modules.screenshots.get_db_context")
    def test_db_error_does_not_crash(self, mock_ctx, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        mock_ctx.side_effect = Exception("DB down")
        e = ScreenshotEngine("example.com", "scan-1")
        e.results = [{"url": "https://example.com", "file_path": None, "tool": None}]
        e._store_results()  # should not raise

    @patch("backend.modules.screenshots.get_db_context")
    def test_empty_results_skips_db(self, mock_ctx, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        e = ScreenshotEngine("example.com", "scan-1")
        e._store_results()
        mock_ctx.assert_not_called()
