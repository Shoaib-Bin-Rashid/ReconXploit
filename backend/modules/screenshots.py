"""
ReconXploit - Screenshot Capture Module
Phase 8: Take screenshots of live hosts and build a visual recon gallery.

Primary tool:   gowitness (Go binary — fast, headless Chrome)
Fallback:       headless Chrome/Chromium via subprocess (--screenshot flag)
Last fallback:  curl + HTML response preview

Output:
  - data/screenshots/{domain}/   (PNG files per host)
  - data/screenshots/{domain}.txt  (index of captured hosts)
  - screenshots table in DB

Each screenshot record includes:
  url, file_path, status_code, page_title, file_size_bytes, captured_at
"""

import json
import logging
import os
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from backend.models.database import get_db_context
from backend.utils.file_storage import save_screenshots

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

SCREENSHOTS_DIR = Path("data/screenshots")
TIMEOUT_SECONDS = 20
MAX_URLS        = 200    # cap to avoid very long runs


class ScreenshotEngine:
    """
    Captures screenshots of live hosts.
    Tries gowitness first, falls back to headless Chrome, then curl preview.
    """

    def __init__(self, domain: str, scan_id: str):
        self.domain   = domain
        self.scan_id  = scan_id
        self.results: List[Dict] = []
        self._output_dir = SCREENSHOTS_DIR / domain
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────

    def run(self, live_hosts: List[Dict]) -> int:
        """
        Take screenshots of all live hosts.

        Args:
            live_hosts: list of host dicts from Phase 2 validation
                        (each has 'url' key)

        Returns:
            Number of screenshots captured.
        """
        urls = self._extract_urls(live_hosts)
        if not urls:
            logger.info(f"[Phase 8] No live hosts to screenshot for {self.domain}")
            return 0

        # Cap
        urls = urls[:MAX_URLS]
        logger.info(f"[Phase 8] Screenshotting {len(urls)} URLs for {self.domain}")

        # Try tools in order of preference
        if self._has_tool("gowitness"):
            self.results = self._run_gowitness(urls)
        elif self._has_chrome():
            self.results = self._run_chrome_headless(urls)
        else:
            logger.warning("[Phase 8] No screenshot tool available — using HTML preview fallback")
            self.results = self._run_html_preview(urls)

        # Save to DB + text file
        self._store_results()
        save_screenshots(self.domain, self.results)

        captured = sum(1 for r in self.results if r.get("file_path") or r.get("preview"))
        logger.info(f"[Phase 8] Captured {captured}/{len(urls)} screenshots for {self.domain}")
        return captured

    def get_results(self) -> List[Dict]:
        return self.results

    def get_gallery(self) -> List[Dict]:
        """Return only results that have a file or preview."""
        return [r for r in self.results if r.get("file_path") or r.get("preview")]

    # ─────────────────────────────────────────────────
    # GOWITNESS
    # ─────────────────────────────────────────────────

    def _run_gowitness(self, urls: List[str]) -> List[Dict]:
        """Run gowitness file-based screenshot batch."""
        results = []

        # Write URL list to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            url_file = f.name

        try:
            cmd = [
                "gowitness", "file",
                "--file",      url_file,
                "--screenshot-path", str(self._output_dir),
                "--timeout",   str(TIMEOUT_SECONDS),
                "--disable-db",
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=TIMEOUT_SECONDS * len(urls) + 60,
            )
            logger.debug(f"[Phase 8] gowitness stdout: {proc.stdout[:500]}")
            if proc.returncode != 0:
                logger.warning(f"[Phase 8] gowitness non-zero exit: {proc.stderr[:300]}")

            # Collect PNG files created
            png_files = {f.stem.lower(): f for f in self._output_dir.glob("*.png")}

            for url in urls:
                rec = self._base_record(url)
                # gowitness names files by URL slug
                slug = self._url_to_slug(url).lower()
                matched = next((p for s, p in png_files.items() if slug in s or s in slug), None)
                if matched:
                    rec["file_path"]       = str(matched)
                    rec["file_size_bytes"] = matched.stat().st_size
                    rec["tool"]            = "gowitness"
                results.append(rec)

        except FileNotFoundError:
            logger.warning("[Phase 8] gowitness binary not found")
            results = self._run_html_preview(urls)
        except subprocess.TimeoutExpired:
            logger.warning("[Phase 8] gowitness timed out")
            results = self._run_html_preview(urls)
        except Exception as e:
            logger.warning(f"[Phase 8] gowitness error: {e}")
            results = self._run_html_preview(urls)
        finally:
            try:
                os.unlink(url_file)
            except Exception:
                pass

        return results

    # ─────────────────────────────────────────────────
    # HEADLESS CHROME
    # ─────────────────────────────────────────────────

    def _run_chrome_headless(self, urls: List[str]) -> List[Dict]:
        """Run headless Chrome one URL at a time."""
        chrome = self._find_chrome()
        results = []

        for url in urls:
            rec = self._base_record(url)
            slug = self._url_to_slug(url)
            out_file = self._output_dir / f"{slug}.png"

            try:
                cmd = [
                    chrome,
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--hide-scrollbars",
                    "--window-size=1280,800",
                    f"--screenshot={out_file}",
                    f"--timeout={TIMEOUT_SECONDS * 1000}",
                    url,
                ]
                proc = subprocess.run(
                    cmd,
                    capture_output=True, text=True,
                    timeout=TIMEOUT_SECONDS + 10,
                )
                if out_file.exists() and out_file.stat().st_size > 0:
                    rec["file_path"]       = str(out_file)
                    rec["file_size_bytes"] = out_file.stat().st_size
                    rec["tool"]            = "chrome-headless"
                else:
                    logger.debug(f"[Phase 8] Chrome no output for {url}: {proc.stderr[:200]}")

            except subprocess.TimeoutExpired:
                logger.debug(f"[Phase 8] Chrome timeout for {url}")
            except Exception as e:
                logger.debug(f"[Phase 8] Chrome error for {url}: {e}")

            results.append(rec)

        return results

    # ─────────────────────────────────────────────────
    # HTML PREVIEW FALLBACK
    # ─────────────────────────────────────────────────

    def _run_html_preview(self, urls: List[str]) -> List[Dict]:
        """
        Fallback: fetch HTTP response and save title + status as a text preview.
        Saves a .txt file instead of a PNG — still useful for recon.
        """
        import urllib.request
        import urllib.error
        import re

        results = []

        for url in urls:
            rec = self._base_record(url)
            slug = self._url_to_slug(url)
            out_file = self._output_dir / f"{slug}_preview.txt"

            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (ReconXploit/1.0)"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    html_bytes = resp.read(8192)
                    html = html_bytes.decode("utf-8", errors="replace")

                    # Extract title
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
                    title = title_match.group(1).strip()[:200] if title_match else ""
                    title = re.sub(r"\s+", " ", title)

                    rec["page_title"]   = title
                    rec["status_code"]  = resp.status
                    rec["content_type"] = resp.headers.get("Content-Type", "")

                    # Save preview file
                    preview_text = (
                        f"URL:          {url}\n"
                        f"Status:       {resp.status}\n"
                        f"Title:        {title}\n"
                        f"Content-Type: {rec['content_type']}\n"
                        f"Captured at:  {rec['captured_at']}\n"
                        f"---\n"
                        f"HTML preview (first 2KB):\n"
                        f"{html[:2048]}\n"
                    )
                    out_file.write_text(preview_text, encoding="utf-8")
                    rec["file_path"]       = str(out_file)
                    rec["file_size_bytes"] = out_file.stat().st_size
                    rec["tool"]            = "html-preview"
                    rec["preview"]         = True

            except urllib.error.HTTPError as e:
                rec["status_code"] = e.code
                rec["error"]       = str(e)
            except Exception as e:
                rec["error"] = str(e)[:200]
                logger.debug(f"[Phase 8] HTML preview error for {url}: {e}")

            results.append(rec)

        return results

    # ─────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────

    def _extract_urls(self, live_hosts: List[Dict]) -> List[str]:
        """Extract unique URLs from live host list."""
        seen = set()
        urls = []
        for h in live_hosts:
            url = h.get("url", "").strip()
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls

    def _base_record(self, url: str) -> Dict:
        parsed = urlparse(url)
        return {
            "url":             url,
            "domain":          parsed.netloc,
            "file_path":       None,
            "file_size_bytes": 0,
            "page_title":      "",
            "status_code":     None,
            "tool":            None,
            "error":           None,
            "captured_at":     datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _url_to_slug(url: str) -> str:
        """Convert URL to safe filename slug."""
        slug = url.replace("https://", "").replace("http://", "")
        slug = slug.replace("/", "_").replace(":", "_").replace(".", "_")
        slug = "".join(c for c in slug if c.isalnum() or c in "_-")
        return slug[:80]

    @staticmethod
    def _has_tool(name: str) -> bool:
        return shutil.which(name) is not None

    @staticmethod
    def _has_chrome() -> bool:
        return ScreenshotEngine._find_chrome() is not None

    @staticmethod
    def _find_chrome() -> Optional[str]:
        candidates = [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
        ]
        for c in candidates:
            if shutil.which(c) or Path(c).exists():
                return c
        return None

    def _store_results(self) -> None:
        """Persist screenshot records to DB."""
        if not self.results:
            return
        try:
            from backend.models.models import Screenshot, Target
            with get_db_context() as session:
                target = session.query(Target).filter(Target.domain == self.domain).first()
                target_id = target.id if target else "unknown"
                for rec in self.results:
                    ss = Screenshot(
                        target_id        = target_id,
                        scan_id          = self.scan_id,
                        url              = rec["url"],
                        file_path        = rec.get("file_path"),
                        page_title       = rec.get("page_title", ""),
                        status_code      = rec.get("status_code"),
                        file_size_bytes  = rec.get("file_size_bytes", 0),
                        tool_used        = rec.get("tool", "unknown"),
                    )
                    session.add(ss)
                session.commit()
        except Exception as e:
            logger.warning(f"[Phase 8] DB storage error: {e}")
