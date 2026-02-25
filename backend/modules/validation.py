"""
ReconXploit - Live Host Validation Module
Phase 2: Probe subdomains with httpx to find live web servers.

Collects per host:
  - status code, title, server header, content length
  - IP address, response time
  - Technology stack (Wappalyzer-style via httpx --tech-detect)
  - WAF / CDN detection
  - TLS info
  - Fingerprint hash (SHA256 of title+server+status for change detection)

Output:
  - Stored in live_hosts DB table
  - Saved to data/live_hosts/{domain}.txt
"""

import subprocess
import logging
import json
import hashlib
from datetime import datetime
from typing import List, Dict

from backend.core.config import settings
from backend.models.database import get_db_context
from backend.utils.file_storage import save_live_hosts

logger = logging.getLogger(__name__)

DEFAULT_PORTS = "80,443,8080,8443,8000,8888,3000,5000,9000"


class LiveHostValidator:
    """
    Runs httpx against a list of subdomains and stores live host results.
    """

    def __init__(self, domain: str, scan_id: str):
        self.domain = domain
        self.scan_id = scan_id
        self.results: List[Dict] = []

    def run(self, subdomains: List[str]) -> int:
        if not subdomains:
            logger.warning("No subdomains provided to LiveHostValidator")
            return 0

        logger.info(f"Probing {len(subdomains)} subdomains for {self.domain}")
        raw = self._run_httpx(subdomains)
        self.results = self._parse_results(raw)

        count = self._store_results()
        save_live_hosts(self.domain, self.results)
        logger.info(f"Live host validation complete: {count} live hosts for {self.domain}")
        return count

    def _run_httpx(self, subdomains: List[str]) -> str:
        cmd = [
            settings.tool_httpx,
            "-silent", "-json", "-title", "-status-code",
            "-server", "-ip", "-content-length", "-response-time",
            "-tech-detect", "-no-color",
            "-ports", DEFAULT_PORTS,
            "-threads", "50",
            "-timeout", "10",
        ]
        stdin_data = "\n".join(subdomains)
        try:
            result = subprocess.run(
                cmd, input=stdin_data, capture_output=True, text=True, timeout=600,
            )
            if result.returncode != 0 and result.stderr:
                logger.warning(f"httpx stderr: {result.stderr[:200]}")
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning("httpx timed out after 600s")
            return ""
        except FileNotFoundError:
            logger.warning("httpx not found in PATH.")
            return ""

    def _parse_results(self, raw_output: str) -> List[Dict]:
        hosts = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = self._normalize(data)
                if host:
                    hosts.append(host)
            except json.JSONDecodeError:
                logger.debug(f"Could not parse httpx line: {line[:100]}")
        return hosts

    def _normalize(self, data: dict) -> dict:
        url = data.get("url", "").strip()
        if not url:
            return {}

        status_code    = data.get("status_code", 0)
        title          = data.get("title", "").strip()
        server         = data.get("webserver", "") or data.get("server", "")
        ip             = data.get("host_ip", "") or data.get("host", "")
        content_length = data.get("content_length", 0)
        response_time  = self._parse_response_time(data.get("time", ""))
        tech_stack     = data.get("tech", []) or []

        waf, cdn = None, None
        if data.get("cdn"):
            cdn = data.get("cdn_name", "unknown CDN")
        if data.get("cdn_type") == "waf":
            waf = data.get("cdn_name", "unknown WAF")

        tls_info = {"enabled": True} if url.startswith("https://") else {}

        fingerprint_hash = hashlib.sha256(
            f"{status_code}|{title}|{server}".encode()
        ).hexdigest()

        return {
            "url": url, "status_code": status_code, "title": title,
            "server": server, "ip": ip, "content_length": content_length,
            "response_time_ms": response_time, "technology_stack": tech_stack,
            "waf": waf, "cdn": cdn, "tls_info": tls_info,
            "fingerprint_hash": fingerprint_hash, "is_active": True,
        }

    def _parse_response_time(self, time_str: str) -> int:
        if not time_str:
            return 0
        try:
            if time_str.endswith("ms"):
                return int(float(time_str[:-2]))
            elif time_str.endswith("s"):
                return int(float(time_str[:-1]) * 1000)
        except (ValueError, IndexError):
            pass
        return 0

    def _store_results(self) -> int:
        if not self.results:
            return 0
        try:
            from backend.models.models import LiveHost
        except Exception as e:
            logger.warning(f"DB import failed: {e}")
            return len(self.results)

        stored = 0
        try:
            with get_db_context() as db:
                for host in self.results:
                    existing = db.query(LiveHost).filter(
                        LiveHost.scan_id == self.scan_id,
                        LiveHost.url == host["url"],
                    ).first()
                    if not existing:
                        record = LiveHost(
                            scan_id=self.scan_id,
                            url=host["url"],
                            status_code=host.get("status_code"),
                            title=host.get("title"),
                            content_length=host.get("content_length"),
                            response_time_ms=host.get("response_time_ms"),
                            server_header=host.get("server"),
                            technology_stack=host.get("technology_stack"),
                            tls_info=host.get("tls_info"),
                            waf_detected=host.get("waf"),
                            cdn_detected=host.get("cdn"),
                            fingerprint_hash=host.get("fingerprint_hash"),
                            is_active=True,
                            first_seen=datetime.utcnow(),
                            last_seen=datetime.utcnow(),
                        )
                        db.add(record)
                        stored += 1
                    else:
                        existing.last_seen = datetime.utcnow()
                        existing.status_code = host.get("status_code")
                        existing.title = host.get("title")
                        existing.fingerprint_hash = host.get("fingerprint_hash")
        except Exception as e:
            logger.warning(f"DB store failed: {e}.")
            return len(self.results)
        return stored

    def get_live_urls(self) -> List[str]:
        return [h["url"] for h in self.results]

    def get_results(self) -> List[Dict]:
        return self.results
