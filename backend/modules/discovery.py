"""
ReconXploit - Subdomain Discovery Module
Phase 1: Runs multiple tools and aggregates results
"""

import asyncio
import subprocess
import logging
import json
from pathlib import Path
from typing import List, Set
from datetime import datetime

from backend.core.config import settings
from backend.models.database import get_db_context
from backend.models.models import Subdomain
from backend.utils.file_storage import save_subdomains

logger = logging.getLogger(__name__)


class SubdomainDiscovery:
    """
    Runs multiple subdomain discovery tools and stores results.
    Tools: subfinder, assetfinder, amass (passive), findomain
    """

    def __init__(self, domain: str, scan_id: str):
        self.domain = domain
        self.scan_id = scan_id
        self.results: Set[tuple] = set()  # (subdomain, source)

    def run(self) -> int:
        """Run all discovery tools and store results. Returns count found."""
        logger.info(f"Starting subdomain discovery for {self.domain}")

        runners = [
            self._run_subfinder,
            self._run_assetfinder,
            self._run_amass,
            self._run_findomain,
            self._run_crtsh,
        ]

        for runner in runners:
            try:
                runner()
            except Exception as e:
                logger.warning(f"{runner.__name__} failed: {e}")

        count = self._store_results()
        save_subdomains(self.domain, list(self.results))  # save to txt file
        logger.info(f"Discovery complete: {count} subdomains found for {self.domain}")
        return count

    # ─────────────────────────────────────────────
    # TOOL RUNNERS
    # ─────────────────────────────────────────────

    def _run_subfinder(self):
        """Run subfinder for passive subdomain enumeration."""
        cmd = [
            settings.tool_subfinder,
            "-d", self.domain,
            "-all",
            "-silent",
            "-json",
        ]
        output = self._execute(cmd, "subfinder")
        for line in output.strip().splitlines():
            try:
                data = json.loads(line)
                host = data.get("host", "").strip().lower()
                if host and self.domain in host:
                    self.results.add((host, "subfinder"))
            except json.JSONDecodeError:
                subdomain = line.strip().lower()
                if subdomain and self.domain in subdomain:
                    self.results.add((subdomain, "subfinder"))

    def _run_assetfinder(self):
        """Run assetfinder for passive subdomain enumeration."""
        cmd = [settings.tool_assetfinder, "--subs-only", self.domain]
        output = self._execute(cmd, "assetfinder")
        for line in output.strip().splitlines():
            subdomain = line.strip().lower()
            if subdomain and self.domain in subdomain:
                self.results.add((subdomain, "assetfinder"))

    def _run_amass(self):
        """Run amass in passive mode for subdomain enumeration."""
        cmd = [
            settings.tool_amass,
            "enum",
            "-passive",
            "-d", self.domain,
            "-nocolor",
        ]
        output = self._execute(cmd, "amass", timeout=300)
        for line in output.strip().splitlines():
            subdomain = line.strip().lower()
            if subdomain and self.domain in subdomain:
                self.results.add((subdomain, "amass"))

    def _run_findomain(self):
        """Run findomain for certificate-based subdomain discovery."""
        cmd = [
            settings.tool_findomain,
            "--target", self.domain,
            "--quiet",
        ]
        output = self._execute(cmd, "findomain")
        for line in output.strip().splitlines():
            subdomain = line.strip().lower()
            if subdomain and self.domain in subdomain:
                self.results.add((subdomain, "findomain"))

    def _run_crtsh(self):
        """Query crt.sh certificate transparency logs."""
        import urllib.request
        import urllib.error

        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ReconXploit/0.1"})
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                for entry in data:
                    name = entry.get("name_value", "")
                    for subdomain in name.splitlines():
                        subdomain = subdomain.strip().lower().lstrip("*.")
                        if subdomain and self.domain in subdomain:
                            self.results.add((subdomain, "crt.sh"))
        except Exception as e:
            logger.warning(f"crt.sh query failed: {e}")

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _execute(self, cmd: List[str], tool_name: str, timeout: int = 300) -> str:
        """Execute a shell command and return stdout."""
        logger.debug(f"Executing: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode != 0:
                logger.warning(f"{tool_name} exited with code {result.returncode}: {result.stderr[:200]}")
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning(f"{tool_name} timed out after {timeout}s")
            return ""
        except FileNotFoundError:
            logger.warning(f"{tool_name} not found in PATH. Install with scripts/install_tools.sh")
            return ""

    def _store_results(self) -> int:
        """Store discovered subdomains in the database."""
        if not self.results:
            return 0

        stored = 0
        with get_db_context() as db:
            for subdomain_name, source in self.results:
                # Upsert: if subdomain exists, update last_seen; else insert
                existing = db.query(Subdomain).filter(
                    Subdomain.scan_id == self.scan_id,
                    Subdomain.subdomain == subdomain_name
                ).first()

                if not existing:
                    # Get target_id from scan
                    from backend.models.models import Scan
                    scan = db.query(Scan).filter(Scan.id == self.scan_id).first()
                    if not scan:
                        continue

                    record = Subdomain(
                        scan_id=self.scan_id,
                        target_id=scan.target_id,
                        subdomain=subdomain_name,
                        source=source,
                        is_active=True,
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                    )
                    db.add(record)
                    stored += 1
                else:
                    existing.last_seen = datetime.utcnow()

        return stored

    def get_subdomains(self) -> List[str]:
        """Return list of unique subdomain names found."""
        return list({s[0] for s in self.results})
