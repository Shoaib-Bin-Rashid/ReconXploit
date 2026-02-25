"""
ReconXploit - Vulnerability Scanner Module
Phase 4: Run nuclei against all live hosts and store findings.

Scan profiles by mode:
  quick   - critical + high only, common tags
  full    - all severities, all default templates
  deep    - all severities, all templates including intrusive

Output per finding:
  - template_id, name, severity, description
  - matched URL, CVE ID, CVSS score
  - remediation advice (from nuclei metadata)

Output:
  - Stored in vulnerabilities DB table
  - Saved to data/vulnerabilities/{domain}.txt
"""

import subprocess
import logging
import json
from datetime import datetime
from typing import List, Dict, Optional

from backend.core.config import settings
from backend.models.database import get_db_context
from backend.utils.file_storage import save_vulnerabilities

logger = logging.getLogger(__name__)

# Severity ordering for sorting/display
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# nuclei tags to include per mode
QUICK_TAGS  = "cve,exposure,misconfig,takeover,default-login,auth-bypass,xss,sqli,ssrf,lfi"
FULL_TAGS   = ""   # empty = all default templates
DEEP_TAGS   = ""   # empty = all templates including intrusive


class VulnerabilityScanner:
    """
    Runs nuclei against live URLs and stores vulnerability findings.
    """

    def __init__(self, domain: str, scan_id: str):
        self.domain = domain
        self.scan_id = scan_id
        self.results: List[Dict] = []

    def run(self, live_hosts: List[Dict], mode: str = "full") -> int:
        """
        Scan all live hosts for vulnerabilities.

        Args:
            live_hosts: list of dicts from Phase 2 (must have 'url' key)
            mode:       quick / full / deep

        Returns:
            count of vulnerabilities found
        """
        urls = self._extract_urls(live_hosts)
        if not urls:
            logger.warning("No URLs to scan in Phase 4")
            return 0

        logger.info(f"Starting vulnerability scan on {len(urls)} URLs for {self.domain} (mode={mode})")

        raw = self._run_nuclei(urls, mode)
        self.results = self._parse_results(raw)

        count = self._store_results()
        save_vulnerabilities(self.domain, self.results)
        logger.info(
            f"Vuln scan complete: {count} findings for {self.domain} "
            f"({self._count_by_severity()})"
        )
        return count

    # ─────────────────────────────────────────────
    # NUCLEI RUNNER
    # ─────────────────────────────────────────────

    def _run_nuclei(self, urls: List[str], mode: str) -> str:
        """
        Run nuclei with URL list piped via stdin.
        Returns raw JSONL stdout.
        """
        cmd = [
            settings.tool_nuclei,
            "-silent",
            "-jsonl",
            "-no-color",
            "-rate-limit", "100",
            "-concurrency", "25",
            "-timeout", "10",
        ]

        # Mode-specific flags
        if mode == "quick":
            cmd += ["-severity", "critical,high,medium", "-tags", QUICK_TAGS]
        elif mode == "deep":
            cmd += ["-severity", "critical,high,medium,low,info"]
            # Include intrusive templates in deep mode
            cmd += ["-include-tags", "intrusive"]
        else:  # full
            cmd += ["-severity", "critical,high,medium,low,info"]

        stdin_data = "\n".join(urls)
        logger.debug(f"Running nuclei on {len(urls)} URLs")

        try:
            result = subprocess.run(
                cmd,
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour max
            )
            if result.returncode not in (0, 1) and result.stderr:
                logger.warning(f"nuclei stderr: {result.stderr[:300]}")
            return result.stdout

        except subprocess.TimeoutExpired:
            logger.warning("nuclei timed out after 3600s")
            return ""
        except FileNotFoundError:
            logger.warning(
                "nuclei not found in PATH. "
                "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
            return ""

    # ─────────────────────────────────────────────
    # RESULT PARSER
    # ─────────────────────────────────────────────

    def _parse_results(self, raw_output: str) -> List[Dict]:
        """Parse nuclei JSONL output into list of normalized finding dicts."""
        findings = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = self._normalize(data)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                logger.debug(f"Could not parse nuclei line: {line[:100]}")

        # Sort by severity
        return sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity", "unknown"), 5))

    def _normalize(self, data: dict) -> Optional[Dict]:
        """Normalize a raw nuclei JSONL object into our schema."""
        template_id = data.get("template-id", "").strip()
        matched_at  = data.get("matched-at", "").strip()

        if not template_id or not matched_at:
            return None

        # Core info
        info = data.get("info", {})
        name        = info.get("name", template_id).strip()
        severity    = info.get("severity", "info").lower().strip()
        description = info.get("description", "").strip()
        remediation = info.get("remediation", "").strip()

        # Ensure severity is valid
        if severity not in SEVERITY_ORDER:
            severity = "info"

        # CVE / CVSS
        cve_id     = self._extract_cve(info)
        cvss_score = self._extract_cvss(info)

        # Classification tags
        classification = info.get("classification", {})
        cwe_ids = classification.get("cwe-id", [])

        return {
            "template_id":  template_id,
            "name":         name,
            "severity":     severity,
            "description":  description,
            "remediation":  remediation,
            "matched_at":   matched_at,
            "cve_id":       cve_id,
            "cvss_score":   cvss_score,
            "cwe_ids":      cwe_ids,
            "tags":         info.get("tags", []),
            "reference":    info.get("reference", []),
        }

    def _extract_cve(self, info: dict) -> Optional[str]:
        """Extract CVE ID from nuclei info block."""
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", [])
        if isinstance(cve_ids, list) and cve_ids:
            return cve_ids[0].upper().strip()
        if isinstance(cve_ids, str) and cve_ids:
            return cve_ids.upper().strip()
        # Some templates put it in tags
        tags = info.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                if tag.upper().startswith("CVE-"):
                    return tag.upper()
        return None

    def _extract_cvss(self, info: dict) -> Optional[float]:
        """Extract CVSS score from nuclei info block."""
        classification = info.get("classification", {})
        cvss = classification.get("cvss-score")
        if cvss is not None:
            try:
                return float(cvss)
            except (ValueError, TypeError):
                pass
        return None

    # ─────────────────────────────────────────────
    # DATABASE STORAGE
    # ─────────────────────────────────────────────

    def _store_results(self) -> int:
        """Store vulnerabilities in the database. Returns count stored."""
        if not self.results:
            return 0

        try:
            from backend.models.models import Vulnerability
        except Exception as e:
            logger.warning(f"DB import failed, skipping DB store: {e}")
            return len(self.results)

        stored = 0
        try:
            with get_db_context() as db:
                for v in self.results:
                    existing = db.query(Vulnerability).filter(
                        Vulnerability.scan_id == self.scan_id,
                        Vulnerability.template_id == v["template_id"],
                        Vulnerability.matched_at == v["matched_at"],
                    ).first()

                    if not existing:
                        record = Vulnerability(
                            scan_id=self.scan_id,
                            vulnerability_name=v["name"],
                            severity=v["severity"],
                            template_id=v["template_id"],
                            description=v.get("description"),
                            remediation=v.get("remediation"),
                            matched_at=v["matched_at"],
                            cve_id=v.get("cve_id"),
                            cvss_score=v.get("cvss_score"),
                            status="new",
                            first_seen=datetime.utcnow(),
                            last_seen=datetime.utcnow(),
                        )
                        db.add(record)
                        stored += 1
                    else:
                        existing.last_seen = datetime.utcnow()
        except Exception as e:
            logger.warning(f"DB store failed: {e}. Results still saved to file.")
            return len(self.results)

        return stored

    # ─────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────

    def _extract_urls(self, live_hosts: List[Dict]) -> List[str]:
        """Extract unique URLs from Phase 2 results."""
        seen = set()
        urls = []
        for h in live_hosts:
            url = (h.get("url") or "").strip()
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls

    def _count_by_severity(self) -> str:
        """Return a human readable severity summary string."""
        counts: Dict[str, int] = {}
        for v in self.results:
            s = v.get("severity", "info")
            counts[s] = counts.get(s, 0) + 1
        parts = [f"{k}:{v}" for k, v in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 5))]
        return " | ".join(parts) if parts else "none"

    # ─────────────────────────────────────────────
    # ACCESSORS
    # ─────────────────────────────────────────────

    def get_results(self) -> List[Dict]:
        return self.results

    def get_by_severity(self, severity: str) -> List[Dict]:
        return [v for v in self.results if v.get("severity") == severity]

    def get_critical_and_high(self) -> List[Dict]:
        return [v for v in self.results if v.get("severity") in ("critical", "high")]

    def get_summary(self) -> Dict[str, int]:
        """Return {severity: count} dict."""
        summary: Dict[str, int] = {}
        for v in self.results:
            s = v.get("severity", "info")
            summary[s] = summary.get(s, 0) + 1
        return summary
