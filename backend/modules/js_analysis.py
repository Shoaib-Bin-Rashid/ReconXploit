"""
ReconXploit - JS Intelligence Module
Phase 5: Discover JS files, extract endpoints and secrets.

Pipeline:
  1. URL harvesting  — gau / waybackurls (passive), or crawl fallback
  2. JS file filter  — keep only *.js URLs
  3. Content fetch   — download each JS file
  4. Endpoint mining — regex: API paths, GraphQL, internal URLs
  5. Secret hunting  — regex: AWS keys, JWTs, tokens, passwords, etc.

Output:
  - Stored in js_intelligence DB table
  - Saved to data/js_findings/{domain}.txt
"""

import re
import json
import logging
import subprocess
import hashlib
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from typing import List, Dict, Optional, Tuple

from backend.core.config import settings
from backend.models.database import get_db_context
from backend.utils.file_storage import save_js_findings

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# RISK LEVELS BY FINDING TYPE
# ─────────────────────────────────────────────────────────────

RISK_LEVELS = {
    # Secrets
    "aws_access_key":     "critical",
    "aws_secret_key":     "critical",
    "private_key":        "critical",
    "password":           "high",
    "db_connection":      "critical",
    "jwt_token":          "high",
    "stripe_live_key":    "critical",
    "stripe_test_key":    "medium",
    "google_api_key":     "high",
    "firebase_key":       "high",
    "github_token":       "high",
    "slack_token":        "high",
    "twilio_key":         "high",
    "sendgrid_key":       "high",
    "generic_api_key":    "medium",
    "bearer_token":       "medium",
    # Endpoints
    "graphql_endpoint":   "medium",
    "admin_endpoint":     "high",
    "api_endpoint":       "low",
    "internal_url":       "medium",
    "hidden_path":        "low",
    "debug_endpoint":     "high",
    "swagger_endpoint":   "medium",
    "s3_bucket":          "high",
}

# ─────────────────────────────────────────────────────────────
# SECRET PATTERNS
# ─────────────────────────────────────────────────────────────

SECRET_PATTERNS: List[Tuple[str, str, str, int]] = [
    # (secret_type, regex_pattern, risk_level, value_group)
    # value_group: 0 = full match, N = capture group N

    ("aws_access_key",
     r"(?<![A-Z0-9])(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
     "critical", 0),

    ("aws_secret_key",
     r"(?i)aws.{0,20}secret.{0,10}['\"]([A-Za-z0-9/+=]{40})['\"]",
     "critical", 1),

    ("private_key",
     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "critical", 0),

    ("jwt_token",
     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9_-]{10,}",
     "high", 0),

    ("stripe_live_key",
     r"sk_live_[A-Za-z0-9]{24,}",
     "critical", 0),

    ("stripe_test_key",
     r"sk_test_[A-Za-z0-9]{24,}",
     "medium", 0),

    ("google_api_key",
     r"AIza[A-Za-z0-9_-]{35}",
     "high", 0),

    ("firebase_key",
     r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
     "high", 0),

    ("github_token",
     r"gh[pousr]_[A-Za-z0-9]{36,}",
     "high", 0),

    ("slack_token",
     r"xox[baprs]-[A-Za-z0-9-]{10,}",
     "high", 0),

    ("twilio_key",
     r"SK[A-Fa-f0-9]{32}",
     "high", 0),

    ("sendgrid_key",
     r"SG\.[A-Za-z0-9._-]{22,}\.[A-Za-z0-9._-]{43,}",
     "high", 0),

    ("bearer_token",
     r"(?i)(?:authorization|bearer)[\"'\s:=]+([A-Za-z0-9._\-+/]{20,})",
     "medium", 1),

    ("db_connection",
     r"(?i)(?:mongodb|postgresql|mysql|redis|jdbc):\/\/[^\"'\s<>]+",
     "critical", 0),

    ("password",
     r"(?i)(?:password|passwd|pwd|secret)[\"'\s]*[:=][\"'\s]*([^\"'\s]{8,})",
     "high", 1),

    ("generic_api_key",
     r"(?i)(?:api_key|apikey|api-key)[\"'\s]*[:=][\"'\s]*([A-Za-z0-9._\-]{16,})",
     "medium", 1),
]

# ─────────────────────────────────────────────────────────────
# ENDPOINT PATTERNS
# ─────────────────────────────────────────────────────────────

ENDPOINT_PATTERNS: List[Tuple[str, str]] = [
    # (finding_type, regex_pattern)
    ("graphql_endpoint",
     r"""['"]((?:[/\w.-]*/)?graphql(?:/[^\s'"]*)?)['":]"""),

    ("swagger_endpoint",
     r"""['"]((?:[/\w.-]*/)?(?:swagger|api-docs|openapi)(?:/[^\s'"]*)?)['":]"""),

    ("debug_endpoint",
     r"""['"]((?:[/\w.-]*/)?(?:debug|test|dev|staging|qa)(?:/[^\s'"]*)?)['":]"""),

    ("admin_endpoint",
     r"""['"]((?:[/\w.-]*/)?(?:admin|administrator|manage|dashboard|cpanel|backend)(?:/[^\s'"]*)?)['":]"""),

    ("api_endpoint",
     r"""['"](\/?api\/v?\d*\/[^\s'"<>]+)['"]"""),

    ("internal_url",
     r"""https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s'"<>]*"""),

    ("s3_bucket",
     r"""https?://[a-z0-9][a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com[^\s'"<>]*"""),

    ("hidden_path",
     r"""['"](/(?:backup|old|archive|temp|tmp|bak|\.git|\.env|config|conf|setup|install)[^\s'"<>]*)['":]"""),
]

# ─────────────────────────────────────────────────────────────
# FETCH TIMEOUT & SIZE LIMITS
# ─────────────────────────────────────────────────────────────

FETCH_TIMEOUT    = 10   # seconds
MAX_JS_SIZE      = 2 * 1024 * 1024   # 2 MB — skip minified bundles larger than this
MAX_JS_PER_HOST  = 20                 # max JS files to analyze per live host
MAX_URLS_GAU     = 5000               # cap gau results per domain


class JsAnalyzer:
    """
    Discover JS files from live hosts, extract endpoints and secrets.
    """

    def __init__(self, domain: str, scan_id: str, mode: str = "full"):
        self.domain    = domain
        self.scan_id   = scan_id
        self.mode      = mode
        self.results: List[Dict]   = []
        self._seen:   set          = set()   # dedup key: (source_url, finding_type, value[:80])

    # ─────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────

    def run(self, live_hosts: List[Dict]) -> int:
        """
        Run full JS analysis pipeline.

        Args:
            live_hosts: output from Phase 2 validation
                        [{"url": "https://...", "ip": "...", ...}]

        Returns:
            Number of findings stored.
        """
        logger.info(f"[Phase 5] Starting JS analysis for {self.domain}")

        # Step 1: Collect URLs (gau / waybackurls / crawl fallback)
        all_urls = self._collect_urls(live_hosts)
        logger.info(f"[Phase 5] Collected {len(all_urls)} URLs")

        # Step 2: Filter JS files
        js_urls = self._filter_js_urls(all_urls)
        logger.info(f"[Phase 5] Found {len(js_urls)} JS files to analyze")

        # Step 3: Analyze each JS file
        for js_url in js_urls[:MAX_JS_PER_HOST * max(len(live_hosts), 1)]:
            findings = self._analyze_js_file(js_url)
            for f in findings:
                key = (f["source_url"], f["finding_type"], f["finding_value"][:80])
                if key not in self._seen:
                    self._seen.add(key)
                    self.results.append(f)

        # Sort: critical first, then by type
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.results.sort(key=lambda x: (risk_order.get(x["risk_level"], 4), x["finding_type"]))

        # Step 4: Store to DB
        stored = self._store_results(self.results)

        # Step 5: Save to text file
        save_js_findings(self.domain, self.results)

        logger.info(f"[Phase 5] Stored {stored} JS findings")
        return stored

    def get_results(self) -> List[Dict]:
        return self.results

    def get_summary(self) -> Dict:
        summary: Dict[str, int] = {}
        for r in self.results:
            t = r.get("finding_type", "unknown")
            summary[t] = summary.get(t, 0) + 1
        return summary

    def get_secrets(self) -> List[Dict]:
        secret_types = {p[0] for p in SECRET_PATTERNS}
        return [r for r in self.results if r["finding_type"] in secret_types]

    def get_endpoints(self) -> List[Dict]:
        endpoint_types = {p[0] for p in ENDPOINT_PATTERNS}
        return [r for r in self.results if r["finding_type"] in endpoint_types]

    # ─────────────────────────────────────────────────
    # URL COLLECTION
    # ─────────────────────────────────────────────────

    def _collect_urls(self, live_hosts: List[Dict]) -> List[str]:
        """Try gau, then waybackurls, then HTML crawl as fallback."""
        urls: set = set()

        # Passive: gau
        if self.mode != "quick":
            gau_urls = self._run_gau(self.domain)
            urls.update(gau_urls)
            logger.debug(f"[Phase 5] gau: {len(gau_urls)} URLs")

        # Passive fallback: waybackurls
        if not urls and self.mode != "quick":
            wb_urls = self._run_waybackurls(self.domain)
            urls.update(wb_urls)
            logger.debug(f"[Phase 5] waybackurls: {len(wb_urls)} URLs")

        # Active fallback: crawl HTML of each live host
        if not urls or self.mode in ("full", "deep"):
            for host in live_hosts[:20]:
                crawled = self._crawl_html_for_links(host.get("url", ""))
                urls.update(crawled)
            logger.debug(f"[Phase 5] HTML crawl added, total: {len(urls)}")

        return list(urls)[:MAX_URLS_GAU]

    def _run_gau(self, domain: str) -> List[str]:
        """Run gau (GetAllURLs) for passive URL harvesting."""
        try:
            result = subprocess.run(
                ["gau", "--threads", "5", "--timeout", "15", domain],
                capture_output=True, text=True, timeout=120,
            )
            return [u.strip() for u in result.stdout.splitlines() if u.strip()]
        except FileNotFoundError:
            logger.debug("[Phase 5] gau not installed, skipping")
            return []
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.warning(f"[Phase 5] gau error: {e}")
            return []

    def _run_waybackurls(self, domain: str) -> List[str]:
        """Run waybackurls for historical URL harvesting."""
        try:
            result = subprocess.run(
                ["waybackurls", domain],
                capture_output=True, text=True, timeout=120,
            )
            return [u.strip() for u in result.stdout.splitlines() if u.strip()]
        except FileNotFoundError:
            logger.debug("[Phase 5] waybackurls not installed, skipping")
            return []
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.warning(f"[Phase 5] waybackurls error: {e}")
            return []

    def _crawl_html_for_links(self, base_url: str) -> List[str]:
        """
        Fetch a page and extract script src= and href= links.
        This is the active fallback when gau/waybackurls are missing.
        """
        if not base_url:
            return []
        try:
            req = urllib.request.Request(
                base_url,
                headers={"User-Agent": "Mozilla/5.0 (ReconXploit/1.0)"},
            )
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                content = resp.read(512 * 1024).decode("utf-8", errors="replace")

            links = re.findall(
                r"""(?:src|href)=['"]((?:https?://|/)[^'"<>]+)['"]""",
                content, re.IGNORECASE,
            )
            absolute = []
            parsed_base = urllib.parse.urlparse(base_url)
            for link in links:
                if link.startswith("http"):
                    absolute.append(link)
                elif link.startswith("/"):
                    absolute.append(f"{parsed_base.scheme}://{parsed_base.netloc}{link}")
            return absolute
        except Exception as e:
            logger.debug(f"[Phase 5] crawl error {base_url}: {e}")
            return []

    # ─────────────────────────────────────────────────
    # JS FILE FILTERING
    # ─────────────────────────────────────────────────

    def _filter_js_urls(self, urls: List[str]) -> List[str]:
        """Keep only .js URLs that belong to the target domain."""
        js: List[str] = []
        seen_urls: set = set()
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                # Must be same domain or subdomain
                if self.domain not in parsed.netloc:
                    continue
                path = parsed.path.lower().split("?")[0]
                if not path.endswith(".js"):
                    continue
                # Deduplicate by normalized URL (strip query string for .js)
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean in seen_urls:
                    continue
                seen_urls.add(clean)
                js.append(clean)
            except Exception:
                continue
        return js

    # ─────────────────────────────────────────────────
    # JS CONTENT ANALYSIS
    # ─────────────────────────────────────────────────

    def _analyze_js_file(self, js_url: str) -> List[Dict]:
        """Download and analyze a single JS file."""
        content = self._fetch_js_content(js_url)
        if not content:
            return []

        findings: List[Dict] = []

        # Secret detection
        for secret_type, pattern, risk, value_group in SECRET_PATTERNS:
            for match in re.finditer(pattern, content):
                value = match.group(value_group).strip()
                if not value or len(value) < 6:
                    continue
                findings.append({
                    "source_url":    js_url,
                    "js_file_url":   js_url,
                    "finding_type":  secret_type,
                    "finding_value": self._redact(value, secret_type),
                    "secret_type":   secret_type,
                    "risk_level":    risk,
                    "context":       self._extract_context(content, value),
                })

        # Endpoint extraction
        for finding_type, pattern in ENDPOINT_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                value = match.strip()
                if not value or len(value) < 3:
                    continue
                findings.append({
                    "source_url":    js_url,
                    "js_file_url":   js_url,
                    "finding_type":  finding_type,
                    "finding_value": value,
                    "secret_type":   None,
                    "risk_level":    RISK_LEVELS.get(finding_type, "low"),
                    "context":       None,
                })

        return findings

    def _fetch_js_content(self, url: str) -> Optional[str]:
        """Fetch JS file content with size guard."""
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (ReconXploit/1.0)"},
            )
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                raw = resp.read(MAX_JS_SIZE)
                return raw.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug(f"[Phase 5] fetch error {url}: {e}")
            return None

    def _redact(self, value: str, secret_type: str) -> str:
        """
        Redact secret values — show first 6 chars then stars.
        AWS keys, private keys: show type + hash only.
        """
        if secret_type in ("aws_secret_key", "private_key", "db_connection", "password"):
            digest = hashlib.sha256(value.encode()).hexdigest()[:12]
            return f"[REDACTED:{secret_type}:sha256:{digest}]"
        if len(value) > 12:
            return value[:6] + "*" * (len(value) - 6)
        return value[:4] + "***"

    @staticmethod
    def _extract_context(content: str, value: str) -> Optional[str]:
        """Extract a small snippet of code around the matched value for context."""
        try:
            idx = content.find(value)
            if idx == -1:
                return None
            start = max(0, idx - 40)
            end   = min(len(content), idx + len(value) + 40)
            snippet = content[start:end].strip()
            # Replace newlines for storage
            return snippet.replace("\n", " ").replace("\r", "")[:200]
        except Exception:
            return None

    # ─────────────────────────────────────────────────
    # DB STORAGE
    # ─────────────────────────────────────────────────

    def _store_results(self, findings: List[Dict]) -> int:
        """Store findings in js_intelligence table. Deduplicates on (scan_id, source_url, finding_type, value[:80])."""
        if not findings:
            return 0
        try:
            from backend.models.models import JsIntelligence
            stored = 0
            with get_db_context() as session:
                # Load existing keys for this scan
                existing = session.query(
                    JsIntelligence.source_url,
                    JsIntelligence.finding_type,
                    JsIntelligence.finding_value,
                ).filter(JsIntelligence.scan_id == self.scan_id).all()
                existing_keys = {
                    (r.source_url, r.finding_type, r.finding_value[:80])
                    for r in existing
                }

                for f in findings:
                    key = (f["source_url"], f["finding_type"], f["finding_value"][:80])
                    if key in existing_keys:
                        continue
                    existing_keys.add(key)

                    rec = JsIntelligence(
                        scan_id       = self.scan_id,
                        source_url    = f["source_url"],
                        js_file_url   = f.get("js_file_url"),
                        finding_type  = f["finding_type"],
                        finding_value = f["finding_value"],
                        secret_type   = f.get("secret_type"),
                        risk_level    = f["risk_level"],
                        context       = f.get("context"),
                    )
                    session.add(rec)
                    stored += 1
                session.commit()
            return stored
        except Exception as e:
            logger.warning(f"[Phase 5] DB storage error: {e}")
            return 0
