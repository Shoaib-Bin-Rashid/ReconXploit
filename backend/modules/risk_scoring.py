"""
ReconXploit - Risk Scoring Module
Phase 7a: Compute a 0-100 risk score for each scan based on all findings.

Score factors (from config/settings.yaml risk_scoring block):
  Vulnerabilities  — weighted by severity (critical=40, high=25, medium=10, low=5)
  Sensitive ports  — each open sensitive port adds points
  JS secrets       — secrets found in JS files
  JS endpoints     — admin/debug endpoints found
  Changes          — significant changes from Phase 6
  WAF absence      — live hosts without WAF protection

Output:
  - risk_scores DB table  (per-asset and overall)
  - data/risk_scores/{domain}.txt
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional

from backend.models.database import get_db_context
from backend.utils.file_storage import save_risk_scores

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# DEFAULT WEIGHTS  (overridden by config if available)
# ─────────────────────────────────────────────────────────────

DEFAULT_WEIGHTS = {
    "vuln_critical":   40,
    "vuln_high":       25,
    "vuln_medium":     10,
    "vuln_low":         5,
    "vuln_info":        1,
    "sensitive_port":  20,
    "js_secret":       30,
    "admin_endpoint":  20,
    "debug_endpoint":  20,
    "s3_bucket":       15,
    "no_waf":          10,
    "sig_change":      15,
    "new_subdomain":    5,
}

SCORE_CAP = 100


class RiskScorer:
    """
    Computes risk scores from all scan findings.
    Produces an overall 0-100 score + per-category breakdown.
    """

    def __init__(self, domain: str, scan_id: str):
        self.domain  = domain
        self.scan_id = scan_id
        self.scores: List[Dict]  = []   # per-asset score records
        self.overall: int        = 0
        self.breakdown: Dict     = {}
        self._weights            = self._load_weights()

    # ─────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────

    def run(self, scan_data: Dict) -> int:
        """
        Compute risk scores from scan data.

        Args:
            scan_data: {
                subdomains, live_hosts, ports, vulnerabilities,
                js_findings, changes
            }

        Returns:
            Overall risk score (0-100).
        """
        logger.info(f"[Phase 7] Computing risk score for {self.domain}")

        breakdown: Dict[str, int] = {}

        # ── Vulnerabilities ──────────────────────────
        vulns = scan_data.get("vulnerabilities", [])
        vuln_score = 0
        vuln_counts: Dict[str, int] = {}
        for v in vulns:
            sev = v.get("severity", "info")
            key = f"vuln_{sev}"
            w   = self._weights.get(key, 1)
            vuln_score += w
            vuln_counts[sev] = vuln_counts.get(sev, 0) + 1
        breakdown["vulnerabilities"] = min(vuln_score, 60)   # cap vuln contribution

        # ── Sensitive ports ──────────────────────────
        ports = scan_data.get("ports", [])
        port_score = sum(
            self._weights["sensitive_port"]
            for p in ports
            if p.get("is_sensitive") or p.get("sensitive")
        )
        breakdown["sensitive_ports"] = min(port_score, 40)

        # ── JS secrets & endpoints ───────────────────
        js = scan_data.get("js_findings", [])
        js_score = 0
        secret_types = {
            "aws_access_key", "aws_secret_key", "private_key", "jwt_token",
            "stripe_live_key", "google_api_key", "firebase_key", "github_token",
            "slack_token", "db_connection", "password", "generic_api_key",
            "bearer_token", "sendgrid_key", "twilio_key", "stripe_test_key",
        }
        high_endpoints = {"admin_endpoint", "debug_endpoint", "s3_bucket"}
        for f in js:
            ftype = f.get("finding_type", "")
            if ftype in secret_types:
                js_score += self._weights.get("js_secret", 30)
            elif ftype in high_endpoints:
                js_score += self._weights.get(ftype, 20)
        breakdown["js_intelligence"] = min(js_score, 40)

        # ── WAF absence ──────────────────────────────
        live_hosts = scan_data.get("live_hosts", [])
        no_waf_hosts = sum(
            1 for h in live_hosts
            if not (h.get("waf_detected") or h.get("waf", ""))
        )
        waf_score = no_waf_hosts * self._weights.get("no_waf", 10)
        breakdown["no_waf"] = min(waf_score, 20)

        # ── Significant changes ───────────────────────
        changes = scan_data.get("changes", [])
        sig_changes = [c for c in changes if c.get("is_significant")]
        change_score = len(sig_changes) * self._weights.get("sig_change", 15)
        breakdown["significant_changes"] = min(change_score, 30)

        # ── Overall score ─────────────────────────────
        raw = sum(breakdown.values())
        self.overall   = min(raw, SCORE_CAP)
        self.breakdown = breakdown

        # ── Build per-asset records ───────────────────
        self.scores = self._build_score_records(
            scan_data, vuln_counts, port_score, js_score
        )

        # ── Store to DB ───────────────────────────────
        self._store_scores()

        # ── Save to file ──────────────────────────────
        save_risk_scores(self.domain, self.overall, self.breakdown, self.scores)

        logger.info(f"[Phase 7] Risk score for {self.domain}: {self.overall}/100")
        return self.overall

    def get_overall_score(self) -> int:
        return self.overall

    def get_breakdown(self) -> Dict:
        return self.breakdown

    def get_label(self) -> str:
        if self.overall >= 80:   return "CRITICAL"
        if self.overall >= 60:   return "HIGH"
        if self.overall >= 40:   return "MEDIUM"
        if self.overall >= 20:   return "LOW"
        return "INFO"

    def get_scores(self) -> List[Dict]:
        return self.scores

    # ─────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────

    def _load_weights(self) -> Dict:
        """Load weights from config, fall back to defaults."""
        try:
            from backend.core.config import settings
            rs = getattr(settings, "risk_scoring", None)
            if rs and isinstance(rs, dict):
                flat: Dict = {}
                vs = rs.get("vulnerability_severity", {})
                flat["vuln_critical"]  = vs.get("critical", DEFAULT_WEIGHTS["vuln_critical"])
                flat["vuln_high"]      = vs.get("high",     DEFAULT_WEIGHTS["vuln_high"])
                flat["vuln_medium"]    = vs.get("medium",   DEFAULT_WEIGHTS["vuln_medium"])
                flat["vuln_low"]       = vs.get("low",      DEFAULT_WEIGHTS["vuln_low"])
                flat["vuln_info"]      = vs.get("info",     DEFAULT_WEIGHTS["vuln_info"])
                intel = rs.get("intelligence_findings", {})
                flat["js_secret"]      = intel.get("api_key",    DEFAULT_WEIGHTS["js_secret"])
                flat["admin_endpoint"] = intel.get("admin_panel", DEFAULT_WEIGHTS["admin_endpoint"])
                flat["s3_bucket"]      = intel.get("api_key",    DEFAULT_WEIGHTS["s3_bucket"])
                sens = rs.get("sensitive_services", {})
                flat["sensitive_port"] = max(sens.values()) if sens else DEFAULT_WEIGHTS["sensitive_port"]
                exp = rs.get("asset_exposure", {})
                flat["no_waf"]         = exp.get("no_waf", DEFAULT_WEIGHTS["no_waf"])
                return flat
        except Exception:
            pass
        return dict(DEFAULT_WEIGHTS)

    def _build_score_records(
        self,
        scan_data: Dict,
        vuln_counts: Dict,
        port_score: int,
        js_score: int,
    ) -> List[Dict]:
        """Build per-asset score records for storage."""
        records = []

        # Overall scan record
        records.append({
            "asset_type":   "scan",
            "asset_id":     self.scan_id,
            "score":        self.overall,
            "factors":      self.breakdown,
        })

        # Per live-host scores
        for host in scan_data.get("live_hosts", []):
            url = host.get("url", "")
            h_score = 0
            # Vulns on this host
            for v in scan_data.get("vulnerabilities", []):
                if url in (v.get("matched_at", "") or ""):
                    h_score += self._weights.get(f"vuln_{v.get('severity','info')}", 1)
            # No WAF
            if not (host.get("waf_detected") or host.get("waf", "")):
                h_score += self._weights.get("no_waf", 10)
            records.append({
                "asset_type": "live_host",
                "asset_id":   url,
                "score":      min(h_score, SCORE_CAP),
                "factors":    {"url": url},
            })

        return records

    def _store_scores(self) -> None:
        """Store risk scores in the risk_scores table."""
        if not self.scores:
            return
        try:
            from backend.models.models import RiskScore, Target
            with get_db_context() as session:
                target = session.query(Target).filter(Target.domain == self.domain).first()
                target_id = target.id if target else "unknown"
                for rec in self.scores:
                    rs = RiskScore(
                        target_id    = target_id,
                        asset_type   = rec["asset_type"],
                        asset_id     = rec["asset_id"],
                        score        = rec["score"],
                        score_factors = rec.get("factors"),
                    )
                    session.add(rs)
                session.commit()
        except Exception as e:
            logger.warning(f"[Phase 7] DB storage error: {e}")
