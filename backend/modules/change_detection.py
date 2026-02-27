"""
ReconXploit - Change Detection Module
Phase 6: Compare current scan vs previous snapshot and surface meaningful changes.

Pipeline:
  1. Load previous snapshot  — from data/snapshots/{domain}_latest.json
  2. Diff each asset layer   — subdomains, live_hosts, ports, vulns, js_findings
  3. Score each change       — assign severity + is_significant flag
  4. Store to DB             — Change table (graceful fallback)
  5. Save snapshot           — overwrite data/snapshots/{domain}_latest.json
  6. Save changes to file    — data/changes/{domain}.txt

On first scan (no previous snapshot): saves baseline, no changes generated.
Every subsequent scan produces a diff against the previous baseline.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from backend.models.database import get_db_context
from backend.utils.file_storage import save_changes

logger = logging.getLogger(__name__)

# Base snapshot directory
SNAPSHOT_DIR = Path(__file__).parent.parent.parent / "data" / "snapshots"

# ─────────────────────────────────────────────────────────────
# SEVERITY RULES PER CHANGE TYPE
# ─────────────────────────────────────────────────────────────

CHANGE_SEVERITY: Dict[str, str] = {
    # Subdomains
    "new_subdomain":          "low",
    "removed_subdomain":      "low",
    # Live hosts
    "new_live_host":          "medium",
    "removed_live_host":      "low",
    "status_code_changed":    "low",
    "server_changed":         "low",
    "waf_added":              "medium",
    "waf_removed":            "medium",
    # Ports
    "new_open_port":          "medium",
    "closed_port":            "low",
    "service_changed":        "medium",
    "version_changed":        "low",
    "new_sensitive_port":     "high",
    # Vulnerabilities
    "new_vulnerability_critical": "critical",
    "new_vulnerability_high":     "high",
    "new_vulnerability_medium":   "medium",
    "new_vulnerability_low":      "low",
    "vulnerability_fixed":        "low",
    # JS
    "new_js_secret":          "high",
    "new_js_endpoint":        "low",
    "new_admin_endpoint":     "high",
    "new_graphql_endpoint":   "medium",
    "new_s3_bucket":          "high",
    "new_debug_endpoint":     "high",
}

# Changes that are "significant" (need immediate review)
SIGNIFICANT_CHANGE_TYPES: Set[str] = {
    "new_sensitive_port",
    "new_vulnerability_critical",
    "new_vulnerability_high",
    "new_js_secret",
    "new_admin_endpoint",
    "new_debug_endpoint",
    "new_s3_bucket",
    "waf_removed",
}

# Sensitive ports (same set as port_scan.py)
SENSITIVE_PORTS: Set[int] = {22, 21, 23, 3306, 5432, 1433, 1521, 6379, 27017, 9200, 5601, 8500}


class ChangeDetector:
    """
    Compares current scan results against the previous snapshot to detect changes.
    """

    def __init__(self, domain: str, scan_id: str):
        self.domain   = domain
        self.scan_id  = scan_id
        self.changes: List[Dict] = []

    # ─────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────

    def run(self, current_data: Dict) -> int:
        """
        Run change detection.

        Args:
            current_data: dict with keys:
                subdomains    — list of subdomain strings
                live_hosts    — list of dicts from Phase 2
                ports         — list of dicts from Phase 3
                vulnerabilities — list of dicts from Phase 4
                js_findings   — list of dicts from Phase 5

        Returns:
            Number of changes detected.
        """
        logger.info(f"[Phase 6] Running change detection for {self.domain}")

        # Load previous snapshot
        previous = self._load_snapshot()

        if previous is None:
            logger.info(f"[Phase 6] First scan for {self.domain} — saving baseline snapshot")
            self._save_snapshot(current_data)
            save_changes(self.domain, [])
            return 0

        # Diff each layer
        self.changes.extend(self._diff_subdomains(
            previous.get("subdomains", []),
            current_data.get("subdomains", []),
        ))
        self.changes.extend(self._diff_live_hosts(
            previous.get("live_hosts", []),
            current_data.get("live_hosts", []),
        ))
        self.changes.extend(self._diff_ports(
            previous.get("ports", []),
            current_data.get("ports", []),
        ))
        self.changes.extend(self._diff_vulnerabilities(
            previous.get("vulnerabilities", []),
            current_data.get("vulnerabilities", []),
        ))
        self.changes.extend(self._diff_js_findings(
            previous.get("js_findings", []),
            current_data.get("js_findings", []),
        ))

        # Sort: significant first, then by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.changes.sort(key=lambda c: (
            0 if c.get("is_significant") else 1,
            sev_order.get(c.get("severity", "low"), 4),
        ))

        # Store to DB
        stored = self._store_changes(self.changes)

        # Update snapshot to current
        self._save_snapshot(current_data)

        # Save to text file
        save_changes(self.domain, self.changes)

        sig = sum(1 for c in self.changes if c.get("is_significant"))
        logger.info(
            f"[Phase 6] {len(self.changes)} changes detected "
            f"({sig} significant) for {self.domain}"
        )
        return len(self.changes)

    def get_results(self) -> List[Dict]:
        return self.changes

    def get_summary(self) -> Dict:
        summary: Dict[str, int] = {
            "total":       len(self.changes),
            "significant": sum(1 for c in self.changes if c.get("is_significant")),
        }
        for c in self.changes:
            t = c.get("change_type", "unknown")
            summary[t] = summary.get(t, 0) + 1
        return summary

    def get_significant(self) -> List[Dict]:
        return [c for c in self.changes if c.get("is_significant")]

    # ─────────────────────────────────────────────────
    # SNAPSHOT I/O
    # ─────────────────────────────────────────────────

    def _snapshot_path(self) -> Path:
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        return SNAPSHOT_DIR / f"{self.domain}_latest.json"

    def _load_snapshot(self) -> Optional[Dict]:
        """Load the most recent snapshot for this domain."""
        path = self._snapshot_path()
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"[Phase 6] Failed to load snapshot: {e}")
            return None

    def _save_snapshot(self, data: Dict) -> None:
        """Save current scan data as new snapshot."""
        path = self._snapshot_path()
        snapshot = {
            "domain":          self.domain,
            "scan_id":         self.scan_id,
            "timestamp":       datetime.utcnow().isoformat(),
            "subdomains":      data.get("subdomains", []),
            "live_hosts":      self._normalize_live_hosts(data.get("live_hosts", [])),
            "ports":           self._normalize_ports(data.get("ports", [])),
            "vulnerabilities": self._normalize_vulns(data.get("vulnerabilities", [])),
            "js_findings":     self._normalize_js(data.get("js_findings", [])),
        }
        try:
            path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
            logger.debug(f"[Phase 6] Snapshot saved to {path}")
        except Exception as e:
            logger.warning(f"[Phase 6] Failed to save snapshot: {e}")

    # ─────────────────────────────────────────────────
    # NORMALIZERS  (extract stable comparison keys)
    # ─────────────────────────────────────────────────

    @staticmethod
    def _normalize_live_hosts(hosts: List[Dict]) -> List[Dict]:
        return [
            {
                "url":         h.get("url", ""),
                "status_code": h.get("status_code"),
                "server":      h.get("server_header") or h.get("server", ""),
                "waf":         h.get("waf_detected") or h.get("waf", ""),
            }
            for h in hosts
        ]

    @staticmethod
    def _normalize_ports(ports: List[Dict]) -> List[Dict]:
        return [
            {
                "host":     p.get("host", "") or p.get("ip_address", ""),
                "port":     int(p.get("port", 0)),
                "service":  p.get("service_name") or p.get("service", ""),
                "version":  p.get("service_version") or p.get("version", ""),
                "sensitive": bool(p.get("is_sensitive") or p.get("sensitive", False)),
            }
            for p in ports
        ]

    @staticmethod
    def _normalize_vulns(vulns: List[Dict]) -> List[Dict]:
        return [
            {
                "template_id": v.get("template_id", ""),
                "matched_at":  v.get("matched_at") or v.get("url", ""),
                "severity":    v.get("severity", "info"),
                "name":        v.get("vulnerability_name") or v.get("name", ""),
            }
            for v in vulns
        ]

    @staticmethod
    def _normalize_js(findings: List[Dict]) -> List[Dict]:
        return [
            {
                "finding_type":  f.get("finding_type", ""),
                "finding_value": f.get("finding_value", "")[:80],
                "risk_level":    f.get("risk_level", "low"),
            }
            for f in findings
        ]

    # ─────────────────────────────────────────────────
    # DIFF ENGINES
    # ─────────────────────────────────────────────────

    def _diff_subdomains(self, prev: List, curr: List) -> List[Dict]:
        prev_set = set(s.strip().lower() for s in prev if s)
        curr_set = set(s.strip().lower() for s in curr if s)
        changes = []

        for s in sorted(curr_set - prev_set):
            changes.append(self._make_change(
                change_type="new_subdomain",
                asset_type="subdomain",
                asset_id=s,
                new_value={"subdomain": s},
            ))
        for s in sorted(prev_set - curr_set):
            changes.append(self._make_change(
                change_type="removed_subdomain",
                asset_type="subdomain",
                asset_id=s,
                old_value={"subdomain": s},
            ))
        return changes

    def _diff_live_hosts(self, prev: List[Dict], curr: List[Dict]) -> List[Dict]:
        prev_map = {h["url"]: h for h in self._normalize_live_hosts(prev)}
        curr_map = {h["url"]: h for h in self._normalize_live_hosts(curr)}
        changes = []

        for url in sorted(set(curr_map) - set(prev_map)):
            changes.append(self._make_change(
                change_type="new_live_host",
                asset_type="live_host",
                asset_id=url,
                new_value=curr_map[url],
            ))
        for url in sorted(set(prev_map) - set(curr_map)):
            changes.append(self._make_change(
                change_type="removed_live_host",
                asset_type="live_host",
                asset_id=url,
                old_value=prev_map[url],
            ))
        for url in sorted(set(prev_map) & set(curr_map)):
            p, c = prev_map[url], curr_map[url]
            if p.get("status_code") != c.get("status_code"):
                changes.append(self._make_change(
                    change_type="status_code_changed",
                    asset_type="live_host",
                    asset_id=url,
                    old_value={"status_code": p.get("status_code")},
                    new_value={"status_code": c.get("status_code")},
                ))
            if p.get("server") != c.get("server") and c.get("server"):
                changes.append(self._make_change(
                    change_type="server_changed",
                    asset_type="live_host",
                    asset_id=url,
                    old_value={"server": p.get("server")},
                    new_value={"server": c.get("server")},
                ))
            prev_waf = bool(p.get("waf"))
            curr_waf = bool(c.get("waf"))
            if not prev_waf and curr_waf:
                changes.append(self._make_change(
                    change_type="waf_added",
                    asset_type="live_host",
                    asset_id=url,
                    new_value={"waf": c.get("waf")},
                ))
            elif prev_waf and not curr_waf:
                changes.append(self._make_change(
                    change_type="waf_removed",
                    asset_type="live_host",
                    asset_id=url,
                    old_value={"waf": p.get("waf")},
                ))
        return changes

    def _diff_ports(self, prev: List[Dict], curr: List[Dict]) -> List[Dict]:
        def port_key(p: Dict) -> Tuple:
            return (p.get("host", ""), int(p.get("port", 0)))

        prev_map = {port_key(p): p for p in self._normalize_ports(prev)}
        curr_map = {port_key(p): p for p in self._normalize_ports(curr)}
        changes = []

        for key in sorted(set(curr_map) - set(prev_map)):
            p = curr_map[key]
            port_num = key[1]
            change_type = "new_sensitive_port" if port_num in SENSITIVE_PORTS else "new_open_port"
            changes.append(self._make_change(
                change_type=change_type,
                asset_type="port",
                asset_id=f"{key[0]}:{key[1]}",
                new_value=p,
            ))
        for key in sorted(set(prev_map) - set(curr_map)):
            p = prev_map[key]
            changes.append(self._make_change(
                change_type="closed_port",
                asset_type="port",
                asset_id=f"{key[0]}:{key[1]}",
                old_value=p,
            ))
        for key in sorted(set(prev_map) & set(curr_map)):
            pv, cv = prev_map[key], curr_map[key]
            if pv.get("service") != cv.get("service") and cv.get("service"):
                changes.append(self._make_change(
                    change_type="service_changed",
                    asset_type="port",
                    asset_id=f"{key[0]}:{key[1]}",
                    old_value={"service": pv.get("service")},
                    new_value={"service": cv.get("service")},
                ))
            elif pv.get("version") != cv.get("version") and cv.get("version"):
                changes.append(self._make_change(
                    change_type="version_changed",
                    asset_type="port",
                    asset_id=f"{key[0]}:{key[1]}",
                    old_value={"version": pv.get("version")},
                    new_value={"version": cv.get("version")},
                ))
        return changes

    def _diff_vulnerabilities(self, prev: List[Dict], curr: List[Dict]) -> List[Dict]:
        def vuln_key(v: Dict) -> Tuple:
            return (
                v.get("template_id", ""),
                v.get("matched_at") or v.get("url", ""),
            )

        prev_set = {vuln_key(v) for v in self._normalize_vulns(prev)}
        curr_map = {vuln_key(v): v for v in self._normalize_vulns(curr)}
        changes = []

        for key, v in sorted(curr_map.items()):
            if key not in prev_set:
                severity = v.get("severity", "info")
                change_type = f"new_vulnerability_{severity}"
                if change_type not in CHANGE_SEVERITY:
                    change_type = "new_vulnerability_low"
                changes.append(self._make_change(
                    change_type=change_type,
                    asset_type="vulnerability",
                    asset_id=f"{key[0]}@{key[1]}",
                    new_value=v,
                ))

        prev_map = {vuln_key(v): v for v in self._normalize_vulns(prev)}
        for key, v in sorted(prev_map.items()):
            if key not in curr_map:
                changes.append(self._make_change(
                    change_type="vulnerability_fixed",
                    asset_type="vulnerability",
                    asset_id=f"{key[0]}@{key[1]}",
                    old_value=v,
                ))
        return changes

    def _diff_js_findings(self, prev: List[Dict], curr: List[Dict]) -> List[Dict]:
        def js_key(f: Dict) -> Tuple:
            return (f.get("finding_type", ""), f.get("finding_value", "")[:80])

        prev_set = {js_key(f) for f in self._normalize_js(prev)}
        curr_map = {js_key(f): f for f in self._normalize_js(curr)}
        changes = []

        SECRET_TYPES = {
            "aws_access_key", "aws_secret_key", "private_key", "jwt_token",
            "stripe_live_key", "stripe_test_key", "google_api_key", "firebase_key",
            "github_token", "slack_token", "twilio_key", "sendgrid_key",
            "bearer_token", "db_connection", "password", "generic_api_key",
        }
        HIGH_ENDPOINTS = {"admin_endpoint", "debug_endpoint", "s3_bucket"}

        for key, f in sorted(curr_map.items()):
            if key not in prev_set:
                ftype = f.get("finding_type", "")
                if ftype in SECRET_TYPES:
                    change_type = "new_js_secret"
                elif ftype == "graphql_endpoint":
                    change_type = "new_graphql_endpoint"
                elif ftype in HIGH_ENDPOINTS:
                    change_type = f"new_{ftype}"
                else:
                    change_type = "new_js_endpoint"
                changes.append(self._make_change(
                    change_type=change_type,
                    asset_type="js_finding",
                    asset_id=f"{ftype}:{f.get('finding_value', '')[:50]}",
                    new_value=f,
                ))
        return changes

    # ─────────────────────────────────────────────────
    # CHANGE FACTORY
    # ─────────────────────────────────────────────────

    def _make_change(
        self,
        change_type: str,
        asset_type: str,
        asset_id: str,
        old_value: Optional[Dict] = None,
        new_value: Optional[Dict] = None,
    ) -> Dict:
        severity     = CHANGE_SEVERITY.get(change_type, "low")
        is_significant = change_type in SIGNIFICANT_CHANGE_TYPES
        return {
            "change_type":   change_type,
            "asset_type":    asset_type,
            "asset_id":      asset_id,
            "old_value":     old_value,
            "new_value":     new_value,
            "severity":      severity,
            "is_significant": is_significant,
            "detected_at":   datetime.utcnow().isoformat(),
        }

    # ─────────────────────────────────────────────────
    # DB STORAGE
    # ─────────────────────────────────────────────────

    def _store_changes(self, changes: List[Dict]) -> int:
        """Store changes in the changes table."""
        if not changes:
            return 0
        try:
            from backend.models.models import Change, Target
            stored = 0
            with get_db_context() as session:
                # Resolve target_id from domain
                target = session.query(Target).filter(Target.domain == self.domain).first()
                target_id = target.id if target else "unknown"

                for c in changes:
                    rec = Change(
                        scan_id        = self.scan_id,
                        target_id      = target_id,
                        change_type    = c["change_type"],
                        asset_type     = c["asset_type"],
                        asset_identifier = c["asset_id"],
                        old_value      = c.get("old_value"),
                        new_value      = c.get("new_value"),
                        severity       = c["severity"],
                        is_significant = c["is_significant"],
                    )
                    session.add(rec)
                    stored += 1
                session.commit()
            return stored
        except Exception as e:
            logger.warning(f"[Phase 6] DB storage error: {e}")
            return 0
