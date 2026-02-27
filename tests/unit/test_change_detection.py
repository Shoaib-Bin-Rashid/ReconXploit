"""
Unit tests for Phase 6 — Change Detection Module.
No DB, no file I/O — all patched.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from backend.modules.change_detection import (
    ChangeDetector,
    CHANGE_SEVERITY,
    SIGNIFICANT_CHANGE_TYPES,
    SENSITIVE_PORTS,
)

# ─── Sample data ───────────────────────────────────────────

PREV_SUBDOMAINS = ["api.example.com", "mail.example.com"]
CURR_SUBDOMAINS = ["api.example.com", "new.example.com"]

PREV_LIVE = [
    {"url": "https://api.example.com", "status_code": 200,
     "server_header": "nginx", "waf_detected": ""},
]
CURR_LIVE = [
    {"url": "https://api.example.com", "status_code": 301,
     "server_header": "nginx", "waf_detected": "Cloudflare"},
    {"url": "https://new.example.com", "status_code": 200,
     "server_header": "Apache", "waf_detected": ""},
]

PREV_PORTS = [
    {"host": "1.2.3.4", "port": 80, "service_name": "http",  "service_version": "nginx/1.18"},
    {"host": "1.2.3.4", "port": 22, "service_name": "ssh",   "service_version": "OpenSSH 8.0"},
]
CURR_PORTS = [
    {"host": "1.2.3.4", "port": 80, "service_name": "http",  "service_version": "nginx/1.20"},
    {"host": "1.2.3.4", "port": 3306, "service_name": "mysql", "service_version": "8.0"},
]

PREV_VULNS = [
    {"template_id": "xss-reflected", "matched_at": "https://api.example.com/search",
     "severity": "high", "vulnerability_name": "Reflected XSS"},
]
CURR_VULNS = [
    {"template_id": "CVE-2021-44228", "matched_at": "https://api.example.com",
     "severity": "critical", "vulnerability_name": "Log4Shell"},
]

PREV_JS = [
    {"finding_type": "api_endpoint", "finding_value": "/api/v1", "risk_level": "low"},
]
CURR_JS = [
    {"finding_type": "api_endpoint",   "finding_value": "/api/v1",        "risk_level": "low"},
    {"finding_type": "admin_endpoint", "finding_value": "/admin/dashboard","risk_level": "high"},
    {"finding_type": "aws_access_key", "finding_value": "AKIAXXX",         "risk_level": "critical"},
]

CURRENT_DATA = {
    "subdomains":      CURR_SUBDOMAINS,
    "live_hosts":      CURR_LIVE,
    "ports":           CURR_PORTS,
    "vulnerabilities": CURR_VULNS,
    "js_findings":     CURR_JS,
}

PREV_SNAPSHOT = {
    "domain": "example.com",
    "scan_id": "prev-scan-id",
    "timestamp": "2026-02-25T00:00:00",
    "subdomains":      PREV_SUBDOMAINS,
    "live_hosts":      ChangeDetector._normalize_live_hosts.__func__(None, PREV_LIVE)
                       if False else [
                           {"url": "https://api.example.com", "status_code": 200,
                            "server": "nginx", "waf": ""}
                       ],
    "ports": [
        {"host": "1.2.3.4", "port": 80, "service": "http", "version": "nginx/1.18", "sensitive": False},
        {"host": "1.2.3.4", "port": 22, "service": "ssh",  "version": "OpenSSH 8.0","sensitive": True},
    ],
    "vulnerabilities": [
        {"template_id": "xss-reflected", "matched_at": "https://api.example.com/search",
         "severity": "high", "name": "Reflected XSS"},
    ],
    "js_findings": [
        {"finding_type": "api_endpoint", "finding_value": "/api/v1", "risk_level": "low"},
    ],
}


# ─────────────────────────────────────────────────────────────
# Init
# ─────────────────────────────────────────────────────────────

class TestChangeDetectorInit:
    def test_init(self):
        cd = ChangeDetector("example.com", "scan-001")
        assert cd.domain == "example.com"
        assert cd.scan_id == "scan-001"
        assert cd.changes == []

    def test_get_results_empty(self):
        cd = ChangeDetector("example.com", "scan-001")
        assert cd.get_results() == []

    def test_get_summary_empty(self):
        cd = ChangeDetector("example.com", "scan-001")
        s = cd.get_summary()
        assert s["total"] == 0
        assert s["significant"] == 0


# ─────────────────────────────────────────────────────────────
# Snapshot I/O
# ─────────────────────────────────────────────────────────────

class TestSnapshotIO:
    def test_load_snapshot_returns_none_when_missing(self, tmp_path):
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=tmp_path / "missing.json"):
            result = cd._load_snapshot()
        assert result is None

    def test_load_snapshot_returns_data(self, tmp_path):
        snap_file = tmp_path / "example.com_latest.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file):
            result = cd._load_snapshot()
        assert result["domain"] == "example.com"
        assert "subdomains" in result

    def test_save_snapshot_writes_file(self, tmp_path):
        snap_file = tmp_path / "example.com_latest.json"
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file):
            cd._save_snapshot(CURRENT_DATA)
        assert snap_file.exists()
        data = json.loads(snap_file.read_text())
        assert data["domain"] == "example.com"
        assert data["scan_id"] == "scan-001"

    def test_save_snapshot_includes_all_layers(self, tmp_path):
        snap_file = tmp_path / "example.com_latest.json"
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file):
            cd._save_snapshot(CURRENT_DATA)
        data = json.loads(snap_file.read_text())
        for key in ("subdomains", "live_hosts", "ports", "vulnerabilities", "js_findings"):
            assert key in data

    def test_load_snapshot_handles_corrupt_file(self, tmp_path):
        snap_file = tmp_path / "example.com_latest.json"
        snap_file.write_text("not valid json{{{")
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file):
            result = cd._load_snapshot()
        assert result is None


# ─────────────────────────────────────────────────────────────
# Subdomain diff
# ─────────────────────────────────────────────────────────────

class TestSubdomainDiff:
    def test_detects_new_subdomain(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_subdomains(["api.example.com"], ["api.example.com", "new.example.com"])
        types = [c["change_type"] for c in changes]
        assert "new_subdomain" in types

    def test_detects_removed_subdomain(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_subdomains(["api.example.com", "old.example.com"], ["api.example.com"])
        types = [c["change_type"] for c in changes]
        assert "removed_subdomain" in types

    def test_no_changes_when_same(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_subdomains(["api.example.com"], ["api.example.com"])
        assert changes == []

    def test_new_subdomain_asset_id(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_subdomains([], ["new.example.com"])
        assert changes[0]["asset_id"] == "new.example.com"

    def test_new_subdomain_severity_is_low(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_subdomains([], ["new.example.com"])
        assert changes[0]["severity"] == "low"

    def test_case_insensitive_comparison(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_subdomains(["API.EXAMPLE.COM"], ["api.example.com"])
        assert changes == []


# ─────────────────────────────────────────────────────────────
# Live host diff
# ─────────────────────────────────────────────────────────────

class TestLiveHostDiff:
    def _prev(self):
        return [{"url": "https://api.example.com", "status_code": 200,
                 "server_header": "nginx", "waf_detected": ""}]

    def test_detects_new_live_host(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = self._prev() + [{"url": "https://new.example.com", "status_code": 200,
                                 "server_header": "Apache", "waf_detected": ""}]
        changes = cd._diff_live_hosts(self._prev(), curr)
        assert any(c["change_type"] == "new_live_host" for c in changes)

    def test_detects_removed_live_host(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_live_hosts(self._prev(), [])
        assert any(c["change_type"] == "removed_live_host" for c in changes)

    def test_detects_status_code_change(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"url": "https://api.example.com", "status_code": 404,
                 "server_header": "nginx", "waf_detected": ""}]
        changes = cd._diff_live_hosts(self._prev(), curr)
        assert any(c["change_type"] == "status_code_changed" for c in changes)

    def test_detects_waf_added(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"url": "https://api.example.com", "status_code": 200,
                 "server_header": "nginx", "waf_detected": "Cloudflare"}]
        changes = cd._diff_live_hosts(self._prev(), curr)
        assert any(c["change_type"] == "waf_added" for c in changes)

    def test_detects_waf_removed(self):
        cd = ChangeDetector("example.com", "scan-001")
        prev = [{"url": "https://api.example.com", "status_code": 200,
                 "server_header": "nginx", "waf_detected": "Cloudflare"}]
        curr = [{"url": "https://api.example.com", "status_code": 200,
                 "server_header": "nginx", "waf_detected": ""}]
        changes = cd._diff_live_hosts(prev, curr)
        assert any(c["change_type"] == "waf_removed" for c in changes)

    def test_waf_removed_is_significant(self):
        cd = ChangeDetector("example.com", "scan-001")
        prev = [{"url": "https://api.example.com", "status_code": 200,
                 "server_header": "nginx", "waf_detected": "Cloudflare"}]
        curr = [{"url": "https://api.example.com", "status_code": 200,
                 "server_header": "nginx", "waf_detected": ""}]
        changes = cd._diff_live_hosts(prev, curr)
        waf_removed = [c for c in changes if c["change_type"] == "waf_removed"]
        assert waf_removed[0]["is_significant"]

    def test_no_change_when_identical(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_live_hosts(self._prev(), self._prev())
        assert changes == []


# ─────────────────────────────────────────────────────────────
# Port diff
# ─────────────────────────────────────────────────────────────

class TestPortDiff:
    def _prev(self):
        return [{"host": "1.2.3.4", "port": 80, "service_name": "http", "service_version": ""}]

    def test_detects_new_port(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = self._prev() + [{"host": "1.2.3.4", "port": 443,
                                  "service_name": "https", "service_version": ""}]
        changes = cd._diff_ports(self._prev(), curr)
        assert any(c["change_type"] == "new_open_port" for c in changes)

    def test_detects_closed_port(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_ports(self._prev(), [])
        assert any(c["change_type"] == "closed_port" for c in changes)

    def test_sensitive_port_gets_high_severity(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"host": "1.2.3.4", "port": 3306, "service_name": "mysql", "service_version": "8.0"}]
        changes = cd._diff_ports([], curr)
        sensitive = [c for c in changes if c["change_type"] == "new_sensitive_port"]
        assert sensitive[0]["severity"] == "high"
        assert sensitive[0]["is_significant"]

    def test_non_sensitive_port_not_significant(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"host": "1.2.3.4", "port": 8080, "service_name": "http", "service_version": ""}]
        changes = cd._diff_ports([], curr)
        assert not changes[0]["is_significant"]

    def test_detects_version_change(self):
        cd = ChangeDetector("example.com", "scan-001")
        prev = [{"host": "1.2.3.4", "port": 80, "service_name": "http", "service_version": "nginx/1.18"}]
        curr = [{"host": "1.2.3.4", "port": 80, "service_name": "http", "service_version": "nginx/1.20"}]
        changes = cd._diff_ports(prev, curr)
        assert any(c["change_type"] == "version_changed" for c in changes)

    def test_detects_service_change(self):
        cd = ChangeDetector("example.com", "scan-001")
        prev = [{"host": "1.2.3.4", "port": 80, "service_name": "http",  "service_version": ""}]
        curr = [{"host": "1.2.3.4", "port": 80, "service_name": "https", "service_version": ""}]
        changes = cd._diff_ports(prev, curr)
        assert any(c["change_type"] == "service_changed" for c in changes)


# ─────────────────────────────────────────────────────────────
# Vulnerability diff
# ─────────────────────────────────────────────────────────────

class TestVulnDiff:
    def _prev(self):
        return [{"template_id": "xss-reflected",
                 "matched_at": "https://api.example.com/q",
                 "severity": "high", "vulnerability_name": "XSS"}]

    def test_detects_new_critical_vuln(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"template_id": "CVE-2021-44228", "matched_at": "https://api.example.com",
                 "severity": "critical", "vulnerability_name": "Log4Shell"}]
        changes = cd._diff_vulnerabilities([], curr)
        assert any(c["change_type"] == "new_vulnerability_critical" for c in changes)

    def test_new_critical_is_significant(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"template_id": "CVE-2021-44228", "matched_at": "https://api.example.com",
                 "severity": "critical", "vulnerability_name": "Log4Shell"}]
        changes = cd._diff_vulnerabilities([], curr)
        crit = [c for c in changes if c["change_type"] == "new_vulnerability_critical"]
        assert crit[0]["is_significant"]

    def test_detects_new_high_vuln(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"template_id": "sqli-generic", "matched_at": "https://api.example.com/login",
                 "severity": "high", "vulnerability_name": "SQLi"}]
        changes = cd._diff_vulnerabilities([], curr)
        assert any(c["change_type"] == "new_vulnerability_high" for c in changes)

    def test_detects_vulnerability_fixed(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_vulnerabilities(self._prev(), [])
        assert any(c["change_type"] == "vulnerability_fixed" for c in changes)

    def test_no_change_when_same_vuln(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_vulnerabilities(self._prev(), self._prev())
        assert changes == []


# ─────────────────────────────────────────────────────────────
# JS findings diff
# ─────────────────────────────────────────────────────────────

class TestJsDiff:
    def _prev(self):
        return [{"finding_type": "api_endpoint", "finding_value": "/api/v1", "risk_level": "low"}]

    def test_detects_new_secret(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = self._prev() + [{"finding_type": "aws_access_key",
                                  "finding_value": "AKIAXXX", "risk_level": "critical"}]
        changes = cd._diff_js_findings(self._prev(), curr)
        assert any(c["change_type"] == "new_js_secret" for c in changes)

    def test_new_secret_is_significant(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"finding_type": "aws_access_key", "finding_value": "AKIAXXX", "risk_level": "critical"}]
        changes = cd._diff_js_findings([], curr)
        secrets = [c for c in changes if c["change_type"] == "new_js_secret"]
        assert secrets[0]["is_significant"]

    def test_detects_new_admin_endpoint(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"finding_type": "admin_endpoint", "finding_value": "/admin", "risk_level": "high"}]
        changes = cd._diff_js_findings([], curr)
        assert any(c["change_type"] == "new_admin_endpoint" for c in changes)

    def test_detects_new_graphql(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"finding_type": "graphql_endpoint", "finding_value": "/graphql", "risk_level": "medium"}]
        changes = cd._diff_js_findings([], curr)
        assert any(c["change_type"] == "new_graphql_endpoint" for c in changes)

    def test_no_change_when_same_endpoint(self):
        cd = ChangeDetector("example.com", "scan-001")
        changes = cd._diff_js_findings(self._prev(), self._prev())
        assert changes == []

    def test_generic_endpoint_uses_new_js_endpoint(self):
        cd = ChangeDetector("example.com", "scan-001")
        curr = [{"finding_type": "api_endpoint", "finding_value": "/api/v2", "risk_level": "low"}]
        changes = cd._diff_js_findings([], curr)
        assert changes[0]["change_type"] == "new_js_endpoint"


# ─────────────────────────────────────────────────────────────
# make_change factory
# ─────────────────────────────────────────────────────────────

class TestMakeChange:
    def test_make_change_fields(self):
        cd = ChangeDetector("example.com", "scan-001")
        c = cd._make_change("new_subdomain", "subdomain", "new.example.com",
                            new_value={"subdomain": "new.example.com"})
        assert c["change_type"]    == "new_subdomain"
        assert c["asset_type"]     == "subdomain"
        assert c["asset_id"]       == "new.example.com"
        assert c["severity"]       == "low"
        assert c["is_significant"] is False
        assert c["detected_at"]    is not None

    def test_significant_changes_marked(self):
        cd = ChangeDetector("example.com", "scan-001")
        for ct in SIGNIFICANT_CHANGE_TYPES:
            c = cd._make_change(ct, "test", "id")
            assert c["is_significant"], f"{ct} should be significant"

    def test_old_new_value_preserved(self):
        cd = ChangeDetector("example.com", "scan-001")
        c = cd._make_change("status_code_changed", "live_host", "https://x.com",
                            old_value={"status_code": 200},
                            new_value={"status_code": 404})
        assert c["old_value"]["status_code"] == 200
        assert c["new_value"]["status_code"] == 404


# ─────────────────────────────────────────────────────────────
# run() — first scan (no previous snapshot)
# ─────────────────────────────────────────────────────────────

class TestRunFirstScan:
    def test_first_scan_returns_zero(self, tmp_path):
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=tmp_path / "snap.json"), \
             patch("backend.modules.change_detection.save_changes"), \
             patch.object(cd, "_store_changes", return_value=0):
            result = cd.run(CURRENT_DATA)
        assert result == 0

    def test_first_scan_saves_snapshot(self, tmp_path):
        snap_file = tmp_path / "snap.json"
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch.object(cd, "_store_changes", return_value=0):
            cd.run(CURRENT_DATA)
        assert snap_file.exists()

    def test_first_scan_no_changes_in_results(self, tmp_path):
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=tmp_path / "snap.json"), \
             patch("backend.modules.change_detection.save_changes"), \
             patch.object(cd, "_store_changes", return_value=0):
            cd.run(CURRENT_DATA)
        assert cd.get_results() == []


# ─────────────────────────────────────────────────────────────
# run() — subsequent scan (diff)
# ─────────────────────────────────────────────────────────────

class TestRunWithPreviousSnapshot:
    def test_detects_changes_on_second_run(self, tmp_path):
        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch.object(cd, "_store_changes", return_value=5):
            count = cd.run(CURRENT_DATA)
        assert count > 0

    def test_second_run_updates_snapshot(self, tmp_path):
        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))
        cd = ChangeDetector("example.com", "scan-new")
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch.object(cd, "_store_changes", return_value=0):
            cd.run(CURRENT_DATA)
        updated = json.loads(snap_file.read_text())
        assert updated["scan_id"] == "scan-new"

    def test_second_run_calls_file_storage(self, tmp_path):
        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes") as mock_save, \
             patch.object(cd, "_store_changes", return_value=0):
            cd.run(CURRENT_DATA)
        mock_save.assert_called_once()

    def test_changes_sorted_significant_first(self, tmp_path):
        snap_file = tmp_path / "snap.json"
        snap_file.write_text(json.dumps(PREV_SNAPSHOT))
        cd = ChangeDetector("example.com", "scan-001")
        with patch.object(cd, "_snapshot_path", return_value=snap_file), \
             patch("backend.modules.change_detection.save_changes"), \
             patch.object(cd, "_store_changes", return_value=0):
            cd.run(CURRENT_DATA)
        if len(cd.changes) >= 2:
            sig_indices = [i for i, c in enumerate(cd.changes) if c["is_significant"]]
            non_sig_indices = [i for i, c in enumerate(cd.changes) if not c["is_significant"]]
            if sig_indices and non_sig_indices:
                assert max(sig_indices) < min(non_sig_indices)


# ─────────────────────────────────────────────────────────────
# get_summary / get_significant
# ─────────────────────────────────────────────────────────────

class TestSummaryAndSignificant:
    def test_get_summary_counts(self):
        cd = ChangeDetector("example.com", "scan-001")
        cd.changes = [
            {"change_type": "new_subdomain", "severity": "low", "is_significant": False},
            {"change_type": "new_subdomain", "severity": "low", "is_significant": False},
            {"change_type": "new_js_secret", "severity": "high", "is_significant": True},
        ]
        s = cd.get_summary()
        assert s["total"] == 3
        assert s["significant"] == 1
        assert s["new_subdomain"] == 2
        assert s["new_js_secret"] == 1

    def test_get_significant_filters(self):
        cd = ChangeDetector("example.com", "scan-001")
        cd.changes = [
            {"change_type": "new_subdomain", "is_significant": False},
            {"change_type": "new_js_secret", "is_significant": True},
        ]
        sig = cd.get_significant()
        assert len(sig) == 1
        assert sig[0]["change_type"] == "new_js_secret"
