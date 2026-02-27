"""
Unit tests for backend/utils/dedup.py — Phase 14 deduplication helpers.
"""

import pytest
from backend.utils.dedup import (
    dedup_subdomains, dedup_live_hosts, dedup_ports,
    dedup_vulns, dedup_js_findings, dedup_by_key,
)


class TestDedupSubdomains:
    def test_removes_exact_duplicates(self):
        items = [("sub.example.com", "subfinder"), ("sub.example.com", "amass")]
        result = dedup_subdomains(items)
        assert len(result) == 1
        assert result[0][0] == "sub.example.com"

    def test_case_insensitive(self):
        items = [("SUB.EXAMPLE.COM", "a"), ("sub.example.com", "b")]
        assert len(dedup_subdomains(items)) == 1

    def test_preserves_first_occurrence(self):
        items = [("a.com", "src1"), ("b.com", "src2"), ("a.com", "src3")]
        result = dedup_subdomains(items)
        assert len(result) == 2
        assert result[0] == ("a.com", "src1")

    def test_empty_list(self):
        assert dedup_subdomains([]) == []

    def test_skips_empty_subdomain(self):
        items = [("", "src"), ("a.com", "src")]
        result = dedup_subdomains(items)
        assert all(r[0] for r in result)

    def test_whitespace_stripped(self):
        items = [("  a.com  ", "src"), ("a.com", "src")]
        result = dedup_subdomains(items)
        assert len(result) == 1


class TestDedupLiveHosts:
    def test_removes_duplicate_urls(self):
        hosts = [{"url": "https://a.com/"}, {"url": "https://a.com/"}]
        assert len(dedup_live_hosts(hosts)) == 1

    def test_strips_trailing_slash(self):
        hosts = [{"url": "https://a.com/"}, {"url": "https://a.com"}]
        assert len(dedup_live_hosts(hosts)) == 1

    def test_case_insensitive(self):
        hosts = [{"url": "HTTPS://A.COM"}, {"url": "https://a.com"}]
        assert len(dedup_live_hosts(hosts)) == 1

    def test_different_urls_kept(self):
        hosts = [{"url": "https://a.com"}, {"url": "https://b.com"}]
        assert len(dedup_live_hosts(hosts)) == 2

    def test_empty_url_skipped(self):
        hosts = [{"url": ""}, {"url": "https://a.com"}]
        result = dedup_live_hosts(hosts)
        assert all(h["url"] for h in result)


class TestDedupPorts:
    def test_removes_duplicate_port_entries(self):
        ports = [
            {"host": "1.2.3.4", "port_number": 80, "protocol": "tcp"},
            {"host": "1.2.3.4", "port_number": 80, "protocol": "tcp"},
        ]
        assert len(dedup_ports(ports)) == 1

    def test_different_ports_kept(self):
        ports = [
            {"host": "1.2.3.4", "port_number": 80,  "protocol": "tcp"},
            {"host": "1.2.3.4", "port_number": 443, "protocol": "tcp"},
        ]
        assert len(dedup_ports(ports)) == 2

    def test_port_alias_key(self):
        # "port" alias should also work as key
        ports = [
            {"host": "x", "port": 22, "protocol": "tcp"},
            {"host": "x", "port": 22, "protocol": "tcp"},
        ]
        assert len(dedup_ports(ports)) == 1


class TestDedupVulns:
    def test_removes_duplicate_template_at(self):
        vulns = [
            {"template_id": "cve-1234", "matched_at": "https://x.com/admin"},
            {"template_id": "cve-1234", "matched_at": "https://x.com/admin"},
        ]
        assert len(dedup_vulns(vulns)) == 1

    def test_different_urls_kept(self):
        vulns = [
            {"template_id": "t1", "matched_at": "https://a.com"},
            {"template_id": "t1", "matched_at": "https://b.com"},
        ]
        assert len(dedup_vulns(vulns)) == 2

    def test_falls_back_to_name(self):
        vulns = [
            {"vulnerability_name": "XSS", "matched_at": "https://a.com/x"},
            {"vulnerability_name": "XSS", "matched_at": "https://a.com/x"},
        ]
        assert len(dedup_vulns(vulns)) == 1


class TestDedupJsFindings:
    def test_removes_duplicate_type_value(self):
        findings = [
            {"finding_type": "secret", "value": "sk_live_abc"},
            {"finding_type": "secret", "value": "sk_live_abc"},
        ]
        assert len(dedup_js_findings(findings)) == 1

    def test_different_values_kept(self):
        findings = [
            {"finding_type": "secret", "value": "key1"},
            {"finding_type": "secret", "value": "key2"},
        ]
        assert len(dedup_js_findings(findings)) == 2

    def test_skips_empty_value(self):
        findings = [
            {"finding_type": "secret", "value": ""},
            {"finding_type": "secret", "value": "realkey"},
        ]
        result = dedup_js_findings(findings)
        assert all(f.get("value") for f in result)


class TestDedupByKey:
    def test_dedup_by_single_key(self):
        items = [{"id": 1, "name": "a"}, {"id": 1, "name": "b"}, {"id": 2, "name": "c"}]
        result = dedup_by_key(items, "id")
        assert len(result) == 2

    def test_dedup_by_multiple_keys(self):
        items = [
            {"k1": "a", "k2": "x"},
            {"k1": "a", "k2": "x"},
            {"k1": "a", "k2": "y"},
        ]
        result = dedup_by_key(items, "k1", "k2")
        assert len(result) == 2

    def test_empty_input(self):
        assert dedup_by_key([], "id") == []
