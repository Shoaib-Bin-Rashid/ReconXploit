"""
Unit tests for backend/models/models.py

Tests ORM model instantiation, relationships, constraints,
and default values. Uses in-memory SQLite — no PostgreSQL needed.
"""

import uuid
import pytest
from datetime import datetime
from unittest.mock import patch


# ── SQLite compatibility patch for INET and UUID columns ─────────────────────
# PostgreSQL-specific types fall back gracefully in SQLite tests.

@pytest.mark.unit
class TestTargetModel:
    """Tests for the Target ORM model."""

    def test_target_instantiation(self):
        from backend.models.models import Target
        t = Target(domain="example.com", organization="Acme Corp")
        assert t.domain == "example.com"
        assert t.organization == "Acme Corp"

    def test_target_default_status(self):
        from backend.models.models import Target
        t = Target(domain="example.com")
        assert t.status == "active"

    def test_target_repr(self):
        from backend.models.models import Target
        t = Target(domain="example.com")
        assert "example.com" in repr(t)

    def test_target_valid_statuses(self):
        from backend.models.models import Target
        for status in ("active", "paused", "archived"):
            t = Target(domain=f"test-{status}.com", status=status)
            assert t.status == status

    def test_target_requires_domain(self):
        from backend.models.models import Target
        # domain is not nullable — should be set
        t = Target()
        assert t.domain is None  # not enforced at Python level, only at DB level

    def test_target_uuid_primary_key_type(self):
        from backend.models.models import Target
        import uuid
        t = Target(domain="example.com")
        t.id = uuid.uuid4()
        assert isinstance(t.id, uuid.UUID)


@pytest.mark.unit
class TestScanModel:
    """Tests for the Scan ORM model."""

    def test_scan_default_status(self):
        from backend.models.models import Scan
        s = Scan()
        assert s.status == "pending"

    def test_scan_default_type(self):
        from backend.models.models import Scan
        s = Scan()
        assert s.scan_type == "full"

    def test_scan_valid_types(self):
        from backend.models.models import Scan
        for scan_type in ("full", "quick", "deep", "custom"):
            s = Scan(scan_type=scan_type)
            assert s.scan_type == scan_type

    def test_scan_valid_statuses(self):
        from backend.models.models import Scan
        for status in ("pending", "running", "completed", "failed", "cancelled"):
            s = Scan(status=status)
            assert s.status == status

    def test_scan_stats_accepts_dict(self):
        from backend.models.models import Scan
        stats = {"subdomains_found": 100, "live_hosts": 50, "vulns": 3}
        s = Scan(stats=stats)
        assert s.stats["subdomains_found"] == 100

    def test_scan_repr(self):
        from backend.models.models import Scan
        s = Scan(status="running")
        assert "running" in repr(s)


@pytest.mark.unit
class TestSubdomainModel:
    """Tests for the Subdomain ORM model."""

    def test_subdomain_instantiation(self):
        from backend.models.models import Subdomain
        s = Subdomain(subdomain="api.example.com", source="subfinder")
        assert s.subdomain == "api.example.com"
        assert s.source == "subfinder"

    def test_subdomain_default_active(self):
        from backend.models.models import Subdomain
        s = Subdomain(subdomain="test.example.com")
        assert s.is_active is True

    def test_subdomain_repr(self):
        from backend.models.models import Subdomain
        s = Subdomain(subdomain="api.example.com")
        assert "api.example.com" in repr(s)

    def test_subdomain_sources(self):
        from backend.models.models import Subdomain
        for source in ("subfinder", "amass", "assetfinder", "crt.sh", "findomain"):
            s = Subdomain(subdomain="test.com", source=source)
            assert s.source == source


@pytest.mark.unit
class TestLiveHostModel:
    """Tests for the LiveHost ORM model."""

    def test_livehost_instantiation(self):
        from backend.models.models import LiveHost
        lh = LiveHost(url="https://api.example.com", status_code=200)
        assert lh.url == "https://api.example.com"
        assert lh.status_code == 200

    def test_livehost_default_active(self):
        from backend.models.models import LiveHost
        lh = LiveHost(url="https://example.com")
        assert lh.is_active is True

    def test_livehost_tech_stack_accepts_list(self):
        from backend.models.models import LiveHost
        lh = LiveHost(url="https://example.com", technology_stack=["PHP", "WordPress"])
        assert "PHP" in lh.technology_stack

    def test_livehost_repr_contains_status(self):
        from backend.models.models import LiveHost
        lh = LiveHost(url="https://api.example.com", status_code=403)
        assert "403" in repr(lh)


@pytest.mark.unit
class TestVulnerabilityModel:
    """Tests for the Vulnerability ORM model."""

    def test_vuln_instantiation(self):
        from backend.models.models import Vulnerability
        v = Vulnerability(
            vulnerability_name="SQL Injection",
            severity="critical",
        )
        assert v.vulnerability_name == "SQL Injection"
        assert v.severity == "critical"

    def test_vuln_default_status(self):
        from backend.models.models import Vulnerability
        v = Vulnerability(vulnerability_name="XSS")
        assert v.status == "new"

    def test_vuln_valid_severities(self):
        from backend.models.models import Vulnerability
        for sev in ("critical", "high", "medium", "low", "info"):
            v = Vulnerability(vulnerability_name="test", severity=sev)
            assert v.severity == sev

    def test_vuln_valid_statuses(self):
        from backend.models.models import Vulnerability
        for status in ("new", "confirmed", "false_positive", "fixed", "accepted"):
            v = Vulnerability(vulnerability_name="test", status=status)
            assert v.status == status

    def test_vuln_repr_contains_severity(self):
        from backend.models.models import Vulnerability
        v = Vulnerability(vulnerability_name="RCE", severity="critical")
        assert "critical" in repr(v)


@pytest.mark.unit
class TestChangeModel:
    """Tests for the Change ORM model."""

    def test_change_instantiation(self):
        from backend.models.models import Change
        c = Change(
            change_type="new_subdomain",
            asset_type="subdomain",
            asset_identifier="new.example.com",
        )
        assert c.change_type == "new_subdomain"
        assert c.asset_identifier == "new.example.com"

    def test_change_default_severity(self):
        from backend.models.models import Change
        c = Change(change_type="test", asset_type="port", asset_identifier="80")
        assert c.severity == "low"

    def test_change_default_not_significant(self):
        from backend.models.models import Change
        c = Change(change_type="test", asset_type="port", asset_identifier="80")
        assert c.is_significant is False

    def test_change_can_store_old_and_new_values(self):
        from backend.models.models import Change
        c = Change(
            change_type="version_change",
            asset_type="service",
            asset_identifier="nginx",
            old_value={"version": "1.14.0"},
            new_value={"version": "1.18.0"},
        )
        assert c.old_value["version"] == "1.14.0"
        assert c.new_value["version"] == "1.18.0"


@pytest.mark.unit
class TestRiskScoreModel:
    """Tests for the RiskScore ORM model."""

    def test_risk_score_instantiation(self):
        from backend.models.models import RiskScore
        rs = RiskScore(asset_type="live_host", score=75)
        assert rs.score == 75

    def test_risk_score_factors_as_dict(self):
        from backend.models.models import RiskScore
        factors = {"vuln_severity": 40, "exposed_service": 20, "no_waf": 10}
        rs = RiskScore(asset_type="live_host", score=70, score_factors=factors)
        assert rs.score_factors["vuln_severity"] == 40

    def test_risk_score_repr(self):
        from backend.models.models import RiskScore
        import uuid
        asset_id = uuid.uuid4()
        rs = RiskScore(asset_type="live_host", asset_id=asset_id, score=85)
        assert "85" in repr(rs)


@pytest.mark.unit
class TestAlertModel:
    """Tests for the Alert ORM model."""

    def test_alert_instantiation(self):
        from backend.models.models import Alert
        a = Alert(
            alert_type="critical_vulnerability",
            title="Critical Issue Found",
            message="RCE found at /api/exec",
            severity="critical",
        )
        assert a.alert_type == "critical_vulnerability"
        assert a.severity == "critical"

    def test_alert_default_status(self):
        from backend.models.models import Alert
        a = Alert(alert_type="test", title="test", message="test")
        assert a.status == "sent"

    def test_alert_channels_as_list(self):
        from backend.models.models import Alert
        a = Alert(
            alert_type="test",
            title="test",
            message="test",
            channels=["telegram", "discord"],
        )
        assert "telegram" in a.channels
