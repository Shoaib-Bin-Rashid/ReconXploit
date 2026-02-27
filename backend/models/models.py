"""
ReconXploit - Database Models (SQLAlchemy ORM)
Mirrors schema.sql with Python ORM models
"""

import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column, String, Integer, Boolean, Text, DateTime,
    ForeignKey, Numeric, Index, CheckConstraint, JSON
)
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB
from sqlalchemy.types import TypeDecorator
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()


class JSONBType(TypeDecorator):
    """
    Uses PostgreSQL JSONB when available, falls back to JSON (SQLite/testing).
    This keeps production performance while allowing SQLite-based unit tests.
    """
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_JSONB())
        return dialect.type_descriptor(JSON())


def generate_uuid():
    return str(uuid.uuid4())


# ─────────────────────────────────────────────
# CORE TABLES
# ─────────────────────────────────────────────

class Target(Base):
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain = Column(String(255), nullable=False, unique=True)
    organization = Column(String(255))
    description = Column(Text)
    status = Column(String(20), default="active")
    scan_schedule = Column(String(50))  # cron expression
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __init__(self, **kwargs):
        kwargs.setdefault("status", "active")
        super().__init__(**kwargs)

    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    subdomains = relationship("Subdomain", back_populates="target", cascade="all, delete-orphan")
    changes = relationship("Change", back_populates="target", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="target", cascade="all, delete-orphan")
    risk_scores = relationship("RiskScore", back_populates="target", cascade="all, delete-orphan")
    snapshots = relationship("Snapshot", back_populates="target", cascade="all, delete-orphan")
    screenshots = relationship("Screenshot", back_populates="target", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("status IN ('active', 'paused', 'archived')", name="chk_target_status"),
    )

    def __repr__(self):
        return f"<Target {self.domain}>"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    scan_type = Column(String(50), default="full")
    status = Column(String(20), default="pending")

    def __init__(self, **kwargs):
        kwargs.setdefault("status", "pending")
        kwargs.setdefault("scan_type", "full")
        super().__init__(**kwargs)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    duration_seconds = Column(Integer)
    error_message = Column(Text)
    stats = Column(JSONBType)  # {subdomains_found, live_hosts, vulns}
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    target = relationship("Target", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    live_hosts = relationship("LiveHost", back_populates="scan", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    js_intelligence = relationship("JsIntelligence", back_populates="scan", cascade="all, delete-orphan")
    changes = relationship("Change", back_populates="scan", cascade="all, delete-orphan")
    snapshots = relationship("Snapshot", back_populates="scan", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="scan")
    screenshots = relationship("Screenshot", back_populates="scan")

    __table_args__ = (
        CheckConstraint(
            "scan_type IN ('full', 'quick', 'deep', 'custom')",
            name="chk_scan_type"
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', 'cancelled')",
            name="chk_scan_status"
        ),
        Index("idx_scans_target", "target_id"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_created", "created_at"),
    )

    def __repr__(self):
        return f"<Scan {self.id} [{self.status}]>"


# ─────────────────────────────────────────────
# ASSET DISCOVERY
# ─────────────────────────────────────────────

class Subdomain(Base):
    __tablename__ = "subdomains"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    subdomain = Column(String(255), nullable=False)
    source = Column(String(50))  # subfinder, amass, assetfinder, etc.
    ip_address = Column(String(50))
    cname = Column(String(255))
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="subdomains")
    target = relationship("Target", back_populates="subdomains")
    live_hosts = relationship("LiveHost", back_populates="subdomain", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        kwargs.setdefault("is_active", True)
        super().__init__(**kwargs)

    __table_args__ = (
        Index("idx_subdomains_target", "target_id"),
        Index("idx_subdomains_scan", "scan_id"),
        Index("idx_subdomains_name", "subdomain"),
        Index("idx_subdomains_active", "is_active"),
    )

    def __repr__(self):
        return f"<Subdomain {self.subdomain}>"


class LiveHost(Base):
    __tablename__ = "live_hosts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    subdomain_id = Column(String(36), ForeignKey("subdomains.id", ondelete="CASCADE"))
    url = Column(Text, nullable=False)
    status_code = Column(Integer)
    title = Column(Text)
    content_length = Column(Integer)
    response_time_ms = Column(Integer)
    server_header = Column(String(255))
    technology_stack = Column(JSONBType)   # ["PHP", "MySQL", "WordPress"]
    tls_info = Column(JSONBType)
    waf_detected = Column(String(100))
    cdn_detected = Column(String(100))
    screenshot_path = Column(Text)
    fingerprint_hash = Column(String(64))  # SHA256 of response
    is_active = Column(Boolean, default=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="live_hosts")
    subdomain = relationship("Subdomain", back_populates="live_hosts")
    ports = relationship("Port", back_populates="live_host", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="live_host", cascade="all, delete-orphan")
    js_intelligence = relationship("JsIntelligence", back_populates="live_host", cascade="all, delete-orphan")

    def __init__(self, **kwargs):
        kwargs.setdefault("is_active", True)
        super().__init__(**kwargs)

    __table_args__ = (
        Index("idx_livehosts_scan", "scan_id"),
        Index("idx_livehosts_subdomain", "subdomain_id"),
        Index("idx_livehosts_active", "is_active"),
    )

    def __repr__(self):
        return f"<LiveHost {self.url} [{self.status_code}]>"


# ─────────────────────────────────────────────
# SERVICE ENUMERATION
# ─────────────────────────────────────────────

class Port(Base):
    __tablename__ = "ports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    live_host_id = Column(String(36), ForeignKey("live_hosts.id", ondelete="CASCADE"))
    ip_address = Column(String(50), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    state = Column(String(20))        # open, closed, filtered
    service_name = Column(String(100))
    service_version = Column(String(255))
    banner = Column(Text)
    is_sensitive = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="ports")
    live_host = relationship("LiveHost", back_populates="ports")

    # Sensitive ports: SSH, FTP, DB, Redis, etc.
    SENSITIVE_PORTS = {22, 21, 23, 3306, 5432, 1433, 1521, 6379, 27017, 9200, 5601, 8500}

    __table_args__ = (
        Index("idx_ports_scan", "scan_id"),
        Index("idx_ports_ip", "ip_address"),
        Index("idx_ports_number", "port"),
        Index("idx_ports_sensitive", "is_sensitive"),
    )

    def __repr__(self):
        return f"<Port {self.ip_address}:{self.port}/{self.protocol}>"


# ─────────────────────────────────────────────
# VULNERABILITY ASSESSMENT
# ─────────────────────────────────────────────

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    live_host_id = Column(String(36), ForeignKey("live_hosts.id", ondelete="CASCADE"))
    vulnerability_name = Column(String(255), nullable=False)
    severity = Column(String(20))
    cvss_score = Column(Numeric(3, 1))
    cve_id = Column(String(50))
    description = Column(Text)
    template_id = Column(String(100))  # nuclei template ID
    matched_at = Column(Text)          # URL where found
    poc_url = Column(Text)
    remediation = Column(Text)
    status = Column(String(20), default="new")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    live_host = relationship("LiveHost", back_populates="vulnerabilities")

    def __init__(self, **kwargs):
        kwargs.setdefault("status", "new")
        super().__init__(**kwargs)

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="chk_vuln_severity"
        ),
        CheckConstraint(
            "status IN ('new', 'confirmed', 'false_positive', 'fixed', 'accepted')",
            name="chk_vuln_status"
        ),
        Index("idx_vulns_scan", "scan_id"),
        Index("idx_vulns_severity", "severity"),
        Index("idx_vulns_status", "status"),
        Index("idx_vulns_cve", "cve_id"),
    )

    def __repr__(self):
        return f"<Vulnerability {self.vulnerability_name} [{self.severity}]>"


# ─────────────────────────────────────────────
# INTELLIGENCE GATHERING
# ─────────────────────────────────────────────

class JsIntelligence(Base):
    __tablename__ = "js_intelligence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    live_host_id = Column(String(36), ForeignKey("live_hosts.id", ondelete="CASCADE"))
    source_url = Column(Text, nullable=False)
    js_file_url = Column(Text)
    finding_type = Column(String(50))   # endpoint, secret, api_key, internal_url
    finding_value = Column(Text, nullable=False)
    secret_type = Column(String(50))    # aws_key, jwt, password, api_key
    risk_level = Column(String(20))
    context = Column(Text)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="js_intelligence")
    live_host = relationship("LiveHost", back_populates="js_intelligence")

    __table_args__ = (
        CheckConstraint(
            "risk_level IN ('critical', 'high', 'medium', 'low')",
            name="chk_js_risk"
        ),
        Index("idx_js_scan", "scan_id"),
        Index("idx_js_type", "finding_type"),
        Index("idx_js_risk", "risk_level"),
    )

    def __repr__(self):
        return f"<JsIntelligence {self.finding_type}: {self.finding_value[:50]}>"


class Parameter(Base):
    __tablename__ = "parameters"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    parameter_name = Column(String(255), nullable=False)
    parameter_value = Column(Text)
    source = Column(String(50))  # arjun, paramspider, wayback
    first_seen = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Parameter {self.parameter_name} @ {self.url}>"


class HistoricalUrl(Base):
    __tablename__ = "historical_urls"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    url = Column(Text, nullable=False)
    source = Column(String(50))  # wayback, gau
    timestamp = Column(DateTime)
    status_code = Column(Integer)
    is_accessible = Column(Boolean)
    first_seen = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<HistoricalUrl {self.url}>"


# ─────────────────────────────────────────────
# CHANGE DETECTION
# ─────────────────────────────────────────────

class Snapshot(Base):
    __tablename__ = "snapshots"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    snapshot_date = Column(DateTime, default=datetime.utcnow)
    snapshot_hash = Column(String(64))
    asset_counts = Column(JSONBType)  # {subdomains, live_hosts, ports, vulns}
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="snapshots")
    target = relationship("Target", back_populates="snapshots")

    def __repr__(self):
        return f"<Snapshot {self.target_id} @ {self.snapshot_date}>"


class Change(Base):
    __tablename__ = "changes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    change_type = Column(String(50), nullable=False)    # new_subdomain, removed_port, version_change
    asset_type = Column(String(50), nullable=False)     # subdomain, port, vulnerability
    asset_identifier = Column(Text, nullable=False)
    old_value = Column(JSONBType)
    new_value = Column(JSONBType)
    severity = Column(String(20), default="low")
    is_significant = Column(Boolean, default=False)
    detected_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="changes")
    target = relationship("Target", back_populates="changes")

    def __init__(self, **kwargs):
        kwargs.setdefault("severity", "low")
        kwargs.setdefault("is_significant", False)
        super().__init__(**kwargs)

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="chk_change_severity"
        ),
        Index("idx_changes_scan", "scan_id"),
        Index("idx_changes_target", "target_id"),
        Index("idx_changes_type", "change_type"),
        Index("idx_changes_severity", "severity"),
        Index("idx_changes_significant", "is_significant"),
        Index("idx_changes_detected", "detected_at"),
    )

    def __repr__(self):
        return f"<Change {self.change_type}: {self.asset_identifier}>"


# ─────────────────────────────────────────────
# RISK SCORING
# ─────────────────────────────────────────────

class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    asset_type = Column(String(50), nullable=False)   # subdomain, live_host, vulnerability
    asset_id = Column(String(36), nullable=False)
    score = Column(Integer, nullable=False)           # 0-100
    score_factors = Column(JSONBType)
    calculated_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    target = relationship("Target", back_populates="risk_scores")

    __table_args__ = (
        CheckConstraint("score >= 0 AND score <= 100", name="chk_risk_score_range"),
        Index("idx_risk_target", "target_id"),
        Index("idx_risk_type", "asset_type"),
        Index("idx_risk_score", "score"),
    )

    def __repr__(self):
        return f"<RiskScore {self.asset_type}/{self.asset_id}: {self.score}>"


# ─────────────────────────────────────────────
# NOTIFICATIONS
# ─────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    alert_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20))
    channels = Column(JSONBType)   # ["telegram", "discord"]
    sent_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), default="sent")

    # Relationships
    target = relationship("Target", back_populates="alerts")
    scan = relationship("Scan", back_populates="alerts")

    def __init__(self, **kwargs):
        kwargs.setdefault("status", "sent")
        super().__init__(**kwargs)

    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="chk_alert_severity"
        ),
        CheckConstraint(
            "status IN ('pending', 'sent', 'failed')",
            name="chk_alert_status"
        ),
        Index("idx_alerts_target", "target_id"),
        Index("idx_alerts_type", "alert_type"),
        Index("idx_alerts_severity", "severity"),
        Index("idx_alerts_sent", "sent_at"),
    )

    def __repr__(self):
        return f"<Alert {self.alert_type} [{self.severity}]>"


# ─────────────────────────────────────────────────────────────
# Phase 8 — Screenshots
# ─────────────────────────────────────────────────────────────

class Screenshot(Base):
    __tablename__ = "screenshots"

    id               = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id        = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    scan_id          = Column(String(36), ForeignKey("scans.id",   ondelete="SET NULL"), nullable=True)
    url              = Column(String(2048), nullable=False)
    file_path        = Column(String(1024))
    page_title       = Column(String(512))
    status_code      = Column(Integer)
    file_size_bytes  = Column(Integer, default=0)
    tool_used        = Column(String(50))        # gowitness / chrome-headless / html-preview
    captured_at      = Column(DateTime, default=datetime.utcnow)

    target = relationship("Target", back_populates="screenshots")
    scan   = relationship("Scan",   back_populates="screenshots")

    def __init__(self, **kwargs):
        kwargs.setdefault("file_size_bytes", 0)
        super().__init__(**kwargs)

    __table_args__ = (
        Index("idx_screenshots_target",  "target_id"),
        Index("idx_screenshots_scan",    "scan_id"),
        Index("idx_screenshots_url",     "url"),
        Index("idx_screenshots_captured","captured_at"),
    )

    def __repr__(self):
        return f"<Screenshot {self.url} [{self.tool_used}]>"
