-- ReconXploit Database Schema
-- PostgreSQL 13+

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ===========================================
-- CORE TABLES
-- ===========================================

-- Targets table: Organizations/domains being monitored
CREATE TABLE targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain VARCHAR(255) NOT NULL UNIQUE,
    organization VARCHAR(255),
    description TEXT,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'paused', 'archived')),
    scan_schedule VARCHAR(50), -- cron expression
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scans table: Individual reconnaissance scans
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) DEFAULT 'full' CHECK (scan_type IN ('full', 'quick', 'deep', 'custom')),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    start_time TIMESTAMP,
    end_time TIMESTAMP,
    duration_seconds INTEGER,
    error_message TEXT,
    stats JSONB, -- {subdomains_found: 100, live_hosts: 50, vulns: 10}
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================================
-- ASSET DISCOVERY TABLES
-- ===========================================

-- Subdomains discovered
CREATE TABLE subdomains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    subdomain VARCHAR(255) NOT NULL,
    source VARCHAR(50), -- subfinder, amass, etc.
    ip_address INET,
    cname VARCHAR(255),
    is_active BOOLEAN DEFAULT true,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target_id, subdomain)
);

-- Live hosts (validated HTTP/HTTPS endpoints)
CREATE TABLE live_hosts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    subdomain_id UUID REFERENCES subdomains(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    content_length INTEGER,
    response_time_ms INTEGER,
    server_header VARCHAR(255),
    technology_stack JSONB, -- ["PHP", "MySQL", "WordPress"]
    tls_info JSONB,
    waf_detected VARCHAR(100),
    cdn_detected VARCHAR(100),
    screenshot_path TEXT,
    fingerprint_hash VARCHAR(64), -- SHA256 of response for change detection
    is_active BOOLEAN DEFAULT true,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, url)
);

-- ===========================================
-- SERVICE ENUMERATION TABLES
-- ===========================================

-- Open ports and services
CREATE TABLE ports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    live_host_id UUID REFERENCES live_hosts(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) DEFAULT 'tcp',
    state VARCHAR(20), -- open, closed, filtered
    service_name VARCHAR(100),
    service_version VARCHAR(255),
    banner TEXT,
    is_sensitive BOOLEAN DEFAULT false, -- SSH, DB, Redis, etc.
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, ip_address, port, protocol)
);

-- ===========================================
-- VULNERABILITY TABLES
-- ===========================================

-- Vulnerabilities found
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    live_host_id UUID REFERENCES live_hosts(id) ON DELETE CASCADE,
    vulnerability_name VARCHAR(255) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_score DECIMAL(3,1),
    cve_id VARCHAR(50),
    description TEXT,
    template_id VARCHAR(100), -- nuclei template ID
    matched_at TEXT, -- URL or endpoint where found
    poc_url TEXT,
    remediation TEXT,
    status VARCHAR(20) DEFAULT 'new' CHECK (status IN ('new', 'confirmed', 'false_positive', 'fixed', 'accepted')),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================================
-- INTELLIGENCE TABLES
-- ===========================================

-- JavaScript intelligence (endpoints, secrets, APIs)
CREATE TABLE js_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    live_host_id UUID REFERENCES live_hosts(id) ON DELETE CASCADE,
    source_url TEXT NOT NULL, -- Page URL
    js_file_url TEXT, -- JS file URL
    finding_type VARCHAR(50), -- endpoint, secret, api_key, internal_url
    finding_value TEXT NOT NULL,
    secret_type VARCHAR(50), -- aws_key, jwt, password, api_key
    risk_level VARCHAR(20) CHECK (risk_level IN ('critical', 'high', 'medium', 'low')),
    context TEXT, -- Surrounding code
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Parameters discovered
CREATE TABLE parameters (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    parameter_name VARCHAR(255) NOT NULL,
    parameter_value TEXT,
    source VARCHAR(50), -- arjun, paramspider, wayback
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(scan_id, url, parameter_name)
);

-- Historical URLs (wayback, archives)
CREATE TABLE historical_urls (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source VARCHAR(50), -- wayback, gau
    timestamp TIMESTAMP,
    status_code INTEGER,
    is_accessible BOOLEAN,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(target_id, url)
);

-- ===========================================
-- CHANGE DETECTION TABLES
-- ===========================================

-- Snapshots for baseline comparison
CREATE TABLE snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    snapshot_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    snapshot_hash VARCHAR(64), -- Overall state hash
    asset_counts JSONB, -- {subdomains: 100, live_hosts: 50, ports: 200}
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Changes detected between scans
CREATE TABLE changes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    change_type VARCHAR(50) NOT NULL, -- new_subdomain, removed_subdomain, new_port, version_change
    asset_type VARCHAR(50) NOT NULL, -- subdomain, port, vulnerability, service
    asset_identifier TEXT NOT NULL,
    old_value JSONB,
    new_value JSONB,
    severity VARCHAR(20) DEFAULT 'low' CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    is_significant BOOLEAN DEFAULT false,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ===========================================
-- RISK SCORING TABLES
-- ===========================================

-- Risk scores for assets
CREATE TABLE risk_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_type VARCHAR(50) NOT NULL, -- subdomain, live_host, vulnerability
    asset_id UUID NOT NULL,
    score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
    score_factors JSONB, -- {vuln_severity: 40, exposed_service: 20, no_waf: 10}
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(asset_type, asset_id)
);

-- ===========================================
-- NOTIFICATION TABLES
-- ===========================================

-- Alerts sent
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
    alert_type VARCHAR(50) NOT NULL, -- critical_vuln, new_subdomain, secrets_found
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    channels JSONB, -- ["telegram", "discord"]
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'sent' CHECK (status IN ('pending', 'sent', 'failed'))
);

-- ===========================================
-- INDEXES FOR PERFORMANCE
-- ===========================================

-- Targets
CREATE INDEX idx_targets_domain ON targets(domain);
CREATE INDEX idx_targets_status ON targets(status);

-- Scans
CREATE INDEX idx_scans_target ON scans(target_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- Subdomains
CREATE INDEX idx_subdomains_target ON subdomains(target_id);
CREATE INDEX idx_subdomains_scan ON subdomains(scan_id);
CREATE INDEX idx_subdomains_name ON subdomains(subdomain);
CREATE INDEX idx_subdomains_active ON subdomains(is_active);

-- Live Hosts
CREATE INDEX idx_livehosts_scan ON live_hosts(scan_id);
CREATE INDEX idx_livehosts_subdomain ON live_hosts(subdomain_id);
CREATE INDEX idx_livehosts_url ON live_hosts(url);
CREATE INDEX idx_livehosts_active ON live_hosts(is_active);

-- Ports
CREATE INDEX idx_ports_scan ON ports(scan_id);
CREATE INDEX idx_ports_ip ON ports(ip_address);
CREATE INDEX idx_ports_number ON ports(port);
CREATE INDEX idx_ports_sensitive ON ports(is_sensitive);

-- Vulnerabilities
CREATE INDEX idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_host ON vulnerabilities(live_host_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_status ON vulnerabilities(status);
CREATE INDEX idx_vulns_cve ON vulnerabilities(cve_id);

-- JS Intelligence
CREATE INDEX idx_js_scan ON js_intelligence(scan_id);
CREATE INDEX idx_js_type ON js_intelligence(finding_type);
CREATE INDEX idx_js_risk ON js_intelligence(risk_level);

-- Changes
CREATE INDEX idx_changes_scan ON changes(scan_id);
CREATE INDEX idx_changes_target ON changes(target_id);
CREATE INDEX idx_changes_type ON changes(change_type);
CREATE INDEX idx_changes_severity ON changes(severity);
CREATE INDEX idx_changes_significant ON changes(is_significant);
CREATE INDEX idx_changes_detected ON changes(detected_at DESC);

-- Risk Scores
CREATE INDEX idx_risk_target ON risk_scores(target_id);
CREATE INDEX idx_risk_type ON risk_scores(asset_type);
CREATE INDEX idx_risk_score ON risk_scores(score DESC);

-- Alerts
CREATE INDEX idx_alerts_target ON alerts(target_id);
CREATE INDEX idx_alerts_type ON alerts(alert_type);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_sent ON alerts(sent_at DESC);

-- Full-text search indexes
CREATE INDEX idx_subdomains_search ON subdomains USING gin(subdomain gin_trgm_ops);
CREATE INDEX idx_vulns_search ON vulnerabilities USING gin(vulnerability_name gin_trgm_ops);

-- ===========================================
-- VIEWS FOR COMMON QUERIES
-- ===========================================

-- Latest scan per target
CREATE VIEW latest_scans AS
SELECT DISTINCT ON (target_id) *
FROM scans
ORDER BY target_id, created_at DESC;

-- Active vulnerabilities summary
CREATE VIEW active_vulnerabilities AS
SELECT 
    t.domain,
    v.severity,
    COUNT(*) as count
FROM vulnerabilities v
JOIN live_hosts lh ON v.live_host_id = lh.id
JOIN subdomains s ON lh.subdomain_id = s.id
JOIN targets t ON s.target_id = t.id
WHERE v.status = 'new'
GROUP BY t.domain, v.severity;

-- Asset inventory per target
CREATE VIEW asset_inventory AS
SELECT 
    t.id as target_id,
    t.domain,
    COUNT(DISTINCT s.id) as total_subdomains,
    COUNT(DISTINCT lh.id) as total_live_hosts,
    COUNT(DISTINCT p.id) as total_open_ports,
    COUNT(DISTINCT v.id) as total_vulnerabilities
FROM targets t
LEFT JOIN subdomains s ON t.id = s.target_id AND s.is_active = true
LEFT JOIN live_hosts lh ON s.id = lh.subdomain_id AND lh.is_active = true
LEFT JOIN ports p ON lh.id = p.live_host_id
LEFT JOIN vulnerabilities v ON lh.id = v.live_host_id AND v.status = 'new'
GROUP BY t.id, t.domain;

-- ===========================================
-- FUNCTIONS
-- ===========================================

-- Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for targets table
CREATE TRIGGER update_targets_updated_at BEFORE UPDATE ON targets
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ===========================================
-- SAMPLE DATA (for testing)
-- ===========================================

-- Uncomment to insert sample data
-- INSERT INTO targets (domain, organization) VALUES ('example.com', 'Example Corp');
