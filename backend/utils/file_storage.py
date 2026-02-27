"""
ReconXploit - File Storage Utility
Saves recon results to text files alongside the database.
Every phase writes to: data/{phase}/{domain}.txt
"""

from pathlib import Path
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

# Base data directory (project root / data)
DATA_DIR = Path(__file__).parent.parent.parent / "data"


def _get_phase_file(phase: str, domain: str) -> Path:
    """Return the path for a phase's text file, creating dirs as needed."""
    phase_dir = DATA_DIR / phase
    phase_dir.mkdir(parents=True, exist_ok=True)
    return phase_dir / f"{domain}.txt"


def _write_header(f, domain: str, phase: str):
    """Write a section header with timestamp."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f.write(f"\n{'='*60}\n")
    f.write(f"  {phase.upper()} — {domain}\n")
    f.write(f"  Scan Time: {now}\n")
    f.write(f"{'='*60}\n")


# ─────────────────────────────────────────────────────────────
# PHASE 1 — SUBDOMAINS
# ─────────────────────────────────────────────────────────────

def save_subdomains(domain: str, subdomains: list[tuple]) -> Path:
    """
    Save discovered subdomains to data/subdomains/{domain}.txt

    Args:
        domain: target domain (e.g. example.com)
        subdomains: list of (subdomain, source) tuples

    Returns:
        Path to the written file
    """
    filepath = _get_phase_file("subdomains", domain)
    with open(filepath, "a", encoding="utf-8") as f:
        _write_header(f, domain, "Phase 1 — Subdomain Discovery")
        f.write(f"  Total found: {len(subdomains)}\n\n")

        # Group by source
        by_source: dict[str, list] = {}
        for subdomain, source in sorted(subdomains):
            by_source.setdefault(source, []).append(subdomain)

        for source, subs in sorted(by_source.items()):
            f.write(f"[{source}] ({len(subs)} found)\n")
            for sub in sorted(subs):
                f.write(f"  {sub}\n")
            f.write("\n")

        f.write(f"# All unique subdomains (copy-paste ready):\n")
        unique = sorted({s for s, _ in subdomains})
        for sub in unique:
            f.write(f"{sub}\n")

    logger.info(f"Subdomains saved to {filepath}")
    return filepath


# ─────────────────────────────────────────────────────────────
# PHASE 2 — LIVE HOSTS
# ─────────────────────────────────────────────────────────────

def save_live_hosts(domain: str, hosts: list[dict]) -> Path:
    """
    Save live host results to data/live_hosts/{domain}.txt

    Args:
        hosts: list of dicts with keys:
               url, status_code, title, server, ip, waf, cdn, tls
    """
    filepath = _get_phase_file("live_hosts", domain)
    with open(filepath, "a", encoding="utf-8") as f:
        _write_header(f, domain, "Phase 2 — Live Host Validation")
        f.write(f"  Total live: {len(hosts)}\n\n")

        for h in sorted(hosts, key=lambda x: x.get("url", "")):
            f.write(f"URL:     {h.get('url', '')}\n")
            f.write(f"Status:  {h.get('status_code', '')}\n")
            f.write(f"Title:   {h.get('title', '')}\n")
            f.write(f"Server:  {h.get('server', '')}\n")
            f.write(f"IP:      {h.get('ip', '')}\n")
            f.write(f"WAF:     {h.get('waf', 'None detected')}\n")
            f.write(f"CDN:     {h.get('cdn', 'None detected')}\n")
            f.write(f"TLS:     {h.get('tls', '')}\n")
            f.write("-" * 40 + "\n")

        f.write(f"\n# Live URLs only (copy-paste ready):\n")
        for h in sorted(hosts, key=lambda x: x.get("url", "")):
            f.write(f"{h.get('url', '')}\n")

    logger.info(f"Live hosts saved to {filepath}")
    return filepath


# ─────────────────────────────────────────────────────────────
# PHASE 3 — PORTS
# ─────────────────────────────────────────────────────────────

def save_ports(domain: str, port_results: list[dict]) -> Path:
    """
    Save port scan results to data/ports/{domain}.txt

    Args:
        port_results: list of dicts with keys:
                      host, port, protocol, service, version, state
    """
    filepath = _get_phase_file("ports", domain)
    with open(filepath, "a", encoding="utf-8") as f:
        _write_header(f, domain, "Phase 3 — Port & Service Mapping")
        f.write(f"  Total open ports: {len(port_results)}\n\n")

        # Group by host
        by_host: dict[str, list] = {}
        for p in port_results:
            host = p.get("host", "unknown")
            by_host.setdefault(host, []).append(p)

        for host, ports in sorted(by_host.items()):
            f.write(f"HOST: {host}\n")
            for p in sorted(ports, key=lambda x: x.get("port", 0)):
                service = p.get("service", "")
                version = p.get("version", "")
                proto = p.get("protocol", "tcp")
                f.write(f"  {p.get('port')}/{proto}  {service}  {version}\n")
            f.write("\n")

    logger.info(f"Ports saved to {filepath}")
    return filepath


# ─────────────────────────────────────────────────────────────
# PHASE 4 — VULNERABILITIES
# ─────────────────────────────────────────────────────────────

def save_vulnerabilities(domain: str, vulns: list[dict]) -> Path:
    """
    Save vulnerability results to data/vulnerabilities/{domain}.txt

    Args:
        vulns: list of dicts with keys:
               url, template_id, name, severity, description, matched
    """
    filepath = _get_phase_file("vulnerabilities", domain)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    with open(filepath, "a", encoding="utf-8") as f:
        _write_header(f, domain, "Phase 4 — Vulnerability Scan")
        f.write(f"  Total findings: {len(vulns)}\n\n")

        sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x.get("severity", "info"), 5))
        for v in sorted_vulns:
            severity = v.get("severity", "").upper()
            f.write(f"[{severity}] {v.get('name', '')}\n")
            f.write(f"  Template:    {v.get('template_id', '')}\n")
            f.write(f"  URL:         {v.get('url', '')}\n")
            f.write(f"  Matched:     {v.get('matched', '')}\n")
            f.write(f"  Description: {v.get('description', '')}\n")
            f.write("-" * 40 + "\n")

    logger.info(f"Vulnerabilities saved to {filepath}")
    return filepath


# ─────────────────────────────────────────────────────────────
# PHASE 5 — JS FINDINGS
# ─────────────────────────────────────────────────────────────

def save_js_findings(domain: str, findings: list[dict]) -> Path:
    """
    Save JS intelligence results to data/js_findings/{domain}.txt

    Args:
        findings: list of dicts with keys:
                  finding_type, finding_value, source_url, js_file_url,
                  risk_level, secret_type, context
    """
    filepath = _get_phase_file("js_findings", domain)
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    with open(filepath, "a", encoding="utf-8") as f:
        _write_header(f, domain, "Phase 5 — JavaScript Intelligence")

        secrets   = [x for x in findings if x.get("secret_type")]
        endpoints = [x for x in findings if not x.get("secret_type")]
        f.write(f"  Total findings: {len(findings)}"
                f"  ({len(secrets)} secrets, {len(endpoints)} endpoints)\n\n")

        if secrets:
            f.write("─── SECRETS ───────────────────────────────────\n")
            for item in sorted(secrets, key=lambda x: risk_order.get(x.get("risk_level", "low"), 4)):
                risk = item.get("risk_level", "").upper()
                f.write(f"[{risk}] {item.get('finding_type', '').upper()}\n")
                f.write(f"  Value:   {item.get('finding_value', '')}\n")
                f.write(f"  Source:  {item.get('source_url', '')}\n")
                if item.get("context"):
                    f.write(f"  Context: {item.get('context', '')}\n")
                f.write("\n")

        if endpoints:
            f.write("─── ENDPOINTS ─────────────────────────────────\n")
            by_type: dict[str, list] = {}
            for item in endpoints:
                t = item.get("finding_type", "unknown")
                by_type.setdefault(t, []).append(item)
            for ftype, items in sorted(by_type.items()):
                f.write(f"[{ftype.upper()}] ({len(items)} found)\n")
                for item in items:
                    f.write(f"  {item.get('finding_value', '')}\n")
                    f.write(f"    ← {item.get('source_url', '')}\n")
                f.write("\n")

    logger.info(f"JS findings saved to {filepath}")
    return filepath


# ─────────────────────────────────────────────────────────────
# PHASE 6 — CHANGES
# ─────────────────────────────────────────────────────────────

def save_changes(domain: str, changes: list[dict]) -> Path:
    """
    Save change detection results to data/changes/{domain}.txt

    Args:
        changes: list of dicts with keys:
                 change_type, asset_type, asset_id, old_value, new_value,
                 severity, is_significant, detected_at
    """
    filepath = _get_phase_file("changes", domain)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    with open(filepath, "a", encoding="utf-8") as f:
        _write_header(f, domain, "Phase 6 — Change Detection")
        significant = [c for c in changes if c.get("is_significant")]
        f.write(f"  Total changes:  {len(changes)}\n")
        f.write(f"  Significant:    {len(significant)}\n\n")

        if not changes:
            f.write("  No changes detected (or first scan baseline).\n")
        else:
            if significant:
                f.write("⚠  SIGNIFICANT — review immediately:\n")
                f.write("─" * 50 + "\n")
                for c in sorted(significant, key=lambda x: sev_order.get(x.get("severity", "low"), 4)):
                    sev = c.get("severity", "").upper()
                    f.write(f"  [{sev}] {c.get('change_type', '')}\n")
                    f.write(f"    Asset:  {c.get('asset_id', '')}\n")
                    if c.get("old_value"):
                        f.write(f"    Before: {json.dumps(c['old_value'])}\n")
                    if c.get("new_value"):
                        f.write(f"    After:  {json.dumps(c['new_value'])}\n")
                    f.write("\n")

            f.write("All changes:\n")
            f.write("─" * 50 + "\n")
            for c in changes:
                sev = c.get("severity", "")
                sig = " ★" if c.get("is_significant") else ""
                f.write(
                    f"  [{sev.upper()}]{sig} {c.get('change_type', '')} "
                    f"→ {c.get('asset_id', '')}\n"
                )

    logger.info(f"Changes saved to {filepath}")
    return filepath


# ─────────────────────────────────────────────────────────────
# PHASE 7 — RISK SCORES
# ─────────────────────────────────────────────────────────────

def save_risk_scores(domain: str, overall: int, breakdown: dict, scores: list[dict]) -> Path:
    """
    Save risk score results to data/risk_scores/{domain}.txt

    Args:
        overall:   0-100 overall score
        breakdown: dict of category -> score
        scores:    list of per-asset score dicts
    """
    filepath = _get_phase_file("risk_scores", domain)

    label_map = {
        range(80, 101): "🔴 CRITICAL",
        range(60, 80):  "🟠 HIGH",
        range(40, 60):  "🟡 MEDIUM",
        range(20, 40):  "🟢 LOW",
        range(0, 20):   "⚪ INFO",
    }
    label = next((v for r, v in label_map.items() if overall in r), "⚪ INFO")

    with open(filepath, "a", encoding="utf-8") as f:
        _write_header(f, domain, "Phase 7 — Risk Score")
        f.write(f"  Overall Score: {overall}/100  {label}\n\n")

        f.write("Score Breakdown:\n")
        f.write("─" * 40 + "\n")
        for category, score in sorted(breakdown.items(), key=lambda x: -x[1]):
            bar = "█" * (score // 5) + "░" * ((20 - score // 5) if score < 100 else 0)
            f.write(f"  {category:<25} {score:>3}  {bar}\n")
        f.write("\n")

        host_scores = [s for s in scores if s.get("asset_type") == "live_host"]
        if host_scores:
            f.write("Per-Host Scores:\n")
            f.write("─" * 40 + "\n")
            for s in sorted(host_scores, key=lambda x: -x.get("score", 0)):
                f.write(f"  {s.get('score', 0):>3}/100  {s.get('asset_id', '')}\n")

    logger.info(f"Risk scores saved to {filepath}")
    return filepath
