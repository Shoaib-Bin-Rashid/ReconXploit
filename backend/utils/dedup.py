"""
ReconXploit - Deduplication helpers
Phase 14: Remove duplicate findings before DB inserts.

All functions return a de-duplicated list, preserving the FIRST occurrence.
"""

from typing import List, Dict, Any


def dedup_subdomains(items: List[tuple]) -> List[tuple]:
    """
    Deduplicate (subdomain, source) tuples — keep first occurrence per subdomain.
    """
    seen: set = set()
    out  = []
    for item in items:
        key = item[0].lower().strip() if item else ""
        if key and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def dedup_live_hosts(hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate live host dicts by URL (case-insensitive, trailing-slash stripped).
    """
    seen: set = set()
    out  = []
    for h in hosts:
        url = h.get("url", "").rstrip("/").lower()
        if url and url not in seen:
            seen.add(url)
            out.append(h)
    return out


def dedup_ports(ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate port findings by (host, port_number, protocol).
    """
    seen: set = set()
    out  = []
    for p in ports:
        key = (
            p.get("host", "").lower(),
            p.get("port_number") or p.get("port"),
            p.get("protocol", "tcp"),
        )
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def dedup_vulns(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate vulnerability dicts by (template_id, matched_at).
    Falls back to (name, matched_at) if template_id missing.
    """
    seen: set = set()
    out  = []
    for v in vulns:
        key = (
            (v.get("template_id") or v.get("vulnerability_name") or "").lower(),
            (v.get("matched_at")  or v.get("url") or "").lower(),
        )
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def dedup_js_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate JS intelligence findings by (finding_type, value).
    """
    seen: set = set()
    out  = []
    for f in findings:
        key = (
            (f.get("finding_type") or f.get("type") or "").lower(),
            (f.get("value") or "").strip(),
        )
        if key[1] and key not in seen:
            seen.add(key)
            out.append(f)
    return out


def dedup_by_key(items: List[Dict[str, Any]], *keys: str) -> List[Dict[str, Any]]:
    """
    Generic deduplication: keep first occurrence per unique combination of `keys`.
    """
    seen: set = set()
    out  = []
    for item in items:
        key = tuple((item.get(k) or "") for k in keys)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out
