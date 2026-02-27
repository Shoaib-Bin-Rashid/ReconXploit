"""
ReconXploit API — Vulnerabilities router

Endpoints:
  GET  /api/v1/vulns                     List all vulnerabilities (filterable)
  GET  /api/v1/vulns/stats               Severity counts across all targets
  GET  /api/v1/vulns/{vuln_id}           Get one vulnerability
  GET  /api/v1/vulns/target/{domain}     All vulns for a target
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from datetime import datetime

from backend.models.database import get_db_context
from backend.models.models import Vulnerability, Target

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────

class VulnOut(BaseModel):
    id: str
    target_domain: Optional[str]
    vulnerability_name: Optional[str]
    severity: Optional[str]
    matched_at: Optional[str]
    template_id: Optional[str]
    cve_id: Optional[str]
    description: Optional[str]
    discovered_at: Optional[datetime]

    class Config:
        from_attributes = True


class VulnStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    by_target: dict


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@router.get("", response_model=List[VulnOut], summary="List vulnerabilities")
def list_vulns(
    domain:   Optional[str] = Query(None),
    severity: Optional[str] = Query(None, description="critical|high|medium|low|info"),
    limit:    int           = Query(100, ge=1, le=500),
    offset:   int           = Query(0, ge=0),
):
    with get_db_context() as db:
        q = db.query(Vulnerability)
        if domain:
            target = db.query(Target).filter(Target.domain == domain).first()
            if target:
                q = q.filter(Vulnerability.target_id == target.id)
            else:
                return []
        if severity:
            q = q.filter(Vulnerability.severity == severity)
        vulns = q.order_by(Vulnerability.first_seen.desc()).offset(offset).limit(limit).all()
        return [_vuln_out(v, db) for v in vulns]


@router.get("/stats", response_model=VulnStats, summary="Vulnerability severity stats")
def vuln_stats():
    with get_db_context() as db:
        vulns = db.query(Vulnerability).all()
        by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_target: dict = {}
        for v in vulns:
            sev = (v.severity or "info").lower()
            by_sev[sev] = by_sev.get(sev, 0) + 1
            t = db.query(Target).filter(Target.id == v.target_id).first()
            tname = t.domain if t else "unknown"
            by_target[tname] = by_target.get(tname, 0) + 1
        return VulnStats(
            total    = len(vulns),
            critical = by_sev["critical"],
            high     = by_sev["high"],
            medium   = by_sev["medium"],
            low      = by_sev["low"],
            info     = by_sev.get("info", 0),
            by_target = by_target,
        )


@router.get("/target/{domain}", response_model=List[VulnOut], summary="Vulns for a target")
def vulns_for_target(
    domain:   str,
    severity: Optional[str] = Query(None),
    limit:    int           = Query(200, ge=1, le=500),
):
    with get_db_context() as db:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            raise HTTPException(404, f"Target '{domain}' not found")
        q = db.query(Vulnerability).filter(Vulnerability.target_id == target.id)
        if severity:
            q = q.filter(Vulnerability.severity == severity)
        vulns = q.order_by(Vulnerability.first_seen.desc()).limit(limit).all()
        return [_vuln_out(v, db) for v in vulns]


@router.get("/{vuln_id}", response_model=VulnOut, summary="Get one vulnerability")
def get_vuln(vuln_id: str):
    with get_db_context() as db:
        v = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
        if not v:
            raise HTTPException(404, f"Vulnerability '{vuln_id}' not found")
        return _vuln_out(v, db)


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _vuln_out(v: Vulnerability, db) -> VulnOut:
    target = db.query(Target).filter(Target.id == v.target_id).first()
    return VulnOut(
        id                  = v.id,
        target_domain       = target.domain if target else None,
        vulnerability_name  = v.vulnerability_name,
        severity            = v.severity,
        matched_at          = v.matched_at,
        template_id         = getattr(v, "template_id", None),
        cve_id              = getattr(v, "cve_id", None),
        description         = getattr(v, "description", None),
        discovered_at       = getattr(v, "discovered_at", None),
    )
