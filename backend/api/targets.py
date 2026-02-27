"""
ReconXploit API — Targets router
CRUD operations for scan targets.

Endpoints:
  GET    /api/v1/targets               List all targets
  POST   /api/v1/targets               Add a new target
  GET    /api/v1/targets/{domain}      Get target details
  PATCH  /api/v1/targets/{domain}      Update target (status, notes)
  DELETE /api/v1/targets/{domain}      Delete target + all data
  GET    /api/v1/targets/{domain}/summary   Full summary of latest scan
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.models.database import get_db_context
from backend.models.models import Target, Scan, Subdomain, LiveHost, Vulnerability

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────

class TargetCreate(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255, description="Target domain e.g. example.com")
    program: Optional[str] = Field(None, max_length=255)
    scan_mode: Optional[str] = Field("full", description="full|passive|quick|deep")
    notes: Optional[str] = None
    interval_hours: Optional[int] = Field(24, ge=1, le=8760)


class TargetUpdate(BaseModel):
    status: Optional[str] = Field(None, description="active|paused|archived")
    notes: Optional[str] = None
    scan_mode: Optional[str] = None
    interval_hours: Optional[int] = Field(None, ge=1, le=8760)


class TargetOut(BaseModel):
    id: str
    domain: str
    program: Optional[str]
    status: str
    scan_mode: Optional[str]
    notes: Optional[str]
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class TargetSummary(BaseModel):
    domain: str
    status: str
    total_scans: int
    last_scan: Optional[datetime]
    subdomain_count: int
    live_host_count: int
    vuln_count: int
    critical_vulns: int
    high_vulns: int
    last_risk_score: int


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@router.get("", response_model=List[TargetOut], summary="List all targets")
def list_targets(
    status: Optional[str] = Query(None, description="Filter by status: active|paused|archived"),
    limit:  int           = Query(100, ge=1, le=500),
    offset: int           = Query(0, ge=0),
):
    """Return all registered targets, optionally filtered by status."""
    with get_db_context() as db:
        q = db.query(Target)
        if status:
            q = q.filter(Target.status == status)
        targets = q.order_by(Target.created_at.desc()).offset(offset).limit(limit).all()
        return [_target_out(t) for t in targets]


@router.post("", response_model=TargetOut, status_code=201, summary="Add a target")
def create_target(body: TargetCreate):
    """Register a new target for scanning."""
    with get_db_context() as db:
        existing = db.query(Target).filter(Target.domain == body.domain).first()
        if existing:
            raise HTTPException(status_code=409, detail=f"Target '{body.domain}' already exists")

        target = Target(
            domain    = body.domain.strip().lower(),
            program   = body.program,
            status    = "active",
            notes     = body.notes,
        )
        db.add(target)
        db.commit()
        db.refresh(target)
        logger.info(f"Target created: {body.domain}")
        return _target_out(target)


@router.get("/{domain}", response_model=TargetOut, summary="Get a target")
def get_target(domain: str):
    """Get details for a specific target."""
    with get_db_context() as db:
        target = _get_or_404(db, domain)
        return _target_out(target)


@router.patch("/{domain}", response_model=TargetOut, summary="Update a target")
def update_target(domain: str, body: TargetUpdate):
    """Update status, notes, or scan mode for a target."""
    with get_db_context() as db:
        target = _get_or_404(db, domain)
        if body.status is not None:
            valid = {"active", "paused", "archived"}
            if body.status not in valid:
                raise HTTPException(400, f"status must be one of {valid}")
            target.status = body.status
        if body.notes is not None:
            target.notes = body.notes
        db.commit()
        db.refresh(target)
        return _target_out(target)


@router.delete("/{domain}", status_code=204, summary="Delete a target")
def delete_target(domain: str):
    """Delete a target and all associated scan data."""
    with get_db_context() as db:
        target = _get_or_404(db, domain)
        db.delete(target)
        db.commit()
        logger.info(f"Target deleted: {domain}")


@router.get("/{domain}/summary", response_model=TargetSummary, summary="Target scan summary")
def target_summary(domain: str):
    """Return a high-level summary of the target's latest recon results."""
    with get_db_context() as db:
        target = _get_or_404(db, domain)

        scans = db.query(Scan).filter(Scan.target_id == target.id)\
                  .order_by(Scan.started_at.desc()).all()
        last_scan = scans[0].started_at if scans else None

        subdomain_count = db.query(Subdomain)\
            .filter(Subdomain.target_id == target.id).count()
        live_host_count = db.query(LiveHost)\
            .filter(LiveHost.target_id == target.id).count()

        vulns = db.query(Vulnerability)\
            .filter(Vulnerability.target_id == target.id).all()
        critical = sum(1 for v in vulns if v.severity == "critical")
        high     = sum(1 for v in vulns if v.severity == "high")

        # Latest risk score
        try:
            from backend.models.models import RiskScore
            rs = db.query(RiskScore)\
                   .filter(RiskScore.target_id == target.id, RiskScore.asset_type == "scan")\
                   .order_by(RiskScore.calculated_at.desc()).first()
            last_score = rs.score if rs else 0
        except Exception:
            last_score = 0

        return TargetSummary(
            domain          = target.domain,
            status          = target.status,
            total_scans     = len(scans),
            last_scan       = last_scan,
            subdomain_count = subdomain_count,
            live_host_count = live_host_count,
            vuln_count      = len(vulns),
            critical_vulns  = critical,
            high_vulns      = high,
            last_risk_score = last_score,
        )


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _get_or_404(db, domain: str) -> Target:
    target = db.query(Target).filter(Target.domain == domain).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{domain}' not found")
    return target


def _target_out(t: Target) -> TargetOut:
    return TargetOut(
        id         = t.id,
        domain     = t.domain,
        program    = getattr(t, "program", None),
        status     = t.status,
        scan_mode  = getattr(t, "scan_mode", None),
        notes      = getattr(t, "notes", None),
        created_at = getattr(t, "created_at", None),
    )
