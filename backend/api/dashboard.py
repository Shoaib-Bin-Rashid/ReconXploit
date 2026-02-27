"""
ReconXploit API — Dashboard router
Aggregated data for the frontend overview page.

Endpoints:
  GET  /api/v1/dashboard/overview        High-level counts + risk summary
  GET  /api/v1/dashboard/recent-changes  Recent significant changes
  GET  /api/v1/dashboard/top-risks       Top-risk targets
  GET  /api/v1/dashboard/activity        Recent scan activity (last 7 days)
"""

import logging
from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, Query
from pydantic import BaseModel

from backend.models.database import get_db_context
from backend.models.models import (
    Target, Scan, Subdomain, LiveHost, Vulnerability, Change, RiskScore
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────

class DashboardOverview(BaseModel):
    total_targets: int
    active_targets: int
    total_scans: int
    total_subdomains: int
    total_live_hosts: int
    total_vulns: int
    critical_vulns: int
    high_vulns: int
    scans_today: int
    avg_risk_score: float


class RecentChange(BaseModel):
    domain: str
    change_type: str
    severity: str
    asset_id: str
    is_significant: bool
    detected_at: Optional[datetime]


class TopRiskTarget(BaseModel):
    domain: str
    risk_score: int
    risk_label: str
    vuln_count: int
    critical_vulns: int


class ActivityPoint(BaseModel):
    date: str
    scans: int
    vulns_found: int
    new_subdomains: int


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@router.get("/overview", response_model=DashboardOverview, summary="Dashboard overview")
def overview():
    with get_db_context() as db:
        total_targets  = db.query(Target).count()
        active_targets = db.query(Target).filter(Target.status == "active").count()
        total_scans    = db.query(Scan).count()
        total_subs     = db.query(Subdomain).count()
        total_hosts    = db.query(LiveHost).count()

        all_vulns    = db.query(Vulnerability).all()
        total_vulns  = len(all_vulns)
        critical_v   = sum(1 for v in all_vulns if v.severity == "critical")
        high_v       = sum(1 for v in all_vulns if v.severity == "high")

        today_start  = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        scans_today  = db.query(Scan).filter(Scan.created_at >= today_start).count()

        # Average risk score (latest score per target)
        try:
            scores = db.query(RiskScore)\
                       .filter(RiskScore.asset_type == "scan")\
                       .order_by(RiskScore.calculated_at.desc())\
                       .all()
            # Deduplicate: latest score per target
            seen: set = set()
            unique_scores = []
            for rs in scores:
                if rs.target_id not in seen:
                    seen.add(rs.target_id)
                    unique_scores.append(rs.score)
            avg_score = round(sum(unique_scores) / len(unique_scores), 1) if unique_scores else 0.0
        except Exception:
            avg_score = 0.0

        return DashboardOverview(
            total_targets    = total_targets,
            active_targets   = active_targets,
            total_scans      = total_scans,
            total_subdomains = total_subs,
            total_live_hosts = total_hosts,
            total_vulns      = total_vulns,
            critical_vulns   = critical_v,
            high_vulns       = high_v,
            scans_today      = scans_today,
            avg_risk_score   = avg_score,
        )


@router.get("/recent-changes", response_model=List[RecentChange], summary="Recent significant changes")
def recent_changes(
    limit: int = Query(20, ge=1, le=100),
    significant_only: bool = Query(True),
):
    with get_db_context() as db:
        q = db.query(Change)
        if significant_only:
            q = q.filter(Change.is_significant == True)
        changes = q.order_by(Change.detected_at.desc()).limit(limit).all()

        result = []
        for c in changes:
            target = db.query(Target).filter(Target.id == c.target_id).first()
            result.append(RecentChange(
                domain         = target.domain if target else "unknown",
                change_type    = c.change_type or "",
                severity       = c.severity or "info",
                asset_id       = c.asset_id or "",
                is_significant = bool(c.is_significant),
                detected_at    = c.detected_at,
            ))
        return result


@router.get("/top-risks", response_model=List[TopRiskTarget], summary="Top risk targets")
def top_risks(limit: int = Query(10, ge=1, le=50)):
    """Return targets ranked by their latest risk score, highest first."""
    with get_db_context() as db:
        targets = db.query(Target).filter(Target.status == "active").all()
        rows = []
        for t in targets:
            try:
                rs = db.query(RiskScore)\
                       .filter(RiskScore.target_id == t.id, RiskScore.asset_type == "scan")\
                       .order_by(RiskScore.calculated_at.desc())\
                       .first()
                score = rs.score if rs else 0
            except Exception:
                score = 0

            vulns    = db.query(Vulnerability).filter(Vulnerability.target_id == t.id).all()
            critical = sum(1 for v in vulns if v.severity == "critical")

            label = (
                "CRITICAL" if score >= 80 else
                "HIGH"     if score >= 60 else
                "MEDIUM"   if score >= 40 else
                "LOW"      if score >= 20 else "INFO"
            )
            rows.append(TopRiskTarget(
                domain       = t.domain,
                risk_score   = score,
                risk_label   = label,
                vuln_count   = len(vulns),
                critical_vulns = critical,
            ))

        rows.sort(key=lambda r: -r.risk_score)
        return rows[:limit]


@router.get("/activity", response_model=List[ActivityPoint], summary="Scan activity last 7 days")
def activity(days: int = Query(7, ge=1, le=30)):
    """Return daily scan counts + findings for the last N days."""
    with get_db_context() as db:
        result = []
        for i in range(days - 1, -1, -1):
            day_start = (datetime.utcnow() - timedelta(days=i)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            day_end = day_start + timedelta(days=1)

            scans_count = db.query(Scan)\
                .filter(Scan.created_at >= day_start, Scan.created_at < day_end).count()
            vulns_count = db.query(Vulnerability)\
                .filter(Vulnerability.first_seen >= day_start,
                        Vulnerability.first_seen < day_end).count()
            subs_count = db.query(Subdomain)\
                .filter(Subdomain.first_seen >= day_start,
                        Subdomain.first_seen < day_end).count()

            result.append(ActivityPoint(
                date           = day_start.strftime("%Y-%m-%d"),
                scans          = scans_count,
                vulns_found    = vulns_count,
                new_subdomains = subs_count,
            ))
        return result
