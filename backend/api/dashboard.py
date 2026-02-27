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
from sqlalchemy import func

from backend.models.database import get_db_context
from backend.models.models import (
    Target, Scan, Subdomain, LiveHost, Vulnerability, Change, RiskScore
)
from backend.utils.cache import ttl_cache
from backend.utils.rate_limit import read_rate_limiter
from fastapi import Depends

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
def overview(_: None = Depends(read_rate_limiter)):
    return _overview_cached()


@ttl_cache(ttl=30, key_prefix="dashboard.overview")
def _overview_cached() -> DashboardOverview:
    """Cached for 30 s — avoids hammering DB on every page refresh."""
    with get_db_context() as db:
        total_targets  = db.query(Target).count()
        active_targets = db.query(Target).filter(Target.status == "active").count()
        total_scans    = db.query(Scan).count()
        total_subs     = db.query(Subdomain).count()
        total_hosts    = db.query(LiveHost).count()

        # Use DB-side aggregation instead of loading all rows into Python
        total_vulns = db.query(func.count(Vulnerability.id)).scalar() or 0
        critical_v  = db.query(func.count(Vulnerability.id))\
                        .filter(Vulnerability.severity == "critical").scalar() or 0
        high_v      = db.query(func.count(Vulnerability.id))\
                        .filter(Vulnerability.severity == "high").scalar() or 0

        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        scans_today = db.query(func.count(Scan.id))\
                        .filter(Scan.created_at >= today_start).scalar() or 0

        # Average risk score — latest score per target via subquery
        try:
            scores = db.query(RiskScore.score)\
                       .filter(RiskScore.asset_type == "scan")\
                       .order_by(RiskScore.calculated_at.desc())\
                       .all()
            seen: set = set()
            unique_scores = []
            for (score,) in scores:
                if score not in seen:
                    seen.add(score)
                    unique_scores.append(score)
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
    _: None = Depends(read_rate_limiter),
):
    with get_db_context() as db:
        q = db.query(Change)
        if significant_only:
            q = q.filter(Change.is_significant == True)
        changes = q.order_by(Change.detected_at.desc()).limit(limit).all()

        if not changes:
            return []

        # Batch-load all referenced targets in ONE query to avoid N+1
        target_ids = list({c.target_id for c in changes if c.target_id})
        targets_map = {
            t.id: t
            for t in db.query(Target).filter(Target.id.in_(target_ids)).all()
        }

        result = []
        for c in changes:
            target = targets_map.get(c.target_id)
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
def top_risks(
    limit: int = Query(10, ge=1, le=50),
    _: None = Depends(read_rate_limiter),
):
    """Return targets ranked by their latest risk score, highest first."""
    return _top_risks_cached(limit)


@ttl_cache(ttl=60, key_prefix="dashboard.top_risks")
def _top_risks_cached(limit: int) -> List[TopRiskTarget]:
    with get_db_context() as db:
        targets = db.query(Target).filter(Target.status == "active").all()
        if not targets:
            return []

        target_ids = [t.id for t in targets]

        # Batch load latest risk score per target (one query)
        risk_rows = db.query(RiskScore)\
                      .filter(RiskScore.target_id.in_(target_ids), RiskScore.asset_type == "scan")\
                      .order_by(RiskScore.calculated_at.desc())\
                      .all()
        latest_score: dict = {}
        for rs in risk_rows:
            if rs.target_id not in latest_score:
                latest_score[rs.target_id] = rs.score

        # Batch load vuln counts per target (two aggregation queries)
        vuln_total_rows = db.query(Vulnerability.target_id, func.count(Vulnerability.id))\
                           .filter(Vulnerability.target_id.in_(target_ids))\
                           .group_by(Vulnerability.target_id).all()
        vuln_critical_rows = db.query(Vulnerability.target_id, func.count(Vulnerability.id))\
                              .filter(Vulnerability.target_id.in_(target_ids),
                                      Vulnerability.severity == "critical")\
                              .group_by(Vulnerability.target_id).all()

        vuln_total    = dict(vuln_total_rows)
        vuln_critical = dict(vuln_critical_rows)

        rows = []
        for t in targets:
            score = latest_score.get(t.id, 0)
            label = (
                "CRITICAL" if score >= 80 else
                "HIGH"     if score >= 60 else
                "MEDIUM"   if score >= 40 else
                "LOW"      if score >= 20 else "INFO"
            )
            rows.append(TopRiskTarget(
                domain         = t.domain,
                risk_score     = score,
                risk_label     = label,
                vuln_count     = vuln_total.get(t.id, 0),
                critical_vulns = vuln_critical.get(t.id, 0),
            ))

        rows.sort(key=lambda r: -r.risk_score)
        return rows[:limit]


@router.get("/activity", response_model=List[ActivityPoint], summary="Scan activity last N days")
def activity(
    days: int = Query(7, ge=1, le=30),
    _: None = Depends(read_rate_limiter),
):
    """Return daily scan counts + findings for the last N days."""
    return _activity_cached(days)


@ttl_cache(ttl=120, key_prefix="dashboard.activity")
def _activity_cached(days: int) -> List[ActivityPoint]:
    with get_db_context() as db:
        result = []
        for i in range(days - 1, -1, -1):
            day_start = (datetime.utcnow() - timedelta(days=i)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            day_end = day_start + timedelta(days=1)

            scans_count = db.query(func.count(Scan.id))\
                .filter(Scan.created_at >= day_start, Scan.created_at < day_end).scalar() or 0
            vulns_count = db.query(func.count(Vulnerability.id))\
                .filter(Vulnerability.first_seen >= day_start,
                        Vulnerability.first_seen < day_end).scalar() or 0
            subs_count  = db.query(func.count(Subdomain.id))\
                .filter(Subdomain.first_seen >= day_start,
                        Subdomain.first_seen < day_end).scalar() or 0

            result.append(ActivityPoint(
                date           = day_start.strftime("%Y-%m-%d"),
                scans          = scans_count,
                vulns_found    = vulns_count,
                new_subdomains = subs_count,
            ))
        return result
