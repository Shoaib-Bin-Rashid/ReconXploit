"""
ReconXploit API — Scans router

Endpoints:
  GET    /api/v1/scans                  List all scans (paginated)
  POST   /api/v1/scans                  Trigger a new scan
  GET    /api/v1/scans/{scan_id}        Get scan details
  DELETE /api/v1/scans/{scan_id}        Delete scan record
  GET    /api/v1/scans/{scan_id}/results  Full scan results bundle
"""

import logging
import uuid as uuid_mod
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Depends
from pydantic import BaseModel, Field

from backend.models.database import get_db_context
from backend.models.models import Scan, Target, Subdomain, LiveHost, Port, Vulnerability, JsIntelligence
from backend.utils.rate_limit import scan_rate_limiter
from backend.utils.cache import cache_clear_all

logger = logging.getLogger(__name__)
router = APIRouter()


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────

class ScanTrigger(BaseModel):
    domain: str
    mode: str = Field("full", description="full|passive|quick|deep")


class ScanOut(BaseModel):
    id: str
    target_domain: Optional[str]
    scan_type: Optional[str]
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    findings_count: Optional[int]

    class Config:
        from_attributes = True


class ScanResults(BaseModel):
    scan_id: str
    domain: str
    mode: str
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    subdomains: List[dict]
    live_hosts: List[dict]
    ports: List[dict]
    vulnerabilities: List[dict]
    js_findings: List[dict]
    summary: dict


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@router.get("", response_model=List[ScanOut], summary="List scans")
def list_scans(
    domain: Optional[str] = Query(None, description="Filter by target domain"),
    status: Optional[str] = Query(None, description="Filter by status: pending|running|completed|failed"),
    limit:  int           = Query(50, ge=1, le=200),
    offset: int           = Query(0, ge=0),
):
    with get_db_context() as db:
        q = db.query(Scan)
        if domain:
            target = db.query(Target).filter(Target.domain == domain).first()
            if target:
                q = q.filter(Scan.target_id == target.id)
            else:
                return []
        if status:
            q = q.filter(Scan.status == status)
        scans = q.order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
        return [_scan_out(s, db) for s in scans]


@router.post("", status_code=202, summary="Trigger a new scan")
def trigger_scan(
    body: ScanTrigger,
    background_tasks: BackgroundTasks,
    _: None = Depends(scan_rate_limiter),
):
    """
    Enqueue a scan for the given domain.
    Dispatches to Celery if Redis is reachable; falls back to BackgroundTasks.
    Poll GET /scans/{scan_id} for status.
    """
    with get_db_context() as db:
        target = db.query(Target).filter(Target.domain == body.domain).first()
        if not target:
            raise HTTPException(404, f"Target '{body.domain}' not found. Add it first via POST /targets")

        scan_id = str(uuid_mod.uuid4())
        scan = Scan(
            id        = scan_id,
            target_id = target.id,
            scan_type = body.mode,
            status    = "pending",
        )
        db.add(scan)
        db.commit()

    dispatched_via = _dispatch_scan(body.domain, body.mode, scan_id, background_tasks)
    logger.info(f"Scan queued via {dispatched_via}: {body.domain} ({body.mode}) → {scan_id}")
    return {
        "scan_id":        scan_id,
        "status":         "pending",
        "domain":         body.domain,
        "mode":           body.mode,
        "dispatched_via": dispatched_via,
    }


@router.get("/{scan_id}/task", summary="Get Celery task state for a scan")
def get_task_state(scan_id: str):
    """
    Return the Celery PROGRESS meta for an async scan.
    Falls back gracefully when Celery/Redis is unavailable.
    """
    try:
        from backend.tasks.celery_app import celery_app
        result = celery_app.AsyncResult(scan_id)
        return {
            "task_id": scan_id,
            "state":   result.state,
            "meta":    result.info if isinstance(result.info, dict) else {},
        }
    except Exception:
        return {"task_id": scan_id, "state": "UNKNOWN", "meta": {}}


@router.get("/{scan_id}", response_model=ScanOut, summary="Get scan status")
def get_scan(scan_id: str):
    with get_db_context() as db:
        scan = _get_scan_or_404(db, scan_id)
        return _scan_out(scan, db)


@router.delete("/{scan_id}", status_code=204, summary="Delete scan")
def delete_scan(scan_id: str):
    with get_db_context() as db:
        scan = _get_scan_or_404(db, scan_id)
        db.delete(scan)
        db.commit()


@router.get("/{scan_id}/results", response_model=ScanResults, summary="Get full scan results")
def get_scan_results(scan_id: str):
    """Return all findings from a specific scan in one bundle."""
    with get_db_context() as db:
        scan   = _get_scan_or_404(db, scan_id)
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        domain = target.domain if target else "unknown"

        subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan_id).all()
        live_hosts = db.query(LiveHost).filter(LiveHost.scan_id == scan_id).all()
        ports      = db.query(Port).filter(Port.scan_id == scan_id).all()
        vulns      = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        js_finds   = db.query(JsIntelligence).filter(JsIntelligence.scan_id == scan_id).all()

        # Severity counts
        sev_counts: dict = {}
        for v in vulns:
            s = v.severity or "info"
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return ScanResults(
            scan_id      = scan_id,
            domain       = domain,
            mode         = scan.scan_type or "full",
            status       = scan.status,
            started_at   = scan.created_at,
            completed_at = scan.end_time,
            subdomains   = [{"subdomain": s.subdomain, "source": s.source} for s in subdomains],
            live_hosts   = [{"url": h.url, "status_code": h.status_code, "title": h.title} for h in live_hosts],
            ports        = [{"host": p.host, "port": p.port_number, "service": p.service_name} for p in ports],
            vulnerabilities = [
                {"name": v.vulnerability_name, "severity": v.severity, "url": v.matched_at}
                for v in vulns
            ],
            js_findings  = [{"type": j.finding_type, "url": j.source_url} for j in js_finds],
            summary      = {
                "subdomains":  len(subdomains),
                "live_hosts":  len(live_hosts),
                "ports":       len(ports),
                "vulns":       len(vulns),
                "js_findings": len(js_finds),
                "by_severity": sev_counts,
            },
        )


# ─────────────────────────────────────────────
# Dispatch helpers
# ─────────────────────────────────────────────

def _dispatch_scan(domain: str, mode: str, scan_id: str, background_tasks: BackgroundTasks) -> str:
    """
    Try Celery first; fall back to FastAPI BackgroundTasks if Redis unavailable.
    Returns 'celery' or 'background_thread'.
    """
    try:
        from backend.tasks.scan_tasks import run_full_scan
        run_full_scan.delay(scan_id, domain, mode)
        return "celery"
    except Exception as celery_err:
        logger.warning(f"Celery unavailable ({celery_err}), falling back to background thread")
        background_tasks.add_task(_run_scan_bg, domain, mode, scan_id)
        return "background_thread"


# ─────────────────────────────────────────────
# Background task (fallback)
# ─────────────────────────────────────────────

def _run_scan_bg(domain: str, mode: str, scan_id: str) -> None:
    """Run the full scan pipeline in a background thread."""
    try:
        _set_scan_status(scan_id, "running")
        from backend.modules.scheduler import ScanScheduler, _mode_to_phases
        import uuid

        phases = _mode_to_phases(mode)
        sched  = ScanScheduler.__new__(ScanScheduler)
        score  = sched._execute_scan.__func__(sched, domain, mode)  # type: ignore
        _set_scan_status(scan_id, "completed")
        logger.info(f"Background scan complete: {domain} score={score}")
    except Exception as e:
        logger.error(f"Background scan failed: {domain} — {e}")
        _set_scan_status(scan_id, "failed")


def _set_scan_status(scan_id: str, status: str) -> None:
    try:
        with get_db_context() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = status
                if status == "completed":
                    scan.end_time = datetime.utcnow()
                db.commit()
        # Invalidate dashboard cache so next read reflects new scan state
        if status in ("completed", "failed"):
            cache_clear_all()
    except Exception as e:
        logger.warning(f"Could not update scan status: {e}")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _get_scan_or_404(db, scan_id: str) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, f"Scan '{scan_id}' not found")
    return scan


def _scan_out(scan: Scan, db) -> ScanOut:
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    return ScanOut(
        id             = scan.id,
        target_domain  = target.domain if target else None,
        scan_type      = scan.scan_type,
        status         = scan.status,
        started_at     = scan.created_at,
        completed_at   = scan.end_time,
        findings_count = getattr(scan, "findings_count", None),
    )
