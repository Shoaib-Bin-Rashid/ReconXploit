"""
ReconXploit - Scan Tasks (Celery)
Phase 12: Fully wired recon pipeline as Celery tasks.

Tasks:
  run_full_scan        — main 8-phase pipeline (discovery → screenshots)
  run_phase_task       — run a single named phase on an existing scan
  check_scheduled_scans— beat task: fire due scheduled targets
"""

import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from backend.tasks.celery_app import celery_app
from backend.models.database import get_db_context
from backend.models.models import Scan, Target

logger = logging.getLogger(__name__)

# Progress checkpoints (phase → 0-100)
PHASE_PROGRESS: Dict[str, int] = {
    "discovery":  10,
    "validation": 25,
    "ports":      40,
    "vulns":      55,
    "js":         68,
    "changes":    78,
    "risk":       86,
    "alerts":     92,
    "screenshots":98,
}


# ──────────────────────────────────────────────────────────────────────────────
# Main pipeline task
# ──────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="backend.tasks.scan_tasks.run_full_scan",
    max_retries=0,
    track_started=True,
)
def run_full_scan(
    self,
    scan_id: str,
    domain: str,
    scan_type: str = "full",
    phases: Optional[List[str]] = None,
):
    """
    Orchestrate the full recon pipeline for one domain.
    Sends PROGRESS updates at each phase so callers can poll state.
    """
    phases = phases if phases is not None else ["all"]
    run_all = "all" in phases

    logger.info(f"[{scan_id}] Starting {scan_type} scan for {domain}")

    stats: Dict[str, int] = {
        "subdomains_found": 0,
        "live_hosts": 0,
        "open_ports": 0,
        "vulnerabilities": 0,
        "js_findings": 0,
        "changes": 0,
    }

    _set_status(scan_id, "running")

    try:
        # ── Phase 1: Subdomain Discovery ─────────────────────────────────────
        if run_all or "discovery" in phases:
            _progress(self, "discovery", domain)
            from backend.modules.discovery import SubdomainDiscovery
            stats["subdomains_found"] = SubdomainDiscovery(domain, scan_id).run()
            logger.info(f"[{scan_id}] discovery → {stats['subdomains_found']} subdomains")

        # ── Phase 2: Live Host Validation ─────────────────────────────────────
        subdomains: List[str] = []
        live_hosts: List[Dict] = []

        if run_all or "validation" in phases:
            _progress(self, "validation", domain)
            from backend.modules.validation import LiveHostValidator
            with get_db_context() as db:
                from backend.models.models import Subdomain
                rows = db.query(Subdomain).filter(Subdomain.scan_id == scan_id).all()
                subdomains = [r.subdomain for r in rows]
            if subdomains:
                validator = LiveHostValidator(domain, scan_id)
                stats["live_hosts"] = validator.run(subdomains)
                live_hosts = validator.get_live_urls()  # type: ignore[attr-defined]
            logger.info(f"[{scan_id}] validation → {stats['live_hosts']} live hosts")

        # ── Phase 3: Port Scanning ────────────────────────────────────────────
        if run_all or "ports" in phases:
            _progress(self, "ports", domain)
            if live_hosts:
                from backend.modules.port_scan import PortScanner
                stats["open_ports"] = PortScanner(domain, scan_id).run(live_hosts)
            logger.info(f"[{scan_id}] ports → {stats['open_ports']} open ports")

        # ── Phase 4: Vulnerability Scanning ───────────────────────────────────
        if run_all or "vulns" in phases:
            _progress(self, "vulns", domain)
            if live_hosts:
                from backend.modules.vuln_scan import VulnerabilityScanner
                stats["vulnerabilities"] = VulnerabilityScanner(domain, scan_id).run(live_hosts)
            logger.info(f"[{scan_id}] vulns → {stats['vulnerabilities']} findings")

        # ── Phase 5: JS Intelligence ──────────────────────────────────────────
        if run_all or "js" in phases:
            _progress(self, "js", domain)
            if live_hosts:
                from backend.modules.js_analysis import JsAnalyzer
                stats["js_findings"] = JsAnalyzer(domain, scan_id).run(live_hosts)
            logger.info(f"[{scan_id}] js → {stats['js_findings']} findings")

        # ── Phase 6: Change Detection ─────────────────────────────────────────
        if run_all or "changes" in phases:
            _progress(self, "changes", domain)
            from backend.modules.change_detection import ChangeDetector
            current_data = {
                "subdomains": subdomains,
                "live_hosts": live_hosts,
                "stats": stats,
            }
            stats["changes"] = ChangeDetector(domain, scan_id).run(current_data)
            logger.info(f"[{scan_id}] changes → {stats['changes']} changes")

        # ── Phase 7: Risk Scoring ─────────────────────────────────────────────
        risk_score = 0
        if run_all or "risk" in phases:
            _progress(self, "risk", domain)
            from backend.modules.risk_scoring import RiskScorer
            scan_data = _build_scan_data(scan_id, domain, stats)
            risk_score = RiskScorer(domain, scan_id).run(scan_data)

        # ── Phase 8: Alerts ───────────────────────────────────────────────────
        if run_all or "alerts" in phases:
            _progress(self, "alerts", domain)
            from backend.modules.alerts import AlertManager
            scan_data = _build_scan_data(scan_id, domain, stats)
            changes_list = scan_data.get("changes", [])
            AlertManager(domain, scan_id).run(risk_score, scan_data, changes_list)

        # ── Phase 9: Screenshots ──────────────────────────────────────────────
        if run_all or "screenshots" in phases:
            _progress(self, "screenshots", domain)
            if live_hosts:
                from backend.modules.screenshots import ScreenshotEngine
                urls = [h["url"] if isinstance(h, dict) else h for h in live_hosts]
                ScreenshotEngine(domain, scan_id).run(urls)

        # ── Done ──────────────────────────────────────────────────────────────
        _set_status(scan_id, "completed", stats=stats)
        logger.info(f"[{scan_id}] scan completed: {stats}")
        return stats

    except Exception as exc:
        logger.error(f"[{scan_id}] scan failed: {exc}", exc_info=True)
        _set_status(scan_id, "failed", error=str(exc))
        raise


# ──────────────────────────────────────────────────────────────────────────────
# Single-phase task (for targeted re-runs)
# ──────────────────────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="backend.tasks.scan_tasks.run_phase_task",
    max_retries=1,
    default_retry_delay=30,
)
def run_phase_task(self, scan_id: str, domain: str, phase: str):
    """Re-run a single phase on an existing scan."""
    logger.info(f"[{scan_id}] re-running phase '{phase}' for {domain}")
    return run_full_scan.apply(args=[scan_id, domain, "custom", [phase]]).result


# ──────────────────────────────────────────────────────────────────────────────
# Beat task: trigger scheduled targets
# ──────────────────────────────────────────────────────────────────────────────

@celery_app.task(name="backend.tasks.scan_tasks.check_scheduled_scans")
def check_scheduled_scans():
    """
    Called every minute by Celery Beat.
    Fires run_full_scan for any target whose next_run is overdue.
    Uses SchedulerState (file-based) so it works even without cron fields.
    """
    from backend.modules.scheduler import SchedulerState
    state = SchedulerState()
    now = datetime.utcnow()

    with get_db_context() as db:
        targets = db.query(Target).filter(Target.status == "active").all()
        target_map = {t.domain: t for t in targets}

    for domain, info in state.all().items():
        if info.get("status") == "disabled":
            continue

        next_run_str = info.get("next_run")
        if not next_run_str:
            continue

        try:
            next_run = datetime.fromisoformat(next_run_str)
        except ValueError:
            continue

        if now < next_run:
            continue

        target = target_map.get(domain)
        if not target:
            continue

        logger.info(f"[beat] triggering scheduled scan for {domain}")
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=target.id,
            scan_type=info.get("mode", "full"),
            status="pending",
            start_time=now,
        )
        with get_db_context() as db:
            db.add(scan)
            db.flush()
            scan_id = scan.id

        run_full_scan.delay(scan_id, domain, info.get("mode", "full"))


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _progress(task, phase: str, domain: str):
    """Push a PROGRESS state update if running inside a real Celery worker."""
    try:
        task.update_state(
            state="PROGRESS",
            meta={"phase": phase, "domain": domain, "progress": PHASE_PROGRESS.get(phase, 0)},
        )
    except Exception:
        pass  # safe to ignore — we may be running eagerly in tests


def _set_status(
    scan_id: str,
    status: str,
    stats: Optional[Dict] = None,
    error: Optional[str] = None,
):
    with get_db_context() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return
        scan.status = status
        if status in ("completed", "failed"):
            scan.end_time = datetime.utcnow()
            if scan.start_time:
                scan.duration_seconds = int(
                    (scan.end_time - scan.start_time).total_seconds()
                )
        if stats:
            scan.stats = stats
        if error:
            scan.error_message = error
    # Invalidate dashboard cache after any terminal state
    if status in ("completed", "failed"):
        try:
            from backend.utils.cache import cache_clear_all
            cache_clear_all()
        except Exception:
            pass


def _build_scan_data(scan_id: str, domain: str, stats: Dict) -> Dict:
    """Build minimal scan_data dict expected by risk/alert modules."""
    with get_db_context() as db:
        from backend.models.models import Vulnerability, JsIntelligence, Port, Change
        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        ports = db.query(Port).filter(Port.scan_id == scan_id).all()
        js    = db.query(JsIntelligence).filter(JsIntelligence.scan_id == scan_id).all()
        chgs  = db.query(Change).filter(Change.scan_id == scan_id).all()

    return {
        "domain": domain,
        "stats":  stats,
        "vulnerabilities": [
            {"severity": v.severity, "template_id": v.template_id, "name": v.name}
            for v in vulns
        ],
        "ports": [
            {"port": p.port, "service": p.service, "state": p.state}
            for p in ports
        ],
        "js_findings": [
            {"type": j.finding_type, "value": j.value}
            for j in js
        ],
        "changes": [
            {"change_type": c.change_type, "asset": c.asset}
            for c in chgs
        ],
    }
