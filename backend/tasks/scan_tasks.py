"""
ReconXploit - Scan Tasks (Celery)
Orchestrates the full recon pipeline
"""

import logging
from datetime import datetime
from backend.tasks.celery_app import celery_app
from backend.models.database import get_db_context
from backend.models.models import Scan, Target

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="backend.tasks.scan_tasks.run_full_scan")
def run_full_scan(self, scan_id: str, domain: str, scan_type: str = "full", phases: list = None):
    """
    Main recon pipeline task.
    Runs all phases sequentially and tracks progress.
    """
    logger.info(f"Starting scan {scan_id} for {domain} (type={scan_type})")
    phases = phases or ["all"]
    run_all = "all" in phases

    stats = {
        "subdomains_found": 0,
        "live_hosts": 0,
        "open_ports": 0,
        "vulnerabilities": 0,
        "js_findings": 0,
        "changes": 0,
    }

    _update_scan_status(scan_id, "running")

    try:
        # Phase 1: Subdomain Discovery
        if run_all or "discovery" in phases:
            self.update_state(state="PROGRESS", meta={"phase": "discovery", "progress": 10})
            from backend.modules.discovery import SubdomainDiscovery
            discovery = SubdomainDiscovery(domain, scan_id)
            stats["subdomains_found"] = discovery.run()
            logger.info(f"Discovery: {stats['subdomains_found']} subdomains")

        # Phase 2: Live Host Validation
        if run_all or "validation" in phases:
            self.update_state(state="PROGRESS", meta={"phase": "validation", "progress": 30})
            # from backend.modules.validation import HostValidation
            # stats["live_hosts"] = HostValidation(scan_id).run()
            logger.info("Validation phase - coming soon")

        # Phase 3: Port Scanning
        if run_all or "ports" in phases:
            self.update_state(state="PROGRESS", meta={"phase": "ports", "progress": 50})
            # from backend.modules.port_scan import PortScanner
            # stats["open_ports"] = PortScanner(scan_id).run()
            logger.info("Port scanning phase - coming soon")

        # Phase 4: Vulnerability Scanning
        if run_all or "vulns" in phases:
            self.update_state(state="PROGRESS", meta={"phase": "vulns", "progress": 70})
            # from backend.modules.vuln_scan import VulnScanner
            # stats["vulnerabilities"] = VulnScanner(scan_id).run()
            logger.info("Vuln scanning phase - coming soon")

        # Phase 5: JS Intelligence
        if run_all or "js" in phases:
            self.update_state(state="PROGRESS", meta={"phase": "js", "progress": 85})
            # from backend.modules.js_analysis import JsAnalyzer
            # stats["js_findings"] = JsAnalyzer(scan_id).run()
            logger.info("JS analysis phase - coming soon")

        # Phase 6: Change Detection
        if run_all:
            self.update_state(state="PROGRESS", meta={"phase": "changes", "progress": 95})
            # from backend.modules.change_detection import ChangeDetector
            # stats["changes"] = ChangeDetector(scan_id).run()
            logger.info("Change detection phase - coming soon")

        _update_scan_status(scan_id, "completed", stats=stats)
        logger.info(f"Scan {scan_id} completed: {stats}")
        return stats

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        _update_scan_status(scan_id, "failed", error=str(e))
        raise


@celery_app.task(name="backend.tasks.scan_tasks.check_scheduled_scans")
def check_scheduled_scans():
    """Check for targets with scheduled scans that are due to run."""
    from croniter import croniter

    with get_db_context() as db:
        targets = db.query(Target).filter(
            Target.status == "active",
            Target.scan_schedule.isnot(None)
        ).all()

        for target in targets:
            try:
                cron = croniter(target.scan_schedule)
                next_run = cron.get_prev(datetime)
                # If the last scheduled run was in the past 2 minutes, trigger scan
                delta = (datetime.utcnow() - next_run).total_seconds()
                if 0 <= delta <= 120:
                    logger.info(f"Triggering scheduled scan for {target.domain}")
                    # Create scan record and queue
                    scan = Scan(
                        target_id=target.id,
                        scan_type="full",
                        status="pending",
                        start_time=datetime.utcnow(),
                    )
                    db.add(scan)
                    db.flush()
                    run_full_scan.delay(str(scan.id), target.domain, "full")
            except Exception as e:
                logger.warning(f"Schedule check failed for {target.domain}: {e}")


def _update_scan_status(scan_id: str, status: str, stats: dict = None, error: str = None):
    """Update scan status in the database."""
    with get_db_context() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
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
