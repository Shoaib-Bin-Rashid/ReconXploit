"""
ReconXploit - Scan Scheduler
Phase 9: Automatically re-scan targets on a configurable schedule.

Features:
  - Per-target scan intervals (default 24h, quick 6h for high-risk, passive 72h)
  - Persistent state (last run time, next run time) in data/scheduler_state.json
  - Max concurrent scan cap (default: 3)
  - On-boot catch-up: targets overdue on startup are queued immediately
  - Manual trigger via CLI: python reconxp.py --schedule run-now target.com
  - Graceful shutdown on Ctrl-C
  - Full integration with reconxp.py run_scan()

Usage:
  Start daemon:   python reconxp.py --mode auto
  Force rescan:   python reconxp.py target.com --force

State file format (data/scheduler_state.json):
  {
    "targets": {
      "example.com": {
        "mode":       "full",
        "interval_h": 24,
        "last_run":   "2025-01-01T00:00:00",
        "next_run":   "2025-01-02T00:00:00",
        "last_score": 72,
        "run_count":  5,
        "status":     "idle"    # idle | running | error
      }
    },
    "scheduler_started": "2025-01-01T00:00:00",
    "total_runs": 42
  }
"""

import json
import logging
import signal
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────

STATE_FILE      = Path("data/scheduler_state.json")
TARGETS_FILE    = Path("data/targets.txt")
POLL_INTERVAL_S = 30      # how often the scheduler loop checks for due targets
MIN_INTERVAL_H  = 1       # minimum allowed scan interval


class SchedulerState:
    """
    Thread-safe read/write of the scheduler state JSON file.
    """

    def __init__(self, state_file: Path = STATE_FILE):
        self._file = state_file
        self._lock = threading.Lock()
        self._state: Dict = self._load()

    # ─── Public interface ───────────────────────────────────

    def get_target(self, domain: str) -> Optional[Dict]:
        with self._lock:
            return self._state["targets"].get(domain)

    def upsert_target(self, domain: str, **kwargs) -> None:
        with self._lock:
            if domain not in self._state["targets"]:
                self._state["targets"][domain] = {
                    "mode":       "full",
                    "interval_h": 24,
                    "last_run":   None,
                    "next_run":   None,
                    "last_score": 0,
                    "run_count":  0,
                    "status":     "idle",
                }
            self._state["targets"][domain].update(kwargs)
            self._save()

    def mark_running(self, domain: str) -> None:
        self.upsert_target(domain, status="running", last_run=_now_iso())

    def mark_done(self, domain: str, score: int, interval_h: int) -> None:
        next_run = (datetime.utcnow() + timedelta(hours=interval_h)).isoformat()
        with self._lock:
            t = self._state["targets"].get(domain, {})
            t.update({
                "status":     "idle",
                "last_score": score,
                "next_run":   next_run,
                "run_count":  t.get("run_count", 0) + 1,
            })
            self._state["targets"][domain] = t
            self._state["total_runs"] = self._state.get("total_runs", 0) + 1
            self._save()

    def mark_error(self, domain: str, error: str) -> None:
        self.upsert_target(domain, status="error", error=error[:200])

    def get_due(self) -> List[str]:
        """Return list of domains whose next_run is in the past (or never run)."""
        now = datetime.utcnow()
        due = []
        with self._lock:
            for domain, info in self._state["targets"].items():
                if info.get("status") == "running":
                    continue
                next_run = info.get("next_run")
                if next_run is None:
                    due.append(domain)
                else:
                    try:
                        if datetime.fromisoformat(next_run) <= now:
                            due.append(domain)
                    except ValueError:
                        due.append(domain)
        return due

    def get_running_count(self) -> int:
        with self._lock:
            return sum(
                1 for t in self._state["targets"].values()
                if t.get("status") == "running"
            )

    def all_targets(self) -> Dict:
        with self._lock:
            return dict(self._state["targets"])

    def summary(self) -> Dict:
        with self._lock:
            targets = self._state["targets"]
            return {
                "total_targets":  len(targets),
                "running":        sum(1 for t in targets.values() if t.get("status") == "running"),
                "idle":           sum(1 for t in targets.values() if t.get("status") == "idle"),
                "error":          sum(1 for t in targets.values() if t.get("status") == "error"),
                "total_runs":     self._state.get("total_runs", 0),
                "scheduler_started": self._state.get("scheduler_started", ""),
            }

    # ─── Private ────────────────────────────────────────────

    def _load(self) -> Dict:
        self._file.parent.mkdir(parents=True, exist_ok=True)
        if self._file.exists():
            try:
                data = json.loads(self._file.read_text(encoding="utf-8"))
                if "targets" not in data:
                    data["targets"] = {}
                return data
            except (json.JSONDecodeError, OSError):
                logger.warning(f"[Scheduler] Could not parse {self._file} — starting fresh")
        return {"targets": {}, "scheduler_started": _now_iso(), "total_runs": 0}

    def _save(self) -> None:
        try:
            self._file.write_text(
                json.dumps(self._state, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as e:
            logger.warning(f"[Scheduler] State save error: {e}")


# ─────────────────────────────────────────────────────────────
# TARGET LOADER
# ─────────────────────────────────────────────────────────────

def load_targets_from_file(path: Path = TARGETS_FILE) -> List[Dict]:
    """
    Parse data/targets.txt and return list of target dicts.

    Format:  domain | program | mode | status | interval_h
    Example: example.com | HackerOne | full | active | 24
    """
    if not path.exists():
        return []

    targets = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        domain = parts[0] if parts else ""
        if not domain:
            continue
        status = parts[3] if len(parts) > 3 else "active"
        if status != "active":
            continue
        interval_h = 24
        if len(parts) > 4:
            try:
                interval_h = max(MIN_INTERVAL_H, int(parts[4]))
            except ValueError:
                pass
        targets.append({
            "domain":     domain,
            "mode":       parts[2] if len(parts) > 2 else "full",
            "interval_h": interval_h,
        })
    return targets


def _interval_for_score(score: int, default_h: int) -> int:
    """Adaptive interval: high-risk targets re-scan more frequently."""
    if score >= 80:
        return max(MIN_INTERVAL_H, default_h // 4)   # CRITICAL → 4× faster
    if score >= 60:
        return max(MIN_INTERVAL_H, default_h // 2)   # HIGH     → 2× faster
    return default_h


# ─────────────────────────────────────────────────────────────
# SCHEDULER
# ─────────────────────────────────────────────────────────────

class ScanScheduler:
    """
    Daemon that watches targets.txt and re-scans targets when their
    next_run time arrives.

    Designed to run inside the reconxp.py --mode auto loop.
    Also callable standalone via ScanScheduler(...).start().
    """

    def __init__(
        self,
        max_concurrent: int = 3,
        poll_interval:  int = POLL_INTERVAL_S,
        default_interval_h: int = 24,
        state_file: Path = STATE_FILE,
    ):
        self.max_concurrent    = max_concurrent
        self.poll_interval     = poll_interval
        self.default_interval_h = default_interval_h
        self.state             = SchedulerState(state_file)
        self._stop_event       = threading.Event()
        self._threads: List[threading.Thread] = []

    # ─────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────

    def start(self, cycle_callback=None) -> None:
        """
        Start the scheduler loop (blocking until stopped).

        Args:
            cycle_callback: optional callable(summary_dict) called after each poll cycle
        """
        logger.info("[Scheduler] Starting scheduler daemon")

        # Register clean shutdown
        signal.signal(signal.SIGINT,  lambda *_: self.stop())
        signal.signal(signal.SIGTERM, lambda *_: self.stop())

        # Sync targets from file
        self._sync_targets()

        while not self._stop_event.is_set():
            self._tick()
            if cycle_callback:
                try:
                    cycle_callback(self.state.summary())
                except Exception:
                    pass
            self._stop_event.wait(timeout=self.poll_interval)

        # Wait for running scans to finish
        self._join_all()
        logger.info("[Scheduler] Scheduler stopped cleanly")

    def stop(self) -> None:
        logger.info("[Scheduler] Stop requested")
        self._stop_event.set()

    def run_now(self, domain: str, mode: str = "full") -> bool:
        """Force an immediate scan of a single target (non-blocking)."""
        t = self.state.get_target(domain)
        if t and t.get("status") == "running":
            logger.warning(f"[Scheduler] {domain} is already running — skipping")
            return False
        self.state.upsert_target(domain, mode=mode, next_run=None)
        self._launch_scan(domain, mode, self.default_interval_h)
        return True

    def add_target(self, domain: str, mode: str = "full", interval_h: int = 24) -> None:
        """Register a new target with the scheduler."""
        interval_h = max(MIN_INTERVAL_H, interval_h)
        self.state.upsert_target(domain, mode=mode, interval_h=interval_h)
        logger.info(f"[Scheduler] Target added: {domain} (mode={mode}, interval={interval_h}h)")

    def get_summary(self) -> Dict:
        return self.state.summary()

    def get_status(self) -> List[Dict]:
        """Return per-target status table."""
        rows = []
        now = datetime.utcnow()
        for domain, info in sorted(self.state.all_targets().items()):
            next_run = info.get("next_run")
            if next_run:
                try:
                    eta = datetime.fromisoformat(next_run) - now
                    eta_str = _humanize(eta)
                except ValueError:
                    eta_str = "?"
            else:
                eta_str = "DUE NOW"
            rows.append({
                "domain":     domain,
                "mode":       info.get("mode", "full"),
                "status":     info.get("status", "idle"),
                "last_run":   info.get("last_run", "never"),
                "next_run":   info.get("next_run", "never"),
                "eta":        eta_str,
                "last_score": info.get("last_score", 0),
                "run_count":  info.get("run_count", 0),
            })
        return rows

    # ─────────────────────────────────────────────────
    # INTERNAL LOOP
    # ─────────────────────────────────────────────────

    def _tick(self) -> None:
        """One scheduler poll cycle."""
        # Refresh target list from file
        self._sync_targets()

        # Clean up finished threads
        self._threads = [t for t in self._threads if t.is_alive()]

        due = self.state.get_due()
        running = self.state.get_running_count()
        slots   = self.max_concurrent - running

        if not due:
            logger.debug("[Scheduler] No targets due")
            return

        logger.info(f"[Scheduler] {len(due)} target(s) due, {slots} slot(s) available")

        for domain in due[:slots]:
            info = self.state.get_target(domain) or {}
            mode       = info.get("mode", "full")
            interval_h = info.get("interval_h", self.default_interval_h)
            self._launch_scan(domain, mode, interval_h)

    def _launch_scan(self, domain: str, mode: str, interval_h: int) -> None:
        """Launch a scan in a background thread."""
        self.state.mark_running(domain)
        t = threading.Thread(
            target=self._run_scan_thread,
            args=(domain, mode, interval_h),
            name=f"scan-{domain}",
            daemon=True,
        )
        self._threads.append(t)
        t.start()
        logger.info(f"[Scheduler] Launched scan: {domain} (mode={mode})")

    def _run_scan_thread(self, domain: str, mode: str, interval_h: int) -> None:
        """Worker thread: runs one full scan pipeline."""
        score = 0
        try:
            logger.info(f"[Scheduler] Scan started: {domain}")
            score = self._execute_scan(domain, mode)
            # Adaptive interval based on risk score
            adaptive_h = _interval_for_score(score, interval_h)
            self.state.mark_done(domain, score=score, interval_h=adaptive_h)
            logger.info(
                f"[Scheduler] Scan done: {domain} score={score} "
                f"next_run in {adaptive_h}h"
            )
        except Exception as e:
            logger.error(f"[Scheduler] Scan error for {domain}: {e}")
            self.state.mark_error(domain, str(e))

    def _execute_scan(self, domain: str, mode: str) -> int:
        """
        Execute the full scan pipeline for a domain.
        Returns the overall risk score.
        """
        import uuid
        from backend.modules.discovery      import SubdomainDiscovery
        from backend.modules.validation     import HostValidator
        from backend.modules.port_scan      import PortScanner
        from backend.modules.vuln_scan      import VulnScanner
        from backend.modules.js_analysis    import JSAnalyzer
        from backend.modules.change_detection import ChangeDetector
        from backend.modules.risk_scoring   import RiskScorer
        from backend.modules.alerts         import AlertManager
        from backend.modules.screenshots    import ScreenshotEngine

        scan_id   = str(uuid.uuid4())
        phases    = _mode_to_phases(mode)
        scan_data = {}

        subdomains = []
        if "discovery" in phases:
            d = SubdomainDiscovery(domain, scan_id)
            d.run()
            subdomains = d.get_results()
            scan_data["subdomains"] = subdomains

        live_hosts = []
        if "live_hosts" in phases:
            v = HostValidator(domain, scan_id)
            v.run(subdomains)
            live_hosts = v.get_results()
            scan_data["live_hosts"] = live_hosts

        if "ports" in phases:
            ps = PortScanner(domain, scan_id)
            ps.run(live_hosts)
            scan_data["ports"] = ps.get_results()

        if "vulns" in phases:
            vs = VulnScanner(domain, scan_id)
            vs.run(live_hosts)
            scan_data["vulnerabilities"] = vs.get_results()

        if "js" in phases:
            js = JSAnalyzer(domain, scan_id)
            js.run(live_hosts)
            scan_data["js_findings"] = js.get_results()

        changes = []
        if "changes" in phases:
            cd = ChangeDetector(domain, scan_id)
            cd.run(scan_data)
            changes = cd.get_results()
            scan_data["changes"] = changes

        score = 0
        if "risk" in phases:
            rs = RiskScorer(domain, scan_id)
            score = rs.run(scan_data)

        if "alerts" in phases:
            am = AlertManager(domain, scan_id)
            am.run(score, scan_data, changes)

        if "screenshots" in phases:
            se = ScreenshotEngine(domain, scan_id)
            se.run(live_hosts)

        return score

    def _sync_targets(self) -> None:
        """Add any new targets from targets.txt to the state."""
        for t in load_targets_from_file():
            existing = self.state.get_target(t["domain"])
            if not existing:
                self.state.upsert_target(
                    t["domain"],
                    mode=t["mode"],
                    interval_h=t["interval_h"],
                )

    def _join_all(self, timeout: int = 30) -> None:
        """Wait for all running scan threads to finish."""
        for t in self._threads:
            if t.is_alive():
                t.join(timeout=timeout)


# ─────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────

def _mode_to_phases(mode: str) -> List[str]:
    """Map scan mode name to list of phases."""
    MAP = {
        "full":    ["discovery", "live_hosts", "ports", "vulns", "js",
                    "changes", "risk", "alerts", "screenshots"],
        "deep":    ["discovery", "live_hosts", "ports", "vulns", "js",
                    "changes", "risk", "alerts", "screenshots"],
        "quick":   ["discovery", "live_hosts"],
        "passive": ["discovery"],
        "auto":    ["discovery", "live_hosts", "ports", "vulns", "js",
                    "changes", "risk", "alerts", "screenshots"],
    }
    return MAP.get(mode, MAP["full"])


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


def _humanize(delta: timedelta) -> str:
    """Convert timedelta to human-readable string like '3h 20m'."""
    total_s = int(delta.total_seconds())
    if total_s < 0:
        return "overdue"
    h, rem = divmod(total_s, 3600)
    m, _   = divmod(rem, 60)
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"
