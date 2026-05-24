"""
ReconXploit - Main Entry Point
================================
Usage:
  python reconxp.py target.com                   # Full scan
  python reconxp.py target.com --mode passive    # Passive only (no active probing)
  python reconxp.py target.com --mode quick      # Quick scan (discovery + live hosts)
  python reconxp.py target.com --mode deep       # Deep scan (everything + brute force)
  python reconxp.py --mode auto                  # Automation daemon (all targets, scheduled)
"""

import sys
import time
import uuid
import click
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich import box
from backend.models.database import get_db_context
from backend.models.models import Target, Scan

console = Console()

BANNER = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
"""

MODES = {
    "full": {
        "label": "Full Scan",
        "color": "bold cyan",
        "phases": ["discovery", "live_hosts", "ports", "vulns", "js", "changes", "risk", "alerts", "screenshots"],
        "description": "All phases. Best coverage.",
    },
    "passive": {
        "label": "Passive Recon",
        "color": "bold green",
        "phases": ["discovery"],
        "description": "No active probing. Uses APIs + cert logs only.",
    },
    "quick": {
        "label": "Quick Scan",
        "color": "bold yellow",
        "phases": ["discovery", "live_hosts"],
        "description": "Discovery + live host check. Fast.",
    },
    "deep": {
        "label": "Deep Scan",
        "color": "bold red",
        "phases": ["discovery", "live_hosts", "ports", "vulns", "js", "changes", "risk", "alerts", "screenshots"],
        "description": "Full scan + brute force wordlists. Thorough but slow.",
    },
    "auto": {
        "label": "Automation Daemon",
        "color": "bold magenta",
        "phases": ["discovery", "live_hosts", "ports", "vulns", "js", "changes", "risk", "alerts", "screenshots"],
        "description": "Runs continuously on all targets. Respects schedules.",
    },
}

PHASE_LABELS = {
    "discovery":   ("🔍", "Subdomain Discovery",   "subfinder, assetfinder, amass, findomain, crt.sh"),
    "live_hosts":  ("🌐", "Live Host Validation",  "httpx — status, title, WAF, CDN, TLS"),
    "ports":       ("🔌", "Port & Service Scan",   "naabu + nmap"),
    "vulns":       ("🧨", "Vulnerability Scan",    "nuclei"),
    "js":         ("🧠", "JS Intelligence",       "linkfinder, secretfinder, gau"),
    "changes":     ("📊", "Change Detection",      "diff vs last scan"),
    "risk":        ("🎯", "Risk Scoring",          "weighted score 0-100"),
    "alerts":      ("🔔", "Alerts",               "Telegram / Discord / Slack"),
    "screenshots": ("🖼️", "Screenshots",           "gowitness / headless Chrome"),
}

DATA_DIR    = Path(__file__).parent / "data"
TARGETS_FILE = DATA_DIR / "targets.txt"


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print("[bold cyan]  Ultimate Automated Recon Platform[/bold cyan]")
    console.print("[dim]  v0.1.0 | Bug Bounty Intelligence Engine[/dim]\n")


def print_mode_info(mode: str, target: str = None):
    m = MODES[mode]
    phases_info = ""
    for p in m["phases"]:
        icon, label, tools = PHASE_LABELS[p]
        phases_info += f"  {icon} {label}\n     [dim]{tools}[/dim]\n"
    target_line = f"  [bold]Target:[/bold]      {target}\n" if target else ""
    console.print(Panel(
        f"[{m['color']}]Mode: {m['label']}[/{m['color']}]\n"
        f"  [dim]{m['description']}[/dim]\n\n"
        f"{target_line}"
        f"  [bold]Phases:[/bold]\n{phases_info}",
        title="[bold cyan]ReconXploit[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED,
    ))


# ─────────────────────────────────────────────────────────────
# PHASE RUNNERS
# ─────────────────────────────────────────────────────────────

def run_phase_discovery(domain: str, scan_id: str):
    from backend.modules.discovery import SubdomainDiscovery
    console.print("\n[bold cyan]🔍 Phase 1 — Subdomain Discovery[/bold cyan]")
    engine = SubdomainDiscovery(domain, scan_id)
    count = engine.run()
    console.print(f"  [green]✓[/green] Found [bold]{count}[/bold] subdomains → [dim]data/subdomains/{domain}.txt[/dim]")
    return engine.get_subdomains()


def run_phase_live_hosts(domain: str, scan_id: str, subdomains: list):
    from backend.modules.validation import LiveHostValidator
    console.print("\n[bold cyan]🌐 Phase 2 — Live Host Validation[/bold cyan]")
    engine = LiveHostValidator(domain, scan_id)
    count = engine.run(subdomains)
    console.print(f"  [green]✓[/green] Found [bold]{count}[/bold] live hosts → [dim]data/live_hosts/{domain}.txt[/dim]")
    return engine.get_results()


def run_phase_ports(domain: str, scan_id: str, live_hosts: list):
    from backend.modules.port_scan import PortScanner
    console.print("\n[bold cyan]🔌 Phase 3 — Port & Service Scan[/bold cyan]")
    engine = PortScanner(domain, scan_id)
    count = engine.run(live_hosts)
    sensitive = len(engine.get_sensitive_ports())
    console.print(
        f"  [green]✓[/green] Found [bold]{count}[/bold] open ports "
        f"([red]{sensitive} sensitive[/red]) → [dim]data/ports/{domain}.txt[/dim]"
    )
    return engine.get_results()


def run_phase_vulns(domain: str, scan_id: str, live_hosts: list):
    from backend.modules.vuln_scan import VulnerabilityScanner
    console.print("\n[bold cyan]🧨 Phase 4 — Vulnerability Scan[/bold cyan]")
    engine = VulnerabilityScanner(domain, scan_id)
    count = engine.run(live_hosts)
    summary = engine.get_summary()
    critical = summary.get("critical", 0)
    high     = summary.get("high", 0)
    console.print(
        f"  [green]✓[/green] Found [bold]{count}[/bold] findings "
        f"([red]{critical} critical[/red] / [yellow]{high} high[/yellow]) "
        f"→ [dim]data/vulnerabilities/{domain}.txt[/dim]"
    )
    return engine.get_results()


def run_phase_js(domain: str, scan_id: str, live_hosts: list):
    from backend.modules.js_analysis import JsAnalyzer
    console.print("\n[bold cyan]🧠 Phase 5 — JS Intelligence[/bold cyan]")
    engine = JsAnalyzer(domain, scan_id)
    count = engine.run(live_hosts)
    secrets   = len(engine.get_secrets())
    endpoints = len(engine.get_endpoints())
    console.print(
        f"  [green]✓[/green] Found [bold]{count}[/bold] findings "
        f"([red]{secrets} secrets[/red] / [yellow]{endpoints} endpoints[/yellow]) "
        f"→ [dim]data/js_findings/{domain}.txt[/dim]"
    )
    return engine.get_results()


def run_phase_changes(domain: str, scan_id: str, current_data: dict):
    from backend.modules.change_detection import ChangeDetector
    console.print("\n[bold cyan]📊 Phase 6 — Change Detection[/bold cyan]")
    engine = ChangeDetector(domain, scan_id)
    count  = engine.run(current_data)
    if count == 0:
        console.print("  [dim]First scan — baseline saved → data/snapshots/{}.json[/dim]".format(domain))
    else:
        sig = len(engine.get_significant())
        console.print(
            f"  [green]✓[/green] [bold]{count}[/bold] changes detected "
            f"([red]{sig} significant[/red]) → [dim]data/changes/{domain}.txt[/dim]"
        )
    return engine.get_results()


def run_phase_risk(domain: str, scan_id: str, scan_data: dict) -> int:
    from backend.modules.risk_scoring import RiskScorer
    console.print("\n[bold cyan]🎯 Phase 7 — Risk Scoring[/bold cyan]")
    scorer = RiskScorer(domain, scan_id)
    score  = scorer.run(scan_data)
    label  = scorer.get_label()
    color  = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "yellow",
               "LOW": "green", "INFO": "dim"}.get(label, "white")
    console.print(
        f"  [green]✓[/green] Risk score: [{color}][bold]{score}/100  {label}[/bold][/{color}] "
        f"→ [dim]data/risk_scores/{domain}.txt[/dim]"
    )
    return score


def run_phase_alerts(domain: str, scan_id: str, risk_score: int,
                     scan_data: dict, changes: list):
    from backend.modules.alerts import AlertManager
    console.print("\n[bold cyan]🔔 Phase 7b — Alerts[/bold cyan]")
    manager = AlertManager(domain, scan_id)
    sent = manager.run(risk_score, scan_data, changes)
    if sent > 0:
        console.print(f"  [green]✓[/green] Alert sent to [bold]{sent}[/bold] channel(s)")
    else:
        console.print("  [dim]No alerts sent (no channels configured or below threshold)[/dim]")
    return sent


def run_phase_screenshots(domain: str, scan_id: str, live_hosts: list):
    from backend.modules.screenshots import ScreenshotEngine
    console.print("\n[bold cyan]🖼️  Phase 8 — Screenshots[/bold cyan]")
    engine = ScreenshotEngine(domain, scan_id)
    captured = engine.run(live_hosts)
    console.print(
        f"  [green]✓[/green] [bold]{captured}[/bold] screenshot(s) captured "
        f"→ [dim]data/screenshots/{domain}/[/dim]"
    )
    return engine.get_results()


# ─────────────────────────────────────────────────────────────
# SCAN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────

def run_scan(domain: str, mode: str):
    scan_id   = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    phases    = MODES[mode]["phases"]
    start     = datetime.now()

    # Register target + scan in DB so FK constraints are satisfied
    try:
        with get_db_context() as db:
            existing = db.query(Target).filter(Target.domain == domain).first()
            if existing:
                target_id = existing.id
            else:
                t = Target(id=target_id, domain=domain, status="active")
                db.add(t)
                db.flush()
            scan = Scan(id=scan_id, target_id=target_id, scan_type=mode, status="running", start_time=start)
            db.add(scan)
    except Exception as e:
        console.print(f"[yellow]⚠ DB registration skipped: {e}[/yellow]")

    console.rule(f"[bold cyan]Scanning: {domain}[/bold cyan]")

    subdomains, live_hosts, ports, vulns, js_findings = [], [], [], [], []
    changes  = []
    risk_score = 0

    if "discovery" in phases:
        subdomains = run_phase_discovery(domain, scan_id)

    if "live_hosts" in phases:
        live_hosts = run_phase_live_hosts(domain, scan_id, subdomains)

    if "ports" in phases:
        ports = run_phase_ports(domain, scan_id, live_hosts)

    if "vulns" in phases:
        vulns = run_phase_vulns(domain, scan_id, live_hosts)

    if "js" in phases:
        js_findings = run_phase_js(domain, scan_id, live_hosts)

    scan_data = {
        "subdomains":      subdomains,
        "live_hosts":      live_hosts,
        "ports":           ports,
        "vulnerabilities": vulns,
        "js_findings":     js_findings,
    }

    if "changes" in phases:
        changes = run_phase_changes(domain, scan_id, scan_data)

    if "risk" in phases:
        risk_score = run_phase_risk(domain, scan_id, scan_data)

    if "alerts" in phases:
        run_phase_alerts(domain, scan_id, risk_score, scan_data, changes)

    if "screenshots" in phases:
        run_phase_screenshots(domain, scan_id, live_hosts)

    from backend.utils.file_storage import save_unified_report
    from backend.utils.report_generator import generate_html_report
    save_unified_report(domain, scan_data)
    report_path = generate_html_report(domain, scan_id, scan_data)

    elapsed = (datetime.now() - start).seconds

    # Mark scan complete in DB
    try:
        with get_db_context() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status   = "completed"
                scan.end_time = datetime.now()
    except Exception:
        pass

    console.print(
        f"\n[bold green]✅ Scan complete[/bold green] — "
        f"{domain} | {elapsed}s | Mode: {MODES[mode]['label']}"
    )
    console.print(f"  [dim]Results in: data/ folder[/dim]")
    console.print(f"  [bold cyan]Visual Report: {report_path}[/bold cyan]\n")


# ─────────────────────────────────────────────────────────────
# AUTO MODE — SCHEDULER DAEMON
# ─────────────────────────────────────────────────────────────

def load_targets_from_file() -> list:
    """Legacy loader — used for simple non-daemon mode."""
    if not TARGETS_FILE.exists():
        return []
    targets = []
    for line in TARGETS_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if parts:
            targets.append({
                "domain": parts[0] if len(parts) > 0 else "",
                "status": parts[3] if len(parts) > 3 else "active",
            })
    return [t for t in targets if t["status"] == "active" and t["domain"]]


def _print_scheduler_status(summary: dict) -> None:
    """Print a compact status line after each scheduler cycle."""
    console.print(
        f"  [dim]⏱  targets={summary['total_targets']}  "
        f"running={summary['running']}  "
        f"total_runs={summary['total_runs']}[/dim]"
    )


def run_auto_mode(interval: int):
    from backend.modules.scheduler import ScanScheduler

    console.print(Panel(
        "[bold magenta]🤖 Automation Daemon Started[/bold magenta]\n\n"
        f"  Targets file:    [dim]data/targets.txt[/dim]\n"
        f"  State file:      [dim]data/scheduler_state.json[/dim]\n"
        f"  Poll every:      [bold]{interval}s[/bold]\n"
        f"  Max concurrent:  [bold]3[/bold]\n\n"
        "  Add targets:     [dim]edit data/targets.txt[/dim]\n"
        "  Stop:            [dim]Ctrl+C[/dim]",
        title="[bold cyan]ReconXploit — Auto Mode[/bold cyan]",
        border_style="magenta",
    ))

    if not TARGETS_FILE.exists() or not TARGETS_FILE.read_text().strip():
        console.print(
            "[yellow]⚠  No targets found in data/targets.txt[/yellow]\n"
            "[dim]  Add targets with:  python cli.py add example.com[/dim]\n"
        )

    scheduler = ScanScheduler(
        max_concurrent=3,
        poll_interval=interval,
        default_interval_h=24,
    )
    scheduler.start(cycle_callback=_print_scheduler_status)


# ─────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", required=False, default=None)
@click.option(
    "--mode", "-m", default="full",
    type=click.Choice(["full", "passive", "quick", "deep", "auto"]),
    show_default=True,
    help="full=all phases | passive=discovery only | quick=discovery+live | deep=full+brute | auto=daemon",
)
@click.option("--interval", "-i", default=3600, show_default=True,
              help="Poll interval in seconds for --mode auto")
@click.option("--force", "-f", is_flag=True, default=False,
              help="Force immediate re-scan (ignore scheduled next_run time)")
@click.option("--status", is_flag=True, default=False,
              help="Show scheduler status for all targets and exit")
@click.option("--no-banner", is_flag=True, hidden=True)
def main(target, mode, interval, force, status, no_banner):
    """
    \b
    ReconXploit — Automated Recon Platform

    \b
    Examples:
      python reconxp.py target.com                  # Full scan
      python reconxp.py target.com --mode passive   # Passive recon only
      python reconxp.py target.com --mode quick     # Quick scan
      python reconxp.py target.com --mode deep      # Deep scan
      python reconxp.py --mode auto                 # Daemon on all targets
      python reconxp.py --mode auto --interval 1800 # Poll every 30 minutes
      python reconxp.py --status                    # Show scheduler status
      python reconxp.py target.com --force          # Force immediate rescan
    """
    if not no_banner:
        print_banner()

    from backend.core.config import settings
    if not settings.is_root:
        console.print("[yellow]⚠  Running as non-root. Some nmap features (OS detection, UDP scan) will be disabled.[/yellow]")
        console.print("[dim]   Run with 'sudo' for full capabilities.[/dim]\n")

    # Show scheduler status table
    if status:
        _print_status_table()
        return

    if mode == "auto":
        if target:
            console.print("[yellow]--mode auto runs on ALL targets from data/targets.txt (ignoring argument)[/yellow]\n")
        print_mode_info("auto")
        run_auto_mode(interval=interval)
        return

    if not target:
        console.print("[bold red]Please provide a target domain.[/bold red]")
        console.print("\n  python reconxp.py example.com")
        console.print("  python reconxp.py example.com --mode passive")
        console.print("  python reconxp.py --mode auto\n")
        sys.exit(1)

    if force:
        console.print(f"[bold yellow]⚡ Force rescan: {target}[/bold yellow]\n")

    print_mode_info(mode, target)
    run_scan(target, mode)


def _print_status_table():
    """Print a rich table of scheduler status for all known targets."""
    from backend.modules.scheduler import SchedulerState
    from rich.table import Table

    state = SchedulerState()
    rows  = []
    now   = datetime.utcnow()

    for domain, info in sorted(state.all_targets().items()):
        next_run = info.get("next_run")
        if next_run:
            try:
                eta = datetime.fromisoformat(next_run) - now
                total_s = int(eta.total_seconds())
                if total_s < 0:
                    eta_str = "[red]OVERDUE[/red]"
                else:
                    h, rem = divmod(total_s, 3600)
                    m, _   = divmod(rem, 60)
                    eta_str = f"{h}h {m}m" if h else f"{m}m"
            except ValueError:
                eta_str = "?"
        else:
            eta_str = "[yellow]DUE NOW[/yellow]"

        score = info.get("last_score", 0)
        score_color = "red" if score >= 80 else "yellow" if score >= 40 else "green"

        rows.append((
            domain,
            info.get("mode", "full"),
            info.get("status", "idle"),
            info.get("last_run", "never"),
            eta_str,
            f"[{score_color}]{score}[/{score_color}]",
            str(info.get("run_count", 0)),
        ))

    table = Table(title="Scheduler Status", box=box.ROUNDED, show_lines=True)
    table.add_column("Domain",      style="bold cyan", no_wrap=True)
    table.add_column("Mode",        style="dim")
    table.add_column("Status",      style="bold")
    table.add_column("Last Run",    style="dim")
    table.add_column("Next In",     justify="right")
    table.add_column("Score",       justify="center")
    table.add_column("Runs",        justify="right", style="dim")

    for row in rows:
        table.add_row(*row)

    if not rows:
        console.print("[dim]No targets scheduled yet. Add targets to data/targets.txt[/dim]")
    else:
        console.print(table)


if __name__ == "__main__":
    main()
