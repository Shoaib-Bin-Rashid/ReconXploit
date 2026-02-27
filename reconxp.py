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
        "phases": ["discovery", "live_hosts", "ports", "vulns", "js", "changes"],
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
        "phases": ["discovery", "live_hosts", "ports", "vulns", "js", "changes"],
        "description": "Full scan + brute force wordlists. Thorough but slow.",
    },
    "auto": {
        "label": "Automation Daemon",
        "color": "bold magenta",
        "phases": ["discovery", "live_hosts", "ports", "vulns", "js", "changes"],
        "description": "Runs continuously on all targets. Respects schedules.",
    },
}

PHASE_LABELS = {
    "discovery":  ("🔍", "Subdomain Discovery",   "subfinder, assetfinder, amass, findomain, crt.sh"),
    "live_hosts": ("🌐", "Live Host Validation",  "httpx — status, title, WAF, CDN, TLS"),
    "ports":      ("🔌", "Port & Service Scan",   "naabu + nmap"),
    "vulns":      ("🧨", "Vulnerability Scan",    "nuclei"),
    "js":         ("🧠", "JS Intelligence",       "linkfinder, secretfinder, gau"),
    "changes":    ("📊", "Change Detection",      "diff vs last scan"),
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


# ─────────────────────────────────────────────────────────────
# SCAN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────

def run_scan(domain: str, mode: str):
    scan_id = str(uuid.uuid4())
    phases  = MODES[mode]["phases"]
    start   = datetime.now()

    console.rule(f"[bold cyan]Scanning: {domain}[/bold cyan]")

    subdomains, live_hosts, ports, vulns, js_findings = [], [], [], [], []

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

    if "changes" in phases:
        run_phase_changes(domain, scan_id, {
            "subdomains":      subdomains,
            "live_hosts":      live_hosts,
            "ports":           ports,
            "vulnerabilities": vulns,
            "js_findings":     js_findings,
        })

    elapsed = (datetime.now() - start).seconds
    console.print(
        f"\n[bold green]✅ Scan complete[/bold green] — "
        f"{domain} | {elapsed}s | Mode: {MODES[mode]['label']}"
    )
    console.print(f"  [dim]Results in: data/ folder[/dim]\n")


# ─────────────────────────────────────────────────────────────
# AUTO MODE — DAEMON
# ─────────────────────────────────────────────────────────────

def load_targets_from_file() -> list:
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
                "domain":  parts[0] if len(parts) > 0 else "",
                "status":  parts[3] if len(parts) > 3 else "active",
            })
    return [t for t in targets if t["status"] == "active" and t["domain"]]


def run_auto_mode(interval: int):
    console.print(Panel(
        "[bold magenta]🤖 Automation Daemon Started[/bold magenta]\n\n"
        f"  Targets file: [dim]data/targets.txt[/dim]\n"
        f"  Cycle every:  [bold]{interval}s[/bold]\n\n"
        "  Stop:         [dim]Ctrl+C[/dim]",
        title="[bold cyan]ReconXploit — Auto Mode[/bold cyan]",
        border_style="magenta",
    ))
    cycle = 0
    try:
        while True:
            cycle += 1
            targets = load_targets_from_file()
            if not targets:
                console.print("[yellow]No active targets in data/targets.txt — waiting...[/yellow]")
            else:
                console.rule(f"[magenta]Cycle #{cycle} — {len(targets)} targets — {datetime.now().strftime('%H:%M:%S')}[/magenta]")
                for t in targets:
                    run_scan(t["domain"], "full")
            console.print(f"[dim]Next cycle in {interval}s. Ctrl+C to stop.[/dim]")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Automation stopped.[/bold yellow]")


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
              help="Seconds between cycles in --mode auto")
@click.option("--no-banner", is_flag=True, hidden=True)
def main(target, mode, interval, no_banner):
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
      python reconxp.py --mode auto --interval 1800 # Every 30 minutes
    """
    if not no_banner:
        print_banner()

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

    print_mode_info(mode, target)
    run_scan(target, mode)


if __name__ == "__main__":
    main()
