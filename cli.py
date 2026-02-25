"""
ReconXploit - CLI Interface
Entry point for running scans from the command line
"""

import click
import sys
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from datetime import datetime

console = Console()

BANNER = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗██████╗ ██╗      ██████╗ ██╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ ██████╔╝██║     ██║   ██║██║   ██║   
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ ██╔═══╝ ██║     ██║   ██║██║   ██║   
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗██║     ███████╗╚██████╔╝██║   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
"""


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print("[bold cyan]  Ultimate Automated Recon Platform[/bold cyan]")
    console.print("[dim]  v0.1.0 | Bug Bounty Intelligence Engine[/dim]\n")


@click.group()
@click.version_option(version="0.1.0", prog_name="ReconXploit")
def cli():
    """
    \b
    ReconXploit - Ultimate Automated Recon Platform
    Automate 90% of your bug bounty reconnaissance workflow.
    """
    pass


# ─────────────────────────────────────────────
# TEXT FILE HELPERS  (data/targets.txt)
# ─────────────────────────────────────────────

TARGETS_FILE = Path(__file__).parent / "data" / "targets.txt"


def _ensure_targets_file():
    """Create data/targets.txt with a header if it doesn't exist."""
    TARGETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not TARGETS_FILE.exists():
        TARGETS_FILE.write_text(
            "# ReconXploit — Target List\n"
            "# Format: domain | organization | description | status | added_date\n"
            "# You can edit this file manually. One target per line.\n"
            "# Lines starting with # are comments and are ignored.\n\n"
        )


def _save_target_to_file(domain: str, org: str = None, description: str = None, status: str = "active"):
    """Append a new target line to data/targets.txt."""
    _ensure_targets_file()
    added = datetime.now().strftime("%Y-%m-%d %H:%M")
    org = org or ""
    description = description or ""
    line = f"{domain} | {org} | {description} | {status} | {added}\n"
    with open(TARGETS_FILE, "a") as f:
        f.write(line)


def _remove_target_from_file(domain: str):
    """Remove a target line from data/targets.txt by domain."""
    if not TARGETS_FILE.exists():
        return
    lines = TARGETS_FILE.read_text().splitlines(keepends=True)
    new_lines = [l for l in lines if l.startswith("#") or not l.startswith(domain)]
    TARGETS_FILE.write_text("".join(new_lines))


# ─────────────────────────────────────────────
# TARGET MANAGEMENT
# ─────────────────────────────────────────────

@cli.command("add-target")
@click.argument("domain")
@click.option("--org", "-o", help="Organization name", default=None)
@click.option("--schedule", "-s", help="Cron schedule (e.g. '0 2 * * *')", default=None)
@click.option("--description", "-d", help="Description", default=None)
def add_target(domain: str, org: str, schedule: str, description: str):
    """Add a new reconnaissance target."""
    print_banner()

    from backend.models.database import get_db_context, check_connection
    from backend.models.models import Target

    if not check_connection():
        # DB not available — save to text file only
        console.print("[yellow]⚠ Database not connected. Saving to data/targets.txt only.[/yellow]")
        _save_target_to_file(domain, org, description)
        console.print(Panel(
            f"[bold yellow]✅ Target saved to data/targets.txt[/bold yellow]\n\n"
            f"  [bold]Domain:[/bold]       {domain}\n"
            f"  [bold]Organization:[/bold] {org or 'N/A'}\n"
            f"  [bold]File:[/bold]         data/targets.txt",
            title="[bold cyan]ReconXploit[/bold cyan]",
            border_style="yellow"
        ))
        return

    with get_db_context() as db:
        existing = db.query(Target).filter(Target.domain == domain).first()
        if existing:
            console.print(f"[yellow]⚠ Target [bold]{domain}[/bold] already exists (ID: {existing.id})[/yellow]")
            return

        target = Target(
            domain=domain,
            organization=org,
            description=description,
            scan_schedule=schedule,
            status="active",
        )
        db.add(target)
        db.flush()

        # Also save to data/targets.txt
        _save_target_to_file(domain, org, description)

        console.print(Panel(
            f"[bold green]✅ Target Added Successfully[/bold green]\n\n"
            f"  [bold]Domain:[/bold]       {domain}\n"
            f"  [bold]Organization:[/bold] {org or 'N/A'}\n"
            f"  [bold]Schedule:[/bold]     {schedule or 'Manual only'}\n"
            f"  [bold]ID:[/bold]           {target.id}",
            title="[bold cyan]ReconXploit[/bold cyan]",
            border_style="green"
        ))
        console.print(f"\n[dim]Run scan with:[/dim] [bold]python cli.py scan {domain}[/bold]")


@cli.command("list-targets")
@click.option("--status", "-s", default=None, help="Filter by status (active/paused/archived)")
def list_targets(status: str):
    """List all monitored targets."""
    from backend.models.database import get_db_context, check_connection
    from backend.models.models import Target, Scan
    from sqlalchemy import func

    if not check_connection():
        console.print("[bold red]❌ Database connection failed.[/bold red]")
        sys.exit(1)

    with get_db_context() as db:
        query = db.query(Target)
        if status:
            query = query.filter(Target.status == status)
        targets = query.order_by(Target.created_at.desc()).all()

        if not targets:
            console.print("[yellow]No targets found. Add one with: python cli.py add-target example.com[/yellow]")
            return

        table = Table(title="🎯 Monitored Targets", border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Domain", style="bold cyan")
        table.add_column("Organization", style="white")
        table.add_column("Status", style="green")
        table.add_column("Schedule", style="dim")
        table.add_column("Added", style="dim")

        for i, t in enumerate(targets, 1):
            status_color = {
                "active": "[green]● active[/green]",
                "paused": "[yellow]◌ paused[/yellow]",
                "archived": "[dim]✕ archived[/dim]",
            }.get(t.status, t.status)

            table.add_row(
                str(i),
                t.domain,
                t.organization or "-",
                status_color,
                t.scan_schedule or "manual",
                t.created_at.strftime("%Y-%m-%d") if t.created_at else "-",
            )

        console.print(table)
        console.print(f"\n[dim]Total: {len(targets)} target(s)[/dim]")


@cli.command("remove-target")
@click.argument("domain")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def remove_target(domain: str, confirm: bool):
    """Remove a target and all its scan data."""
    from backend.models.database import get_db_context
    from backend.models.models import Target

    if not confirm:
        click.confirm(
            f"⚠ This will delete ALL scan data for {domain}. Continue?",
            abort=True
        )

    with get_db_context() as db:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            console.print(f"[red]❌ Target not found: {domain}[/red]")
            return
        db.delete(target)
        _remove_target_from_file(domain)
        console.print(f"[green]✅ Target removed: {domain}[/green]")


# ─────────────────────────────────────────────
# SCANNING
# ─────────────────────────────────────────────

@cli.command("scan")
@click.argument("domain")
@click.option("--type", "-t", "scan_type", default="full",
              type=click.Choice(["full", "quick", "deep"]),
              help="Scan type (default: full)")
@click.option("--phase", "-p", "phases", multiple=True,
              type=click.Choice(["discovery", "validation", "ports", "vulns", "js", "all"]),
              help="Run specific phases only")
def run_scan(domain: str, scan_type: str, phases: tuple):
    """Run a reconnaissance scan against a target."""
    print_banner()

    from backend.models.database import get_db_context, check_connection
    from backend.models.models import Target, Scan

    if not check_connection():
        console.print("[bold red]❌ Database connection failed.[/bold red]")
        sys.exit(1)

    with get_db_context() as db:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            console.print(f"[yellow]⚠ Target not found. Adding {domain} automatically...[/yellow]")
            target = Target(domain=domain, status="active")
            db.add(target)
            db.flush()

        scan = Scan(
            target_id=target.id,
            scan_type=scan_type,
            status="pending",
            start_time=datetime.utcnow(),
        )
        db.add(scan)
        db.flush()
        scan_id = str(scan.id)
        target_domain = target.domain

    console.print(Panel(
        f"[bold cyan]🚀 Launching Recon Scan[/bold cyan]\n\n"
        f"  [bold]Target:[/bold]    {target_domain}\n"
        f"  [bold]Scan ID:[/bold]   {scan_id}\n"
        f"  [bold]Type:[/bold]      {scan_type}\n"
        f"  [bold]Phases:[/bold]    {', '.join(phases) if phases else 'all'}\n"
        f"  [bold]Started:[/bold]   {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        title="[bold cyan]ReconXploit[/bold cyan]",
        border_style="cyan"
    ))

    # Trigger Celery task
    try:
        from backend.tasks.scan_tasks import run_full_scan
        task = run_full_scan.delay(scan_id, target_domain, scan_type, list(phases))
        console.print(f"\n[green]✅ Scan queued (Celery task: {task.id})[/green]")
        console.print(f"[dim]Monitor with: python cli.py scan-status {scan_id}[/dim]")
    except Exception as e:
        console.print(f"\n[yellow]⚠ Celery not available. Running synchronously...[/yellow]")
        console.print(f"[dim]Error: {e}[/dim]")
        _run_sync(scan_id, target_domain, scan_type)


def _run_sync(scan_id: str, domain: str, scan_type: str):
    """Run scan synchronously when Celery is unavailable."""
    from backend.modules.discovery import SubdomainDiscovery
    from backend.models.database import get_db_context
    from backend.models.models import Scan
    from datetime import datetime

    console.print("\n[bold]Running phases:[/bold]\n")

    phases_run = [
        ("🔍 Phase 1: Asset Discovery", lambda: SubdomainDiscovery(domain, scan_id).run()),
    ]

    for label, fn in phases_run:
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[bold cyan]{label}[/bold cyan]"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task("", total=None)
            try:
                result = fn()
                console.print(f"  [green]✓[/green] {label} — [bold]{result}[/bold] found")
            except Exception as e:
                console.print(f"  [red]✗[/red] {label} — Error: {e}")

    with get_db_context() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "completed"
            scan.end_time = datetime.utcnow()

    console.print(f"\n[bold green]✅ Scan complete![/bold green]")
    console.print(f"[dim]View results: python cli.py show-results {domain}[/dim]")


@cli.command("scan-status")
@click.argument("scan_id")
def scan_status(scan_id: str):
    """Check the status of a running scan."""
    from backend.models.database import get_db_context
    from backend.models.models import Scan, Target

    with get_db_context() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            console.print(f"[red]❌ Scan not found: {scan_id}[/red]")
            return

        status_color = {
            "pending": "[yellow]⏳ pending[/yellow]",
            "running": "[cyan]🔄 running[/cyan]",
            "completed": "[green]✅ completed[/green]",
            "failed": "[red]❌ failed[/red]",
            "cancelled": "[dim]✕ cancelled[/dim]",
        }.get(scan.status, scan.status)

        stats = scan.stats or {}
        console.print(Panel(
            f"[bold]Scan ID:[/bold]    {scan.id}\n"
            f"[bold]Status:[/bold]     {status_color}\n"
            f"[bold]Type:[/bold]       {scan.scan_type}\n"
            f"[bold]Started:[/bold]    {scan.start_time or 'N/A'}\n"
            f"[bold]Finished:[/bold]   {scan.end_time or 'Still running...'}\n\n"
            f"[bold]Stats:[/bold]\n"
            f"  Subdomains:     {stats.get('subdomains_found', 0)}\n"
            f"  Live Hosts:     {stats.get('live_hosts', 0)}\n"
            f"  Open Ports:     {stats.get('open_ports', 0)}\n"
            f"  Vulnerabilities:{stats.get('vulnerabilities', 0)}\n"
            f"  JS Findings:    {stats.get('js_findings', 0)}\n"
            f"  Changes:        {stats.get('changes', 0)}",
            title="[bold cyan]Scan Status[/bold cyan]",
            border_style="cyan"
        ))


# ─────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────

@cli.command("show-results")
@click.argument("domain")
@click.option("--type", "-t", "result_type", default="summary",
              type=click.Choice(["summary", "subdomains", "vulns", "ports", "changes", "js"]),
              help="What to display")
@click.option("--severity", "-s", default=None,
              type=click.Choice(["critical", "high", "medium", "low", "info"]),
              help="Filter vulnerabilities by severity")
@click.option("--json", "output_json", is_flag=True, help="Output as JSON")
def show_results(domain: str, result_type: str, severity: str, output_json: bool):
    """Show reconnaissance results for a target."""
    from backend.models.database import get_db_context
    from backend.models.models import Target, Subdomain, LiveHost, Vulnerability, Port, Change

    with get_db_context() as db:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            console.print(f"[red]❌ Target not found: {domain}[/red]")
            return

        if result_type == "summary":
            _show_summary(db, target)
        elif result_type == "subdomains":
            _show_subdomains(db, target, output_json)
        elif result_type == "vulns":
            _show_vulnerabilities(db, target, severity, output_json)
        elif result_type == "ports":
            _show_ports(db, target, output_json)
        elif result_type == "changes":
            _show_changes(db, target, output_json)


def _show_summary(db, target):
    from backend.models.models import Subdomain, LiveHost, Vulnerability, Port, Change

    subdomain_count = db.query(Subdomain).filter(
        Subdomain.target_id == target.id, Subdomain.is_active == True
    ).count()

    live_count = db.query(LiveHost).join(Subdomain).filter(
        Subdomain.target_id == target.id, LiveHost.is_active == True
    ).count()

    vuln_counts = {}
    for sev in ["critical", "high", "medium", "low"]:
        vuln_counts[sev] = db.query(Vulnerability).join(LiveHost).join(Subdomain).filter(
            Subdomain.target_id == target.id,
            Vulnerability.severity == sev,
            Vulnerability.status == "new"
        ).count()

    change_count = db.query(Change).filter(
        Change.target_id == target.id, Change.is_significant == True
    ).count()

    console.print(Panel(
        f"[bold cyan]🎯 {target.domain}[/bold cyan]\n\n"
        f"  [bold]Subdomains:[/bold]  {subdomain_count}\n"
        f"  [bold]Live Hosts:[/bold]  {live_count}\n\n"
        f"  [bold]Vulnerabilities:[/bold]\n"
        f"    [bold red]Critical:[/bold red] {vuln_counts['critical']}\n"
        f"    [bold orange3]High:[/bold orange3]     {vuln_counts['high']}\n"
        f"    [bold yellow]Medium:[/bold yellow]   {vuln_counts['medium']}\n"
        f"    [bold green]Low:[/bold green]      {vuln_counts['low']}\n\n"
        f"  [bold]Significant Changes:[/bold] {change_count}",
        title="[bold]Recon Summary[/bold]",
        border_style="cyan"
    ))


def _show_subdomains(db, target, output_json: bool):
    from backend.models.models import Subdomain

    subs = db.query(Subdomain).filter(
        Subdomain.target_id == target.id, Subdomain.is_active == True
    ).order_by(Subdomain.subdomain).all()

    if output_json:
        data = [{"subdomain": s.subdomain, "ip": str(s.ip_address), "source": s.source} for s in subs]
        click.echo(json.dumps(data, indent=2))
        return

    table = Table(title=f"📋 Subdomains — {target.domain}", border_style="cyan")
    table.add_column("Subdomain", style="cyan")
    table.add_column("IP Address", style="white")
    table.add_column("Source", style="dim")
    table.add_column("First Seen", style="dim")

    for s in subs:
        table.add_row(
            s.subdomain,
            str(s.ip_address) if s.ip_address else "-",
            s.source or "-",
            s.first_seen.strftime("%Y-%m-%d") if s.first_seen else "-",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(subs)} subdomains[/dim]")


def _show_vulnerabilities(db, target, severity_filter: str, output_json: bool):
    from backend.models.models import Vulnerability, LiveHost, Subdomain

    query = db.query(Vulnerability).join(LiveHost).join(Subdomain).filter(
        Subdomain.target_id == target.id, Vulnerability.status == "new"
    )
    if severity_filter:
        query = query.filter(Vulnerability.severity == severity_filter)

    vulns = query.order_by(Vulnerability.severity, Vulnerability.vulnerability_name).all()

    if output_json:
        data = [{
            "name": v.vulnerability_name,
            "severity": v.severity,
            "matched_at": v.matched_at,
            "cve": v.cve_id,
        } for v in vulns]
        click.echo(json.dumps(data, indent=2))
        return

    sev_colors = {
        "critical": "[bold red]CRITICAL[/bold red]",
        "high": "[bold orange3]HIGH[/bold orange3]",
        "medium": "[bold yellow]MEDIUM[/bold yellow]",
        "low": "[bold green]LOW[/bold green]",
        "info": "[dim]INFO[/dim]",
    }

    table = Table(title=f"🧨 Vulnerabilities — {target.domain}", border_style="red")
    table.add_column("Severity", width=10)
    table.add_column("Vulnerability", style="white")
    table.add_column("URL", style="dim")
    table.add_column("CVE", style="dim")

    for v in vulns:
        table.add_row(
            sev_colors.get(v.severity, v.severity),
            v.vulnerability_name,
            (v.matched_at or "-")[:60],
            v.cve_id or "-",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(vulns)} vulnerabilities[/dim]")


def _show_ports(db, target, output_json: bool):
    from backend.models.models import Port, LiveHost, Subdomain

    ports = db.query(Port).join(LiveHost).join(Subdomain).filter(
        Subdomain.target_id == target.id, Port.state == "open"
    ).order_by(Port.ip_address, Port.port).all()

    if output_json:
        data = [{"ip": str(p.ip_address), "port": p.port, "service": p.service_name, "version": p.service_version} for p in ports]
        click.echo(json.dumps(data, indent=2))
        return

    table = Table(title=f"🔌 Open Ports — {target.domain}", border_style="yellow")
    table.add_column("IP Address", style="cyan")
    table.add_column("Port", style="bold white")
    table.add_column("Service", style="white")
    table.add_column("Version", style="dim")
    table.add_column("Sensitive", style="red")

    for p in ports:
        table.add_row(
            str(p.ip_address),
            str(p.port),
            p.service_name or "-",
            (p.service_version or "-")[:40],
            "⚠️" if p.is_sensitive else "",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(ports)} open ports[/dim]")


def _show_changes(db, target, output_json: bool):
    from backend.models.models import Change

    changes = db.query(Change).filter(
        Change.target_id == target.id
    ).order_by(Change.detected_at.desc()).limit(50).all()

    if output_json:
        data = [{
            "type": c.change_type,
            "asset": c.asset_identifier,
            "severity": c.severity,
            "detected_at": c.detected_at.isoformat(),
        } for c in changes]
        click.echo(json.dumps(data, indent=2))
        return

    table = Table(title=f"🔄 Recent Changes — {target.domain}", border_style="blue")
    table.add_column("Type", style="cyan")
    table.add_column("Asset", style="white")
    table.add_column("Severity", width=10)
    table.add_column("Detected", style="dim")

    sev_colors = {
        "critical": "[bold red]CRITICAL[/bold red]",
        "high": "[bold orange3]HIGH[/bold orange3]",
        "medium": "[bold yellow]MEDIUM[/bold yellow]",
        "low": "[dim]LOW[/dim]",
    }

    for c in changes:
        table.add_row(
            c.change_type,
            c.asset_identifier[:60],
            sev_colors.get(c.severity, c.severity),
            c.detected_at.strftime("%Y-%m-%d %H:%M") if c.detected_at else "-",
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(changes)} changes (last 50)[/dim]")


# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

@cli.command("health")
def health_check():
    """Check system health (DB, Redis, Tools)."""
    print_banner()
    console.print("[bold]System Health Check[/bold]\n")

    # Database
    try:
        from backend.models.database import check_connection
        ok = check_connection()
        console.print(f"  {'[green]✓[/green]' if ok else '[red]✗[/red]'} PostgreSQL: {'Connected' if ok else 'FAILED'}")
    except Exception as e:
        console.print(f"  [red]✗[/red] PostgreSQL: {e}")

    # Redis
    try:
        import redis
        from backend.core.config import settings
        r = redis.Redis(host=settings.redis_host, port=settings.redis_port, socket_connect_timeout=2)
        r.ping()
        console.print(f"  [green]✓[/green] Redis: Connected")
    except Exception as e:
        console.print(f"  [red]✗[/red] Redis: {e}")

    # Tools
    import shutil
    tools = ["subfinder", "assetfinder", "amass", "findomain", "httpx", "naabu", "nuclei", "gowitness", "waybackurls", "gau"]
    console.print()
    for tool in tools:
        found = shutil.which(tool) is not None
        console.print(f"  {'[green]✓[/green]' if found else '[yellow]?[/yellow]'} {tool}: {'Found' if found else 'Not found (install with scripts/install_tools.sh)'}")


@cli.command("init-db")
def init_db():
    """Initialize the database schema."""
    from backend.models.database import create_tables, check_connection

    if not check_connection():
        console.print("[red]❌ Cannot connect to PostgreSQL. Check config/settings.yaml[/red]")
        sys.exit(1)

    console.print("[cyan]Creating database tables...[/cyan]")
    create_tables()
    console.print("[bold green]✅ Database initialized successfully![/bold green]")


if __name__ == "__main__":
    cli()
