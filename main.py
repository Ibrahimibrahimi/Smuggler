#!/usr/bin/env python3
"""
██╗  ██╗████████╗████████╗██████╗      ███████╗███╗   ███╗██╗   ██╗ ██████╗  ██████╗ ██╗     ███████╗██████╗
██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗     ██╔════╝████╗ ████║██║   ██║██╔════╝ ██╔════╝ ██║     ██╔════╝██╔══██╗
███████║   ██║      ██║   ██████╔╝     ███████╗██╔████╔██║██║   ██║██║  ███╗██║  ███╗██║     █████╗  ██████╔╝
██╔══██║   ██║      ██║   ██╔═══╝      ╚════██║██║╚██╔╝██║██║   ██║██║   ██║██║   ██║██║     ██╔══╝  ██╔══██╗
██║  ██║   ██║      ██║   ██║          ███████║██║ ╚═╝ ██║╚██████╔╝╚██████╔╝╚██████╔╝███████╗███████╗██║  ██║
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝          ╚══════╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝

HTTP Request Smuggling Vulnerability Scanner
For authorized security testing and bug bounty hunting only.
"""

import sys
import os
import click
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import box
from rich.syntax import Syntax
from rich.live import Live
from rich.layout import Layout
from rich.padding import Padding

console = Console()

# ── Banner ─────────────────────────────────────────────────────────────────────
BANNER = """[bold cyan]
  ██╗  ██╗████████╗████████╗██████╗     ███████╗███╗   ███╗██╗   ██╗ ██████╗  ██████╗ ██╗     ███████╗██████╗
  ██║  ██║╚══██╔══╝╚══██╔══╝██╔══██╗    ██╔════╝████╗ ████║██║   ██║██╔════╝ ██╔════╝ ██║     ██╔════╝██╔══██╗
  ███████║   ██║      ██║   ██████╔╝    ███████╗██╔████╔██║██║   ██║██║  ███╗██║  ███╗██║     █████╗  ██████╔╝
  ██╔══██║   ██║      ██║   ██╔═══╝     ╚════██║██║╚██╔╝██║██║   ██║██║   ██║██║   ██║██║     ██╔══╝  ██╔══██╗
  ██║  ██║   ██║      ██║   ██║         ███████║██║ ╚═╝ ██║╚██████╔╝╚██████╔╝╚██████╔╝███████╗███████╗██║  ██║
  ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝         ╚══════╝╚═╝     ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝
[/bold cyan]"""

VERSION = "1.0.0"

SEVERITY_STYLE = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "bold magenta",
    "low":      "bold blue",
}

CONFIDENCE_STYLE = {
    "confirmed":     "bold green",
    "likely":        "green",
    "possible":      "yellow",
    "false_positive":"dim",
}

TECHNIQUES_ALL = ["CL.TE", "TE.CL", "TE.TE", "H2.CL", "H2.TE", "H2.RL", "CRLF"]


# ── Utility prints ─────────────────────────────────────────────────────────────
def print_banner():
    console.print(BANNER)
    console.print(
        f"  [dim]v{VERSION}[/dim]  [bold cyan]HTTP Request Smuggling Scanner[/bold cyan]  "
        f"[dim]· For authorized testing only ·[/dim]\n"
    )


def print_info(msg: str):    console.print(f"  [bold cyan]ℹ[/bold cyan]  {msg}")
def print_success(msg: str): console.print(f"  [bold green]✓[/bold green]  {msg}")
def print_warn(msg: str):    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")
def print_error(msg: str):   console.print(f"  [bold red]✗[/bold red]  {msg}")
def print_step(msg: str):    console.print(f"  [bold blue]→[/bold blue]  {msg}")


# ── Target info panel ──────────────────────────────────────────────────────────
def print_target_info(target_info, url: str):
    from rich.columns import Columns
    items = [
        f"[dim]URL[/dim]         [cyan]{url}[/cyan]",
        f"[dim]WAF / CDN[/dim]   [yellow]{target_info.waf or 'None detected'}[/yellow]",
        f"[dim]Backend[/dim]     [cyan]{target_info.backend or 'Unknown'}[/cyan]",
        f"[dim]HTTP/2[/dim]      {'[green]✓ Supported[/green]' if target_info.supports_h2 else '[dim]✗ Not detected[/dim]'}",
        f"[dim]Baseline RTT[/dim] [white]{target_info.baseline_time:.3f}s[/white]",
    ]
    panel_text = "\n".join(items)
    console.print(Panel(panel_text, title="[bold]Target Info[/bold]", border_style="cyan", padding=(1, 2)))


# ── Findings table ─────────────────────────────────────────────────────────────
def print_findings_table(findings):
    if not findings:
        console.print(Panel(
            "[bold green]✓  No vulnerabilities detected[/bold green]\n"
            "[dim]All tested techniques returned clean results.[/dim]",
            border_style="green", padding=(1, 2),
        ))
        return

    table = Table(
        title=f"[bold red]⚠  {len(findings)} Finding(s) Detected[/bold red]",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold white on #1a1a2e",
        show_lines=True,
        padding=(0, 1),
    )

    table.add_column("Technique",   style="bold magenta", width=10)
    table.add_column("Finding",     style="white",         width=28)
    table.add_column("Severity",    justify="center",      width=10)
    table.add_column("Confidence",  justify="center",      width=12)
    table.add_column("Evidence",    style="dim",           width=38)
    table.add_column("RTT",         justify="right",       width=8)

    for f in findings:
        sev_style  = SEVERITY_STYLE.get(f.severity, "white")
        conf_style = CONFIDENCE_STYLE.get(f.confidence.value, "white")

        table.add_row(
            f"[bold cyan]{f.technique}[/bold cyan]",
            f.payload_name,
            f"[{sev_style}]{f.severity.upper()}[/{sev_style}]",
            f"[{conf_style}]{f.confidence.value.capitalize()}[/{conf_style}]",
            f.evidence[:60] + ("…" if len(f.evidence) > 60 else ""),
            f"[yellow]{f.elapsed:.2f}s[/yellow]",
        )

    console.print(table)
    console.print()

    # Print remediation for each finding
    for i, f in enumerate(findings, 1):
        console.print(Panel(
            f"[bold white]{f.description}[/bold white]\n\n"
            f"[bold green]🛡  Remediation:[/bold green]\n[dim]{f.remediation}[/dim]\n\n"
            + (f"[bold cyan]References:[/bold cyan]\n" + "\n".join(f"  • {r}" for r in f.references) if f.references else ""),
            title=f"[bold]Finding #{i} — {f.payload_name}[/bold]",
            border_style=SEVERITY_STYLE.get(f.severity, "white"),
            padding=(1, 2),
        ))


# ── Final summary ──────────────────────────────────────────────────────────────
def print_summary(results, generated_reports: dict, duration: float):
    total      = len(results)
    vulnerable = sum(1 for r in results if r.is_vulnerable)
    clean      = total - vulnerable
    critical   = sum(r.critical_count for r in results)
    high       = sum(r.high_count for r in results)
    total_reqs = sum(r.total_requests for r in results)

    console.print(Rule("[bold]Scan Summary[/bold]", style="cyan"))
    console.print()

    stat_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 3))
    stat_table.add_column("Label",  style="dim")
    stat_table.add_column("Value",  style="bold white")

    stat_table.add_row("Targets scanned",    str(total))
    stat_table.add_row("Vulnerable",         f"[bold red]{vulnerable}[/bold red]" if vulnerable else f"[green]{vulnerable}[/green]")
    stat_table.add_row("Clean",              f"[green]{clean}[/green]")
    stat_table.add_row("Critical findings",  f"[bold red]{critical}[/bold red]" if critical else str(critical))
    stat_table.add_row("High findings",      f"[bold yellow]{high}[/bold yellow]" if high else str(high))
    stat_table.add_row("Total requests",     str(total_reqs))
    stat_table.add_row("Scan duration",      f"{duration:.1f}s")

    console.print(stat_table)
    console.print()

    if generated_reports:
        console.print("[bold cyan]Generated Reports:[/bold cyan]")
        for fmt, path in generated_reports.items():
            icon = {"json": "📄", "html": "🌐", "pdf": "📋"}.get(fmt, "📁")
            if path.startswith("ERROR"):
                console.print(f"  {icon} [dim]{fmt.upper()}[/dim]  [red]{path}[/red]")
            else:
                console.print(f"  {icon} [dim]{fmt.upper()}[/dim]  [cyan]{path}[/cyan]")
        console.print()

    if vulnerable:
        console.print(Panel(
            f"[bold red]⚠  {vulnerable} target(s) appear vulnerable to HTTP Request Smuggling.[/bold red]\n"
            "[dim]Review findings and apply recommended remediations before reporting.\n"
            "Always confirm findings manually before submitting to bug bounty programs.[/dim]",
            border_style="red", padding=(1, 2),
        ))
    else:
        console.print(Panel(
            "[bold green]✓  All targets returned clean results.[/bold green]\n"
            "[dim]No request smuggling vulnerabilities detected with the tested techniques.[/dim]",
            border_style="green", padding=(1, 2),
        ))


# ── Auth flow ──────────────────────────────────────────────────────────────────
def handle_auth(auth_config_path: Optional[str], verbose: int):
    """Load existing auth config or launch GUI to collect one"""
    from config.manager import load_auth_config, auth_config_exists, get_auth_config_path
    from gui.auth_window import launch_auth_gui

    existing = None
    if auth_config_path:
        existing = load_auth_config(auth_config_path)
        if existing:
            print_success(f"Loaded auth config from [cyan]{auth_config_path}[/cyan]")
    elif auth_config_exists():
        existing = load_auth_config()
        if existing:
            console.print(f"  [dim]Found saved auth config ({get_auth_config_path()})[/dim]")
            use_saved = click.confirm("  Use saved auth config?", default=True)
            if not use_saved:
                existing = None

    print_step("Launching Auth GUI — configure headers, cookies, and tokens…")
    auth = launch_auth_gui(existing_config=existing)

    if auth is None:
        print_warn("Auth GUI cancelled — scanning without authentication")
        return None

    print_success("Auth config saved and ready")

    if verbose >= 1:
        header_count = len(auth.headers)
        cookie_count = len(auth.cookies)
        has_token    = bool(auth.token)
        console.print(f"  [dim]Headers: {header_count} · Cookies: {cookie_count} · Token: {'Yes' if has_token else 'No'} · Proxy: {'Yes' if auth.proxy_enabled else 'No'}[/dim]")

    return auth


# ── Main scan runner ───────────────────────────────────────────────────────────
def run_scan(targets: List[str], cfg, verbose: int) -> List:
    from scanner.core import SmuggleScanner

    scanner  = SmuggleScanner(cfg)
    all_results = []

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=32, style="cyan", complete_style="bold cyan"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:

        overall_task = progress.add_task(
            f"[cyan]Scanning {len(targets)} target(s)…", total=len(targets)
        )

        for url in targets:
            target_task = progress.add_task(f"[dim]{url}[/dim]", total=100)

            def progress_cb(msg: str, done: int, total: int, t=target_task, u=url):
                pct = int((done / max(total, 1)) * 100)
                progress.update(t, description=f"[dim]{u}[/dim] → [cyan]{msg}[/cyan]", completed=pct)

            result = scanner.scan(url, progress_cb=progress_cb)
            all_results.append(result)
            progress.update(target_task, completed=100)
            progress.advance(overall_task)

            # Print per-target result inline
            console.print()
            if result.is_vulnerable:
                console.print(f"  [bold red]⚠  {url}[/bold red]  [red]{len(result.findings)} finding(s)[/red]")
            else:
                console.print(f"  [green]✓[/green]  [dim]{url}[/dim]  [green]clean[/green]")

    return all_results


# ── CLI Definition ─────────────────────────────────────────────────────────────
@click.group(invoke_without_command=True, context_settings=dict(help_option_names=["-h", "--help"]))
@click.pass_context
def cli(ctx):
    """
    \b
    HTTP Request Smuggling Scanner
    ─────────────────────────────────────────────────────────
    Detects CL.TE · TE.CL · TE.TE · H2 · CRLF vulnerabilities
    For authorized security testing and bug bounty hunting only.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())


@cli.command("scan")
@click.option("--target",   "-t",  default=None,   help="Single target URL to scan")
@click.option("--targets",  "-T",  default=None,   help="File with one URL per line")
@click.option("--auth",     "-a",  is_flag=True,   help="Enable auth mode — opens GUI to configure credentials")
@click.option("--auth-config",     default=None,   help="Path to saved auth config YAML (skips GUI)")
@click.option("--techniques",      default=None,   help=f"Comma-separated techniques [{', '.join(TECHNIQUES_ALL)}] (default: all)")
@click.option("--timeout",  "-to", default=10.0,   help="Request timeout in seconds (default: 10)")
@click.option("--threads",  "-th", default=5,      help="Concurrent threads for batch scanning (default: 5)")
@click.option("--delay",    "-d",  default=0.3,    help="Delay between requests in seconds (default: 0.3)")
@click.option("--output",   "-o",  default="./results", help="Output directory for reports (default: ./results)")
@click.option("--format",   "-f",  default="json,html",  help="Report formats: json,html,pdf (default: json,html)")
@click.option("--verbose",  "-v",  count=True,     help="Verbosity: -v (verbose) -vv (debug)")
@click.option("--no-banner",       is_flag=True,   help="Suppress banner")
@click.option("--config",          default=None,   help="Path to scan config YAML file")
def scan(
    target, targets, auth, auth_config, techniques,
    timeout, threads, delay, output, format,
    verbose, no_banner, config,
):
    """
    \b
    Scan one or more targets for HTTP Request Smuggling vulnerabilities.

    \b
    Examples:
      smuggler scan -t https://example.com
      smuggler scan -t https://example.com --auth
      smuggler scan -T targets.txt --format json,html,pdf
      smuggler scan -t https://example.com --techniques CL.TE,TE.CL -v
      smuggler scan -t https://example.com --auth-config ~/.http-smuggler/auth_config.yaml
    """
    import time as _time
    from config.manager import build_scan_config

    if not no_banner:
        print_banner()

    # ── Validate input ──
    if not target and not targets:
        print_error("No target specified. Use [cyan]--target[/cyan] or [cyan]--targets[/cyan]")
        raise click.UsageError("Provide --target or --targets")

    # ── Parse techniques ──
    technique_list = TECHNIQUES_ALL
    if techniques:
        technique_list = [t.strip().upper() for t in techniques.split(",")]
        invalid = [t for t in technique_list if t not in TECHNIQUES_ALL]
        if invalid:
            print_error(f"Unknown techniques: {', '.join(invalid)}")
            print_info(f"Available: {', '.join(TECHNIQUES_ALL)}")
            raise click.UsageError("Invalid techniques specified")

    # ── Parse formats ──
    format_list = [f.strip().lower() for f in format.split(",")]

    # ── Auth ──
    auth_cfg = None
    if auth:
        console.print()
        console.print(Rule("[bold cyan]Authentication[/bold cyan]", style="cyan"))
        console.print()
        auth_cfg = handle_auth(auth_config, verbose)
    elif auth_config:
        from config.manager import load_auth_config
        auth_cfg = load_auth_config(auth_config)
        if auth_cfg:
            print_success(f"Loaded auth config from [cyan]{auth_config}[/cyan]")
        else:
            print_warn(f"Could not load auth config from [cyan]{auth_config}[/cyan] — scanning unauthenticated")

    # ── Build config ──
    cfg = build_scan_config(
        target=target,
        targets_file=targets,
        techniques=technique_list,
        timeout=timeout,
        threads=threads,
        output_dir=output,
        output_formats=format_list,
        verbose=verbose,
        auth=auth_cfg,
        config_file=config,
        delay=delay,
    )

    # ── Collect targets ──
    from scanner.core import SmuggleScanner
    scanner = SmuggleScanner(cfg)

    url_list: List[str] = []
    if target:
        url = target if target.startswith(("http://", "https://")) else "https://" + target
        url_list.append(url)
    if targets:
        try:
            url_list.extend(scanner.load_targets_from_file(targets))
            print_success(f"Loaded [cyan]{len(url_list)}[/cyan] targets from [dim]{targets}[/dim]")
        except FileNotFoundError:
            print_error(f"Targets file not found: [cyan]{targets}[/cyan]")
            sys.exit(1)

    if not url_list:
        print_error("No valid targets found")
        sys.exit(1)

    # ── Scan info panel ──
    console.print()
    console.print(Rule("[bold cyan]Scan Configuration[/bold cyan]", style="cyan"))
    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info_table.add_column("Key",   style="dim")
    info_table.add_column("Value", style="white")
    info_table.add_row("Targets",    str(len(url_list)))
    info_table.add_row("Techniques", "[cyan]" + "  ".join(technique_list) + "[/cyan]")
    info_table.add_row("Timeout",    f"{timeout}s")
    info_table.add_row("Threads",    str(threads))
    info_table.add_row("Auth",       "[green]✓ Enabled[/green]" if auth_cfg else "[dim]✗ Disabled[/dim]")
    info_table.add_row("Output",     f"[dim]{output}[/dim]")
    info_table.add_row("Formats",    ", ".join(format_list).upper())
    console.print(info_table)
    console.print()

    # ── Confirmation for large batch ──
    if len(url_list) > 10:
        if not click.confirm(f"  About to scan {len(url_list)} targets. Continue?", default=True):
            console.print("  [dim]Scan aborted.[/dim]")
            return

    console.print(Rule("[bold cyan]Scanning[/bold cyan]", style="cyan"))
    console.print()

    start_time = _time.time()
    results = run_scan(url_list, cfg, verbose)
    duration = _time.time() - start_time

    # ── Detailed per-target output ──
    console.print()
    console.print(Rule("[bold]Detailed Results[/bold]", style="cyan"))

    for result in results:
        console.print()
        console.print(f"  [bold cyan]Target:[/bold cyan] [white]{result.target}[/white]")

        if not result.target_info or not result.target_info.reachable:
            print_error(f"Target unreachable: {result.errors}")
            continue

        if verbose >= 1:
            print_target_info(result.target_info, result.target)

        print_findings_table(result.findings)

        if result.errors and verbose >= 1:
            console.print(f"  [dim]Errors: {'; '.join(result.errors[:3])}[/dim]")

    # ── Reports ──
    console.print()
    console.print(Rule("[bold]Reports[/bold]", style="cyan"))
    from reports.generators import generate_reports
    generated = generate_reports(results, output, format_list)

    # ── Summary ──
    console.print()
    print_summary(results, generated, duration)
    console.print()


@cli.command("list-techniques")
def list_techniques():
    """List all supported smuggling techniques and their descriptions"""
    print_banner()
    from payloads.database import ALL_PAYLOADS, TECHNIQUES

    table = Table(
        title="Supported Techniques & Payloads",
        box=box.ROUNDED, border_style="cyan",
        header_style="bold white on #1a1a2e",
        show_lines=True, padding=(0, 1),
    )
    table.add_column("Technique",   style="bold magenta", width=12)
    table.add_column("Payload",     style="white",         width=30)
    table.add_column("Severity",    justify="center",      width=10)
    table.add_column("Description", style="dim",           width=52)

    for technique, payloads in TECHNIQUES.items():
        for p in payloads:
            sev_style = SEVERITY_STYLE.get(p.severity, "white")
            table.add_row(
                f"[cyan]{technique}[/cyan]",
                p.name,
                f"[{sev_style}]{p.severity.upper()}[/{sev_style}]",
                p.description[:80],
            )

    console.print(table)
    console.print(f"\n  [dim]Total: {len(ALL_PAYLOADS)} payloads across {len(TECHNIQUES)} techniques[/dim]\n")


@cli.command("auth")
@click.option("--save-only", is_flag=True, help="Just save the config without scanning")
@click.option("--show",      is_flag=True, help="Display current saved auth config")
@click.option("--clear",     is_flag=True, help="Delete saved auth config")
def auth_cmd(save_only, show, clear):
    """
    Manage authentication configuration (opens GUI editor)

    \b
    Examples:
      smuggler auth           # Open GUI to create/edit auth config
      smuggler auth --show    # Display current saved config
      smuggler auth --clear   # Remove saved config
    """
    print_banner()
    from config.manager import (
        load_auth_config, save_auth_config, auth_config_exists, get_auth_config_path,
    )
    from gui.auth_window import launch_auth_gui

    if clear:
        path = get_auth_config_path()
        if path.exists():
            path.unlink()
            print_success(f"Auth config deleted: [cyan]{path}[/cyan]")
        else:
            print_warn("No saved auth config found")
        return

    if show:
        cfg = load_auth_config()
        if not cfg:
            print_warn("No saved auth config found. Run [cyan]smuggler auth[/cyan] to create one.")
            return

        table = Table(title="Saved Auth Config", box=box.ROUNDED, border_style="cyan")
        table.add_column("Key",   style="dim")
        table.add_column("Value", style="white")

        for k, v in cfg.headers.items():
            table.add_row(f"header:{k}", v)
        for k, v in cfg.cookies.items():
            table.add_row(f"cookie:{k}", v)
        if cfg.token:
            table.add_row("token_type", cfg.token_type)
            table.add_row("token",      "•" * min(len(cfg.token), 20) + "…" if len(cfg.token) > 8 else "•" * len(cfg.token))
        table.add_row("proxy", f"{'✓ ' + cfg.proxy_url if cfg.proxy_enabled else '✗ Disabled'}")
        table.add_row("ssl_verify", str(cfg.ssl_verify))
        table.add_row("saved_at",   cfg.saved_at)

        console.print(table)
        return

    existing = load_auth_config()
    if existing:
        print_info(f"Editing existing config from [cyan]{get_auth_config_path()}[/cyan]")

    print_step("Opening Auth GUI…")
    result = launch_auth_gui(existing_config=existing)

    if result:
        save_auth_config(result)
        print_success(f"Auth config saved to [cyan]{get_auth_config_path()}[/cyan]")
    else:
        print_warn("Auth GUI closed without saving")


@cli.command("version")
def version_cmd():
    """Show version information"""
    console.print(f"\n  [bold cyan]HTTP Request Smuggler[/bold cyan] [dim]v{VERSION}[/dim]\n")


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Allow running as: python main.py scan ...
    cli()
