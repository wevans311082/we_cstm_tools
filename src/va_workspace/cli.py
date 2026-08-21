"""Typer CLI for va-workspace. Thin compositor over core modules."""

from __future__ import annotations

import ssl
import sys
from pathlib import Path

import typer
from rich.table import Table

from va_workspace import __version__
from va_workspace.config.nse import (
    custom_nse_names,
    list_custom_nse,
    packaged_nse_dir,
)
from va_workspace.config.profiles import intensity_or_default, is_privileged
from va_workspace.constants import FindingStatus, Intensity, JobStatus, Mode
from va_workspace.core.compare import write_compare
from va_workspace.core.cvss import CvssError
from va_workspace.core.doctor import collect_doctor
from va_workspace.core.engagement import (
    bootstrap,
    default_out_dir,
    maybe_warn_check_metadata,
    resolve_engagement_dir,
)
from va_workspace.core.findings import add_finding, edit_finding, parse_finding_frontmatter
from va_workspace.core.nmap_runner import ScanPlatformError
from va_workspace.core.pipeline import ingest_xml, run_enum, run_scan
from va_workspace.core.state import save_state, try_load_state, utc_now
from va_workspace.core.templates import load_finding_templates
from va_workspace.core.vault import list_finding_files
from va_workspace.util import log
from va_workspace.util.log import stdout as out_console
from va_workspace.util.net import load_target_args

app = typer.Typer(
    name="va",
    no_args_is_help=True,
    add_completion=False,
    help="Kali operator toolkit: Nmap reconnaissance → CHECK-shaped Obsidian vault.",
)
finding_app = typer.Typer(no_args_is_help=True, help="Operator-authored findings (CVSS 3.1).")
nse_app = typer.Typer(no_args_is_help=True, help="Custom va-*.nse Lua scripts.")
app.add_typer(finding_app, name="finding")
app.add_typer(nse_app, name="nse")


ModeOpt = typer.Option(Mode.LAB, "--mode", help="check | lab | internal")
IntensityOpt = typer.Option(
    None, "--intensity", help="stealth | standard | loud (default depends on --mode)"
)


@app.callback()
def _root(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip non-legal confirmations"),
) -> None:
    """va-workspace."""
    _ = (verbose, yes)


@nse_app.command("path")
def nse_path() -> None:
    """Print the directory of custom va-*.nse Lua files."""
    typer.echo(str(packaged_nse_dir()))


@nse_app.command("list")
def nse_list(
    mode: Mode = ModeOpt,
    intensity: Intensity | None = IntensityOpt,
) -> None:
    """List custom Lua scripts (and which pack they belong to)."""
    resolved = intensity_or_default(mode, intensity)
    selected = set(custom_nse_names(mode, resolved))
    table = Table(title=f"Custom NSE  mode={mode} intensity={resolved}")
    table.add_column("Script")
    table.add_column("This scan")
    for path in list_custom_nse():
        name = path.stem
        table.add_row(name + ".nse", "yes" if name in selected else "no")
    if not list_custom_nse():
        log.warn("no va-*.nse files found — reinstall the package")
        raise typer.Exit(code=1)
    out_console.print(table)
    out_console.print(f"path: {packaged_nse_dir()}")


@app.command()
def version() -> None:
    """Print package version."""
    typer.echo(__version__)


@app.command()
def doctor() -> None:
    """Check binaries, plugin YAML, and wordlists."""
    report = collect_doctor()
    table = Table(title="va doctor")
    table.add_column("Binary")
    table.add_column("Need")
    table.add_column("Status")
    table.add_column("Hint")
    for check in report.checks:
        status = check.version if check.present else "[red]MISSING[/red]"
        need = "required" if check.required else "optional"
        table.add_row(check.name, need, status, check.hint)
    out_console.print(table)
    wl = Table(title="Wordlists")
    wl.add_column("Kind")
    wl.add_column("Path")
    for kind, path in report.wordlists.items():
        wl.add_row(kind, path)
    out_console.print(wl)
    if report.mapping_error:
        log.error(f"tool mappings failed to load: {report.mapping_error}")
        raise typer.Exit(code=1)
    nse_files = list_custom_nse()
    log.info(f"loaded {report.mapping_count} tool mapping(s)")
    log.info(f"custom NSE Lua: {len(nse_files)} script(s) in {packaged_nse_dir()}")
    from va_workspace.core.snap import detect_capture_backend, detect_clipboard_backend

    snap_b = detect_capture_backend() or "missing (apt install maim  or grim+slurp)"
    clip_b = detect_clipboard_backend() or "missing (xclip or wl-copy)"
    log.info(f"screenshot backend: {snap_b}; clipboard: {clip_b}")
    if not sys.platform.startswith("linux"):
        log.warn("this OS is fine for ingest/tests; live va scan requires Kali/Linux")
    if report.required_missing:
        for check in report.required_missing:
            log.error(f"required binary missing: {check.name} ({check.hint})")
        raise typer.Exit(code=1)
    log.success("doctor: required binaries present")


@app.command("init")
def init_cmd(
    client: str = typer.Option(..., "--client", help="Client or engagement short name"),
    mode: Mode = ModeOpt,
    intensity: Intensity | None = IntensityOpt,
    out: Path | None = typer.Option(None, "--out", help="Vault directory"),
    tester: list[str] = typer.Option([], "--tester", help="Repeatable tester name"),
    classification: str = typer.Option("OFFICIAL", "--classification"),
    target: list[str] = typer.Option([], "--target", help="Optional in-scope CIDR/host"),
    exclude: list[str] = typer.Option([], "--exclude"),
) -> None:
    """Create an engagement vault skeleton (recommended for CHECK)."""
    resolved_intensity = intensity_or_default(mode, intensity)
    path = (out or default_out_dir(client)).expanduser()
    state = bootstrap(
        path=path,
        client=client,
        mode=mode,
        intensity=resolved_intensity,
        targets=target,
        excludes=exclude,
        testers=tester,
        classification=classification,
        resume=False,
    )
    maybe_warn_check_metadata(state)
    log.success(f"initialised vault at {state.path}")


def _load_targets(target: str | None, extra: list[str]) -> list[str]:
    values: list[str] = []
    if target:
        values.extend(load_target_args(target))
    for item in extra:
        values.extend(load_target_args(item))
    return values


def _scan_dry_run(
    targets: list[str],
    excludes: list[str],
    intensity: Intensity,
    extra_args: list[str],
    mode: Mode,
    host_discovery: bool,
) -> None:
    """Print planned nmap command and secondary tool list without executing."""
    from va_workspace.config.load import load_tool_mappings
    from va_workspace.config.profiles import build_discovery_argv, build_tcp_argv
    from va_workspace.core.plugins import intensity_rank

    # Use a descriptive placeholder path so the operator sees where output would land.
    out_stem = "<engagement>/05-raw/nmap"
    root = is_privileged()
    disc_argv = build_discovery_argv(
        nmap_path="nmap",
        output_stem=f"{out_stem}/discovery",
        targets=targets,
        excludes=excludes,
        intensity=intensity,
    )
    tcp_argv, tcp_notes = build_tcp_argv(
        nmap_path="nmap",
        output_stem=f"{out_stem}/tcp",
        targets=targets,
        excludes=excludes,
        intensity=intensity,
        extra_args=extra_args,
        privileged=root,
    )

    out_console.print("[bold]Dry run — nothing will be executed[/bold]")
    out_console.print(f"\n[cyan]Mode:[/cyan] {mode}  [cyan]Intensity:[/cyan] {intensity}")
    if not host_discovery:
        out_console.print("[yellow]Host discovery: skipped (--pn)[/yellow]")
    else:
        out_console.print(f"\n[cyan]Discovery argv:[/cyan]\n  {' '.join(disc_argv)}")
    out_console.print(f"\n[cyan]TCP argv:[/cyan]\n  {' '.join(tcp_argv)}")
    for note in tcp_notes:
        out_console.print(f"  [yellow]note:[/yellow] {note}")

    tools = load_tool_mappings()
    active = [
        t for t in tools
        if intensity_rank(intensity) >= intensity_rank(t.min_intensity)
        and t.argv.get(str(intensity))
    ]
    tool_table = Table(title=f"Secondary tools at intensity={intensity}")
    tool_table.add_column("ID")
    tool_table.add_column("Binary / module")
    for t in active:
        binary = t.python_module or t.binary
        tool_table.add_row(t.id, binary)
    out_console.print(tool_table)


@app.command()
def scan(
    target: str | None = typer.Argument(None, help="CIDR, IP, hostname, or targets file"),
    mode: Mode = ModeOpt,
    intensity: Intensity | None = IntensityOpt,
    out: Path | None = typer.Option(None, "--out"),
    resume: bool = typer.Option(False, "--resume"),
    exclude: list[str] = typer.Option([], "--exclude"),
    nmap_args: str | None = typer.Option(
        None,
        "--nmap-args",
        help="Extra nmap arguments (appended; can disable safety — you own this)",
    ),
    client: str = typer.Option("", "--client"),
    no_enum: bool = typer.Option(False, "--no-enum", help="Skip secondary tools after Nmap"),
    pn: bool = typer.Option(False, "--pn", help="Skip host discovery (-Pn)"),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print planned nmap command and secondary tools, then exit without running",
    ),
) -> None:
    """Live Nmap (Linux) then vault + secondary enum. Resume-aware."""
    cwd = Path.cwd()
    engagement_dir = resolve_engagement_dir(out, cwd)
    extra = nmap_args.split() if nmap_args else []
    resolved_intensity = intensity_or_default(mode, intensity)

    existing = try_load_state(engagement_dir) if engagement_dir else None
    targets = _load_targets(target, [])
    if resume and not targets and existing is not None:
        targets = existing.targets
    if not targets:
        log.error("provide TARGET or --resume from an engagement directory")
        raise typer.Exit(code=2)

    if dry_run:
        _scan_dry_run(targets, exclude, resolved_intensity, extra, mode, not pn)
        return

    if engagement_dir is None:
        engagement_dir = default_out_dir(client or "scan")

    state = bootstrap(
        path=engagement_dir,
        client=client or (existing.client if existing else "scan"),
        mode=mode,
        intensity=resolved_intensity,
        targets=targets,
        excludes=exclude or (existing.excludes if existing else []),
        testers=existing.testers if existing else [],
        classification=existing.classification if existing else "OFFICIAL",
        resume=resume,
    )
    maybe_warn_check_metadata(state)
    _show_legal(state)
    try:
        run_scan(
            state,
            extra,
            resume=resume,
            skip_host_discovery=pn,
            enum=not no_enum,
        )
    except ScanPlatformError as exc:
        log.error(str(exc))
        raise typer.Exit(code=2) from exc
    except (FileNotFoundError, TimeoutError, RuntimeError) as exc:
        log.error(str(exc))
        raise typer.Exit(code=1) from exc
    log.success("scan complete")


@app.command()
def ingest(
    xml_file: Path = typer.Argument(..., exists=True, readable=True, dir_okay=False),
    mode: Mode = ModeOpt,
    intensity: Intensity | None = IntensityOpt,
    out: Path | None = typer.Option(None, "--out"),
    exclude: list[str] = typer.Option([], "--exclude"),
    client: str = typer.Option("", "--client"),
    run_enum_tools: bool = typer.Option(
        False, "--enum", help="Also run secondary tools after ingest (Linux)"
    ),
    target: list[str] = typer.Option(
        [], "--target", help="Scope tokens (default: parsed host IPs)"
    ),
) -> None:
    """Parse existing Nmap XML into a vault (Windows-friendly)."""
    cwd = Path.cwd()
    engagement_dir = resolve_engagement_dir(out, cwd) or default_out_dir(client or "ingest")
    resolved_intensity = intensity_or_default(mode, intensity)
    existing = try_load_state(engagement_dir)
    state = bootstrap(
        path=engagement_dir,
        client=client or (existing.client if existing else "ingest"),
        mode=mode,
        intensity=resolved_intensity,
        targets=target,
        excludes=exclude,
        testers=existing.testers if existing else [],
        classification=existing.classification if existing else "OFFICIAL",
        resume=False,
    )
    _show_legal(state)
    ingest_xml(state, xml_file)
    if not target:
        from va_workspace.core.state import save_state
        from va_workspace.core.vault import write_operator_docs

        state.targets = [host.ip for host in state.hosts]
        save_state(state)
        write_operator_docs(state)
    maybe_warn_check_metadata(state)
    if run_enum_tools:
        try:
            run_enum(state)
        except Exception as exc:  # pragma: no cover - defensive
            log.error(str(exc))
            raise typer.Exit(code=1) from exc
    log.success(f"vault ready: {state.path}")


@app.command()
def status(
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """Show engagement host/job/finding counts."""
    path = resolve_engagement_dir(out, Path.cwd())
    if path is None:
        log.error("not an engagement directory (pass --out or cd into the vault)")
        raise typer.Exit(code=2)
    state = try_load_state(path)
    if state is None:
        log.error(f"no state.json in {path}")
        raise typer.Exit(code=1)
    table = Table(title=str(path))
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("client", state.client)
    table.add_row("mode", str(state.mode))
    table.add_row("intensity", str(state.intensity))
    table.add_row("nmap", str(state.nmap.status))
    table.add_row(
        "nmap phases",
        f"disc={state.nmap.discovery} tcp={state.nmap.tcp} "
        f"udp={state.nmap.udp} nse={state.nmap.scripts}",
    )
    table.add_row("hosts", str(len(state.hosts)))
    table.add_row("jobs", str(len(state.jobs)))
    table.add_row(
        "jobs complete",
        str(sum(1 for j in state.jobs if j.status == JobStatus.COMPLETE)),
    )
    table.add_row("findings", str(len(state.findings)))
    table.add_row("targets", ", ".join(state.targets) or "-")
    out_console.print(table)

    # Severity distribution bar
    files = list_finding_files(state)
    if files:
        counts: dict[str, int] = {}
        for f in files:
            meta = parse_finding_frontmatter(f)
            sev = meta.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        order = ["critical", "high", "medium", "low", "none", "unknown"]
        colours = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "green",
            "none": "dim",
            "unknown": "dim",
        }
        bar_parts: list[str] = []
        for sev in order:
            n = counts.get(sev, 0)
            if n:
                colour = colours.get(sev, "white")
                bar_parts.append(f"[{colour}]{'■' * n} {sev}:{n}[/{colour}]")
        if bar_parts:
            out_console.print("  " + "  ".join(bar_parts))


@finding_app.command("templates")
def finding_templates() -> None:
    """List finding templates."""
    table = Table(title="Finding templates")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("CVSS")
    for tmpl in load_finding_templates().values():
        table.add_row(tmpl.id, tmpl.title, tmpl.cvss)
    out_console.print(table)


@finding_app.command("add")
def finding_add(
    title: str | None = typer.Option(None, "--title"),
    cvss: str | None = typer.Option(None, "--cvss", help="CVSS:3.1/AV:N/AC:L/... vector"),
    template: str | None = typer.Option(None, "--template", help="Template id"),
    hosts: list[str] = typer.Option([], "--hosts"),
    ports: list[str] = typer.Option([], "--ports"),
    description: str = typer.Option("", "--description"),
    short_term: str = typer.Option("", "--short-term"),
    strategic: str = typer.Option("", "--strategic"),
    evidence: list[str] = typer.Option([], "--evidence"),
    status: FindingStatus = typer.Option(FindingStatus.DRAFT, "--status"),
    from_lead: Path | None = typer.Option(
        None,
        "--from-lead",
        exists=True,
        file_okay=True,
        dir_okay=False,
        help="Pre-populate from a lead note's YAML frontmatter (still requires --cvss)",
    ),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """Author a finding with CVSS 3.1. Tools never do this for you."""
    path = resolve_engagement_dir(out, Path.cwd())
    if path is None:
        log.error("not an engagement directory")
        raise typer.Exit(code=2)
    state = try_load_state(path)
    if state is None:
        log.error("no state.json")
        raise typer.Exit(code=1)

    # --from-lead: pre-populate fields from the lead's YAML frontmatter.
    # Operator must still supply --cvss; other flags override the lead values.
    lead_hosts: list[str] = []
    lead_description = ""
    lead_title = ""
    if from_lead is not None:
        lead_meta = parse_finding_frontmatter(from_lead)
        lead_host = lead_meta.get("host", "")
        if lead_host:
            lead_hosts = [lead_host]
        product = lead_meta.get("product", "")
        version = lead_meta.get("version", "")
        if product:
            lead_title = product + (f" {version}" if version else "") + " — unverified lead"
            lead_description = (
                f"Lead from `{from_lead.name}`. "
                f"Product: {product}"
                + (f" {version}" if version else "")
                + ". Verify before promoting to a confirmed finding."
            )

    effective_title = title or lead_title
    effective_hosts = list(hosts) or lead_hosts
    effective_description = description or lead_description

    if not template and (not effective_title or not cvss):
        log.error("provide --template or both --title and --cvss (--from-lead pre-populates title)")
        raise typer.Exit(code=2)
    try:
        finding, dest = add_finding(
            state,
            title=effective_title or "",
            cvss_vector=cvss or "",
            hosts=effective_hosts,
            ports=list(ports),
            description=effective_description,
            short_term_fix=short_term,
            strategic_fix=strategic,
            evidence=list(evidence),
            status=status,
            template_id=template or "",
        )
    except (CvssError, KeyError) as exc:
        log.error(str(exc))
        raise typer.Exit(code=2) from exc
    from va_workspace.core.vault import write_operator_docs

    write_operator_docs(state)
    log.success(f"{finding.id} {finding.severity} {finding.cvss_score} → {dest}")


@finding_app.command("list")
def finding_list(
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """List finding notes in the vault."""
    path = resolve_engagement_dir(out, Path.cwd())
    if path is None:
        log.error("not an engagement directory")
        raise typer.Exit(code=2)
    state = try_load_state(path)
    if state is None:
        log.error("no state.json")
        raise typer.Exit(code=1)
    files = list_finding_files(state)
    table = Table(title="Findings")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Score")
    table.add_column("Status")
    table.add_column("Title")
    if not files:
        log.info("no findings yet — va finding add")
        return
    for file in files:
        meta = parse_finding_frontmatter(file)
        table.add_row(
            meta.get("id", file.name),
            meta.get("severity", ""),
            meta.get("cvss_score", ""),
            meta.get("status", ""),
            meta.get("title", ""),
        )
    out_console.print(table)


@finding_app.command("edit")
def finding_edit_cmd(
    finding_id: str = typer.Argument(..., help="Finding ID, e.g. F-001"),
    title: str | None = typer.Option(None, "--title", help="New title"),
    cvss: str | None = typer.Option(None, "--cvss", help="New CVSS 3.1 vector"),
    hosts: list[str] = typer.Option([], "--hosts", help="Replace host list"),
    ports: list[str] = typer.Option([], "--ports", help="Replace port list"),
    status: FindingStatus | None = typer.Option(None, "--status"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """Update title, CVSS, hosts, ports, or status on an existing finding note."""
    path = resolve_engagement_dir(out, Path.cwd())
    if path is None:
        log.error("not an engagement directory")
        raise typer.Exit(code=2)
    state = try_load_state(path)
    if state is None:
        log.error("no state.json")
        raise typer.Exit(code=1)
    try:
        finding, dest = edit_finding(
            state,
            finding_id,
            title=title,
            cvss_vector=cvss,
            hosts=list(hosts) if hosts else None,
            ports=list(ports) if ports else None,
            status=status,
        )
    except FileNotFoundError as exc:
        log.error(str(exc))
        raise typer.Exit(code=2) from exc
    except (ValueError, CvssError) as exc:
        log.error(str(exc))
        raise typer.Exit(code=2) from exc
    from va_workspace.core.vault import write_operator_docs

    write_operator_docs(state)
    log.success(f"{finding.id} updated → {dest}")


@app.command()
def compare(
    other: Path = typer.Argument(..., exists=True, file_okay=False),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """Diff hosts/ports against another engagement vault (retest)."""
    path = resolve_engagement_dir(out, Path.cwd())
    if path is None:
        log.error("not an engagement directory")
        raise typer.Exit(code=2)
    current = try_load_state(path)
    previous = try_load_state(other)
    if current is None or previous is None:
        log.error("both vaults need state.json")
        raise typer.Exit(code=1)
    write_compare(current, previous)
    log.success(f"wrote {current.path / '01-overview' / 'retest-diff.md'}")


@app.command()
def note(
    text: list[str] = typer.Argument(..., help="Diary line"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """Append a tester diary line (feeds methodology breadcrumbs)."""
    path = resolve_engagement_dir(out, Path.cwd())
    if path is None:
        log.error("not an engagement directory")
        raise typer.Exit(code=2)
    diary = path / "06-logs" / "diary.md"
    diary.parent.mkdir(parents=True, exist_ok=True)
    line = " ".join(text).strip()
    with diary.open("a", encoding="utf-8") as handle:
        handle.write(f"- {utc_now()} {line}\n")
    log.success(f"noted → {diary}")


@app.command()
def snap(
    listen: bool = typer.Option(False, "--listen", help="Hotkey daemon (Ctrl+Alt+S)"),
    name: str | None = typer.Option(None, "--name", help="Caption / filename slug"),
    host: str | None = typer.Option(None, "--host", help="Save under 02-hosts/<ip>/evidence"),
    hotkey: str = typer.Option("<ctrl>+<alt>+s", "--hotkey"),
    no_clip: bool = typer.Option(False, "--no-clip"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """Region screenshot into the vault (fixed Evidence Snapper)."""
    from va_workspace.core.snap import capture_region, listen_hotkey, resolve_vault

    path = resolve_vault(out)
    if path is None:
        log.error("not an engagement directory (cd into the vault or pass --out)")
        raise typer.Exit(code=2)
    if listen:
        try:
            listen_hotkey(path, hotkey)
        except RuntimeError as exc:
            log.error(str(exc))
            raise typer.Exit(code=1) from exc
        except KeyboardInterrupt:
            log.info("stopped")
        return
    result = capture_region(
        engagement=path, name=name, host=host, clipboard=not no_clip
    )
    if result.status == "ok":
        log.success(result.message)
    elif result.status == "cancel":
        log.warn("cancelled")
        raise typer.Exit(code=0)
    else:
        log.error(result.message)
        raise typer.Exit(code=1)


@app.command()
def grab(
    name: str | None = typer.Argument(None, help="Caption for the imported image"),
    host: str | None = typer.Option(None, "--host"),
    out: Path | None = typer.Option(None, "--out"),
) -> None:
    """Import the newest image from ~/Pictures into the vault (old `grab` helper)."""
    from va_workspace.core.snap import import_latest_picture, resolve_vault

    path = resolve_vault(out)
    if path is None:
        log.error("not an engagement directory")
        raise typer.Exit(code=2)
    result = import_latest_picture(engagement=path, name=name, host=host)
    if result.status != "ok":
        log.error(result.message)
        raise typer.Exit(code=1)
    log.success(result.message)


@app.command()
def cert(
    host: str = typer.Argument(..., help="Hostname or IP"),
    port: int = typer.Argument(443),
) -> None:
    """Show a remote TLS certificate (stdlib; works on Windows)."""
    from va_workspace.core.certinfo import fetch_cert

    try:
        info = fetch_cert(host, port)
    except (OSError, TimeoutError, RuntimeError, ssl.SSLError, ValueError) as exc:
        log.error(str(exc))
        raise typer.Exit(code=1) from exc
    table = Table(title=f"{host}:{port}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("subject", info["subject"])
    table.add_row("issuer", info["issuer"])
    table.add_row("not_before", info["not_before"])
    table.add_row("not_after", info["not_after"])
    table.add_row("expired", str(info["expired"]))
    table.add_row("SANs", ", ".join(info["sans"]) or "-")
    out_console.print(table)


@app.command("split-ports")
def split_ports_cmd(
    expr: str = typer.Argument(..., help="Nmap port expr, e.g. 1-65535 or 80,443,8000-8100"),
    parts: int = typer.Option(4, "-S", "--split", min=1, max=64),
) -> None:
    """Split a port range into N chunks (old nsplit.py)."""
    from va_workspace.core.portsplit import split_ports

    try:
        chunks = split_ports(expr, parts)
    except ValueError as exc:
        log.error(str(exc))
        raise typer.Exit(code=2) from exc
    for i, chunk in enumerate(chunks, start=1):
        out_console.print(f"{i}/{len(chunks)}  -p {chunk}")


notes_app = typer.Typer(
    no_args_is_help=True, help="CSTM/CHECK operator notes from ca_misc_scripts."
)
app.add_typer(notes_app, name="notes")


@notes_app.command("list")
def notes_list() -> None:
    """List packaged operator notes."""
    from va_workspace.core.notes import list_notes, notes_dir

    files = list_notes()
    if not files:
        log.warn(f"no notes in {notes_dir()}")
        raise typer.Exit(code=1)
    for path in files:
        out_console.print(path.name)


@notes_app.command("show")
def notes_show(name: str = typer.Argument(..., help="Filename or unique substring")) -> None:
    """Print a packaged operator note."""
    from va_workspace.core.notes import read_note

    try:
        path = read_note(name)
    except FileNotFoundError as exc:
        log.error(str(exc))
        raise typer.Exit(code=2) from exc
    out_console.print(path.read_text(encoding="utf-8"))


def _show_legal(state: object) -> None:
    from va_workspace.models import EngagementState

    assert isinstance(state, EngagementState)
    if not state.legal_banner_shown:
        log.legal_banner()
        state.legal_banner_shown = True
        save_state(state)


