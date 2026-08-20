"""Typer CLI for va-workspace. Thin compositor over core modules."""

from __future__ import annotations

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
from va_workspace.config.profiles import intensity_or_default
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
from va_workspace.core.findings import add_finding, parse_finding_frontmatter
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
    if not template and (not title or not cvss):
        log.error("provide --template or both --title and --cvss")
        raise typer.Exit(code=2)
    try:
        finding, dest = add_finding(
            state,
            title=title or "",
            cvss_vector=cvss or "",
            hosts=list(hosts),
            ports=list(ports),
            description=description,
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


def _show_legal(state: object) -> None:
    from va_workspace.models import EngagementState

    assert isinstance(state, EngagementState)
    if not state.legal_banner_shown:
        log.legal_banner()
        state.legal_banner_shown = True
        save_state(state)


