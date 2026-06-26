"""
ForgeLens CLI
=============
Entry point for all command-line operations.

Usage:
    python -m cli.main --help
    python -m cli.main devices
    python -m cli.main image --source /dev/sda --output /evidence/case1
    python -m cli.main hash --file image.dd
    python -m cli.main verify --file image.dd --hash abc123 --algo sha256
    python -m cli.main report --case CASE-001 --evidence EV-XXXXXXXX
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

# Ensure backend/ is on path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.config import settings
from core.logging.logger import setup_logger

app = typer.Typer(
    name="forgelens",
    help="ForgeLens — Professional DFIR Acquisition Toolkit",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()

# ── Sub-apps ──────────────────────────────────────────────────────────────────
imaging_app = typer.Typer(help="Disk imaging commands")
hash_app = typer.Typer(help="Hashing and verification commands")
export_app = typer.Typer(help="Export and report commands")

# Removed non-memory sub-apps



# ── Callback (global options) ─────────────────────────────────────────────────


@app.callback()
def main_callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    log_dir: Path | None = typer.Option(None, "--log-dir", help="Override log directory"),
) -> None:
    """ForgeLens — Digital Forensics & Incident Response Toolkit."""
    level = "DEBUG" if verbose else settings.logging.level
    setup_logger(log_level=level, log_dir=log_dir or settings.logging.log_dir)


# ── devices ───────────────────────────────────────────────────────────────────


# @app.command("devices")
def cmd_devices(
    android: bool = typer.Option(
        False, "--android", "-a", help="Also scan for Android devices via ADB"
    ),
) -> None:
    """Detect and list all storage devices on this system."""
    from core.acquisition.device_detector import DeviceDetector

    with console.status("[cyan]Scanning for devices...[/cyan]"):
        devices = DeviceDetector.detect()
        if android:
            devices += DeviceDetector.detect_android()

    if not devices:
        rprint("[yellow]No devices found.[/yellow]")
        raise typer.Exit(1)

    table = Table(title="Detected Devices", show_lines=True)
    table.add_column("Device ID", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Label / Model")
    table.add_column("Size (GB)", justify="right")
    table.add_column("Interface")
    table.add_column("Removable")
    table.add_column("Serial")

    for d in devices:
        table.add_row(
            d.device_id,
            d.device_type.value,
            d.label or "—",
            str(d.size_gb),
            d.interface or "—",
            "Yes" if d.is_removable else "No",
            d.serial or "—",
        )

    console.print(table)
    rprint(f"\n[green]Found {len(devices)} device(s).[/green]")


# ── enumerate ─────────────────────────────────────────────────────────────────


# @app.command("enumerate")
def cmd_enumerate(
    device_id: str = typer.Argument(..., help="Device path e.g. /dev/sda or \\\\.\\PhysicalDrive0"),
) -> None:
    """Show partition layout for a specific device."""
    from core.acquisition.device_detector import Device, DeviceType
    from core.acquisition.disk_enumerator import DiskEnumerator

    dev = Device(device_id=device_id, label=device_id, device_type=DeviceType.DISK)

    with console.status(f"[cyan]Enumerating {device_id}...[/cyan]"):
        disk_map = DiskEnumerator.enumerate(dev)

    rprint(f"\n[bold cyan]Disk:[/bold cyan] {disk_map.device.device_id}")
    rprint(f"[bold]Partition Table:[/bold] {disk_map.partition_table or 'unknown'}")
    rprint(
        f"[bold]Encrypted Partitions:[/bold] {'[red]YES[/red]' if disk_map.has_encrypted_partitions else '[green]NO[/green]'}"
    )

    if not disk_map.partitions:
        rprint("[yellow]No partitions found.[/yellow]")
        return

    table = Table(title="Partitions", show_lines=True)
    table.add_column("#", justify="right")
    table.add_column("Path", style="cyan")
    table.add_column("Filesystem")
    table.add_column("Size (GB)", justify="right")
    table.add_column("Mount Point")
    table.add_column("Encrypted")

    for p in disk_map.partitions:
        enc = f"[red]{p.encryption_type}[/red]" if p.is_encrypted else "[green]No[/green]"
        table.add_row(
            str(p.index),
            p.device_path,
            p.filesystem or "—",
            str(p.size_gb),
            p.mount_point or "—",
            enc,
        )

    console.print(table)


# ── image acquire ─────────────────────────────────────────────────────────────


@imaging_app.command("acquire")
def cmd_image_acquire(
    source: str = typer.Option(..., "--source", "-s", help="Source device path"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory for the image"),
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID e.g. CASE-2026-001"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Examiner name"),
    format: str = typer.Option("dd", "--format", "-f", help="Image format: dd | e01"),
    block_size: int = typer.Option(65536, "--block-size", "-b", help="Read block size in bytes"),
    notes: str = typer.Option("", "--notes", "-n", help="Acquisition notes"),
    location: str = typer.Option("", "--location", "-l", help="Geo-location / lab name"),
    verify: bool = typer.Option(
        True, "--verify/--no-verify", help="Post-acquisition hash verification"
    ),
) -> None:
    """Acquire a forensic image from a source device."""
    from core.imaging.imager import DiskImager, ImageFormat

    fmt = ImageFormat(format.lower())

    rprint("\n[bold cyan]ForgeLens Acquisition[/bold cyan]")
    rprint(f"  Source   : [yellow]{source}[/yellow]")
    rprint(f"  Output   : {output}")
    rprint(f"  Case     : {case_id}")
    rprint(f"  Examiner : {examiner}")
    rprint(f"  Format   : {fmt.value.upper()}")
    rprint(f"  Verify   : {'Yes' if verify else 'No'}\n")

    confirm = typer.confirm("Start acquisition?")
    if not confirm:
        rprint("[yellow]Aborted.[/yellow]")
        raise typer.Exit()

    imager = DiskImager()
    result = imager.acquire(
        source=source,
        output_dir=output,
        case_id=case_id,
        examiner=examiner,
        image_format=fmt,
        block_size=block_size,
        notes=notes,
        geo_location=location,
        post_verify=verify,
    )

    if result.success:
        rprint("\n[bold green]✔ Acquisition complete[/bold green]")
        rprint(f"  Evidence ID : {result.evidence_id}")
        rprint(f"  Image       : {result.image_path}")
        rprint(f"  SHA256      : {result.hash_sha256}")
        rprint(f"  Duration    : {result.duration_seconds}s")
        rprint(f"  Verified    : {'[green]PASS[/green]' if result.verified else '[red]FAIL[/red]'}")
    else:
        rprint(f"\n[bold red]✘ Acquisition failed:[/bold red] {result.error}")
        raise typer.Exit(1)


# ── image mount / unmount / mounts ────────────────────────────────────────────


@imaging_app.command("mount")
def cmd_image_mount(
    image: Path = typer.Argument(..., help="Disk image to mount (.dd, .raw, .img, .e01)"),
    case_id: str = typer.Option("", "--case", "-c", help="Case ID for chain of custody"),
    evidence_id: str = typer.Option("", "--evidence", "-e", help="Evidence ID (auto from filename)"),
    examiner: str = typer.Option("analyst", "--examiner", help="Examiner name for custody log"),
    drive: str = typer.Option("", "--drive", "-d", help="Windows: drive letter (e.g. Z). Linux: mount path"),
    partition: int = typer.Option(0, "--partition", "-p", help="Partition index to mount (0=auto/first)"),
) -> None:
    """Mount a forensic disk image read-only for analysis."""
    from core.imaging.mounter import ImageMounter, get_windows_mount_tool_status
    import platform as _platform

    if not image.exists():
        rprint(f"[red]Image not found: {image}[/red]")
        raise typer.Exit(1)

    # Windows: warn if no tool available
    if _platform.system() == "Windows":
        tools = get_windows_mount_tool_status()
        available = [t for t, s in tools.items() if s == "available"]
        if not available:
            rprint("\n[yellow]⚠ No mount tool found. Run this first:[/yellow]")
            rprint("  [cyan]python forgelens.py setup mounter[/cyan]")
            rprint()
            rprint("[dim]This downloads Arsenal Image Mounter (AGPL open-source)[/dim]")
            rprint("[dim]or install ImDisk (GPL) from https://sourceforge.net/projects/imdisk-toolkit/[/dim]\n")

    size_gb = round(image.stat().st_size / (1024**3), 2)
    rprint(f"\n[bold cyan]ForgeLens — Mount Image[/bold cyan]")
    rprint(f"  Image     : [yellow]{image}[/yellow]")
    rprint(f"  Size      : {size_gb} GB")
    rprint(f"  Format    : {image.suffix.upper()}")
    rprint(f"  Partition : {partition if partition > 0 else 'auto'}")
    if case_id:
        rprint(f"  Case      : {case_id}")
    rprint()

    mounter = ImageMounter()
    with console.status("[cyan]Mounting image read-only...[/cyan]"):
        result = mounter.mount(
            image_path=image,
            case_id=case_id,
            evidence_id=evidence_id,
            examiner=examiner,
            mount_point=drive or None,
            partition_index=partition,
        )

    if result.success:
        rprint(f"[bold green]✔ Mounted successfully[/bold green]")
        rprint(f"  Mount point : [cyan]{result.mount_point}[/cyan]")
        rprint(f"  Mount ID    : [dim]{result.mount_id}[/dim]")
        rprint(f"  Tool used   : {result.tool_used}")
        rprint(f"\n[dim]Browse: {result.mount_point}[/dim]")
        rprint(f"[dim]Unmount: python forgelens.py image unmount {result.mount_id}[/dim]")
    else:
        rprint(f"\n[bold red]✘ Mount failed:[/bold red] {result.error}")
        if "Administrator" in result.error or "Permission" in result.error:
            rprint("[yellow]Tip: run as Administrator[/yellow]")
        raise typer.Exit(1)


@imaging_app.command("unmount")
def cmd_image_unmount(
    mount_id: str = typer.Argument(..., help="Mount ID from 'image mount' or 'image mounts'"),
    examiner: str = typer.Option("analyst", "--examiner", help="Examiner name for custody log"),
) -> None:
    """Unmount a previously mounted forensic image."""
    from core.imaging.mounter import ImageMounter

    mounter = ImageMounter()
    active = {m.mount_id: m for m in mounter.list_mounts()}

    if mount_id.upper() == "ALL":
        count = mounter.unmount_all()
        rprint(f"[green]✔ Unmounted {count} image(s)[/green]")
        return

    if mount_id not in active:
        rprint(f"[red]Mount ID not found: {mount_id}[/red]")
        rprint("[dim]Run 'python forgelens.py image mounts' to see active mounts[/dim]")
        raise typer.Exit(1)

    m = active[mount_id]
    rprint(f"Unmounting [cyan]{m.mount_point}[/cyan] ({m.image_path})...")

    ok = mounter.unmount(mount_id, examiner=examiner)
    if ok:
        rprint(f"[green]✔ Unmounted successfully[/green]")
    else:
        rprint(f"[red]✘ Unmount failed — try manual unmount of {m.mount_point}[/red]")
        raise typer.Exit(1)


@imaging_app.command("mounts")
def cmd_image_mounts() -> None:
    """List all currently mounted forensic images."""
    from core.imaging.mounter import ImageMounter

    mounter = ImageMounter()
    mounts = mounter.list_mounts()

    if not mounts:
        rprint("[dim]No images currently mounted.[/dim]")
        return

    table = Table(title="Active Mounts", show_lines=True)
    table.add_column("Mount ID", style="cyan")
    table.add_column("Image")
    table.add_column("Mount Point", style="green")
    table.add_column("Tool")
    table.add_column("Case")
    table.add_column("Mounted At", style="dim")

    for m in mounts:
        table.add_row(
            m.mount_id,
            Path(m.image_path).name,
            m.mount_point,
            m.tool_used,
            m.case_id or "—",
            m.mounted_at[:19] if m.mounted_at else "—",
        )
    console.print(table)
    rprint(f"\n[dim]Unmount: python forgelens.py image unmount <MOUNT_ID>[/dim]")
    rprint(f"[dim]Unmount all: python forgelens.py image unmount ALL[/dim]")


# ── hash file ─────────────────────────────────────────────────────────────────


@hash_app.command("file")
def cmd_hash_file(
    file: str = typer.Argument(..., help="File to hash"),
    algo: str = typer.Option(
        "sha256", "--algo", "-a", help="Algorithm: sha256 | md5 | sha1 | blake3"
    ),
    multi: bool = typer.Option(
        False, "--multi", "-m", help="Hash with SHA256 + MD5 + SHA1 simultaneously"
    ),
    chunk_level: bool = typer.Option(False, "--chunks", help="Also compute per-chunk hashes"),
) -> None:
    """Hash a file and display the digest."""
    from core.hashing.hasher import HashAlgorithm, Hasher

    file_path = Path(file)
    # Bypass exists() check for Windows physical drives
    if not file.startswith("\\\\.\\") and not file_path.exists():
        rprint(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    with console.status(f"[cyan]Hashing {file_path.name}...[/cyan]"):
        if multi:
            result = Hasher.hash_file_multi(
                file_path,
                algorithms=[HashAlgorithm.SHA256, HashAlgorithm.MD5, HashAlgorithm.SHA1],
            )
            rprint(f"\n[bold]File:[/bold] {result.file_path}")
            rprint(f"[bold]Size:[/bold] {result.size_bytes / (1024**2):.2f} MB")
            for algorithm, digest in result.hashes.items():
                rprint(f"  [cyan]{algorithm.value.upper()}[/cyan]: {digest}")
        else:
            algorithm = HashAlgorithm(algo.lower())
            result = Hasher.hash_file(file_path, algorithm, chunk_level=chunk_level)
            rprint(f"\n[bold]{algorithm.value.upper()}[/bold]: [green]{result.hex_digest}[/green]")
            rprint(
                f"[dim]Size: {result.size_mb} MB | Duration: {result.duration_seconds}s | {result.throughput_mbps} MB/s[/dim]"
            )
            if chunk_level:
                rprint(f"[dim]Chunk hashes: {len(result.chunk_hashes)}[/dim]")


@hash_app.command("verify")
def cmd_hash_verify(
    file: Path = typer.Argument(..., help="File to verify"),
    expected: str = typer.Argument(..., help="Expected hash digest"),
    algo: str = typer.Option("sha256", "--algo", "-a", help="Algorithm: sha256 | md5 | sha1"),
) -> None:
    """Verify a file against a known hash digest."""
    from core.hashing.hasher import HashAlgorithm, Hasher

    if not file.exists():
        rprint(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    algorithm = HashAlgorithm(algo.lower())

    with console.status(f"[cyan]Verifying {file.name}...[/cyan]"):
        ok = Hasher.verify_file(file, algorithm, expected)

    if ok:
        rprint(f"\n[bold green]✔ VERIFIED[/bold green] — {algorithm.value.upper()} matches.")
    else:
        rprint("\n[bold red]✘ MISMATCH[/bold red] — Hash does not match.")
        raise typer.Exit(1)


# ── export report ─────────────────────────────────────────────────────────────


@export_app.command("report")
def cmd_export_report(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    evidence_id: str = typer.Option(..., "--evidence", "-e", help="Evidence ID"),
    formats: str = typer.Option(
        "json,html,text", "--formats", "-f", help="Comma-separated: json,html,text,pdf"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output directory (defaults to evidence dir)"
    ),
) -> None:
    """Generate acquisition reports for an evidence item."""
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.reporting.report_generator import ReportFormat, ReportGenerator

    mgr = EvidenceManager()
    ev_dir = mgr.evidence_dir(case_id, evidence_id)

    if not ev_dir.exists():
        rprint(f"[red]Evidence not found: {case_id}/{evidence_id}[/red]")
        raise typer.Exit(1)

    try:
        meta_dict = mgr.read_metadata(case_id, evidence_id)
    except FileNotFoundError:
        rprint(f"[red]metadata.json not found for {evidence_id}[/red]")
        raise typer.Exit(1) from None

    from core.acquisition.metadata_collector import AcquisitionMetadata

    meta = AcquisitionMetadata(
        **{k: v for k, v in meta_dict.items() if k in AcquisitionMetadata.__dataclass_fields__}
    )

    fmt_map = {
        "json": ReportFormat.JSON,
        "html": ReportFormat.HTML,
        "text": ReportFormat.TEXT,
        "pdf": ReportFormat.PDF,
    }
    requested = [fmt_map[f.strip()] for f in formats.split(",") if f.strip() in fmt_map]

    out_dir = output or ev_dir
    gen = ReportGenerator(output_dir=out_dir)

    with console.status("[cyan]Generating reports...[/cyan]"):
        outputs = gen.generate(meta, formats=requested)

    rprint("\n[bold green]Reports generated:[/bold green]")
    for fmt, path in outputs.items():
        rprint(f"  [cyan]{fmt.value.upper()}[/cyan]: {path}")


@export_app.command("custody")
def cmd_export_custody(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    evidence_id: str = typer.Option(..., "--evidence", "-e", help="Evidence ID"),
) -> None:
    """Display the chain of custody for an evidence item."""
    from core.chain_of_custody.evidence_manager import EvidenceManager

    mgr = EvidenceManager()
    events = mgr.get_custody_chain(case_id, evidence_id)

    if not events:
        rprint("[yellow]No custody events found.[/yellow]")
        return

    table = Table(title=f"Chain of Custody — {evidence_id}", show_lines=True)
    table.add_column("Timestamp", style="dim")
    table.add_column("Event", style="cyan")
    table.add_column("Actor")
    table.add_column("Notes")

    for ev in events:
        table.add_row(
            ev.get("timestamp", ""),
            ev.get("event_type", ""),
            ev.get("actor", ""),
            ev.get("notes", ""),
        )

    console.print(table)


# ── cases ─────────────────────────────────────────────────────────────────────


@app.command("cases")
def cmd_cases() -> None:
    """List all cases in the evidence vault."""
    from core.chain_of_custody.evidence_manager import EvidenceManager

    mgr = EvidenceManager()
    cases = mgr.list_cases()

    if not cases:
        rprint("[yellow]No cases found in evidence vault.[/yellow]")
        return

    table = Table(title="Evidence Vault — Cases", show_lines=True)
    table.add_column("Case ID", style="cyan")
    table.add_column("Evidence Items", justify="right")

    for case in sorted(cases):
        evidence = mgr.list_evidence(case)
        table.add_row(case, str(len(evidence)))

    console.print(table)


# ── version ───────────────────────────────────────────────────────────────────


@app.command("version")
def cmd_version() -> None:
    """Show ForgeLens version."""
    rprint(f"[bold cyan]ForgeLens[/bold cyan] v{settings.app.version}")

@app.command("tui")
def cmd_tui() -> None:
    """Launch the ForgeLens Terminal User Interface (TUI)."""
    from cli.tui import ForgeLensTUI
    tui_app = ForgeLensTUI()
    tui_app.run()


# ── V0.9 Case management ──────────────────────────────────────────────────────

case_app = typer.Typer(help="Case management commands")
vault_app = typer.Typer(help="Evidence vault commands (search, tag, encrypt)")
app.add_typer(case_app, name="case")
app.add_typer(vault_app, name="vault")

# ── V1.1 Memory forensics ─────────────────────────────────────────────────────
memory_app = typer.Typer(help="Memory forensics commands (Volatility3)")
app.add_typer(memory_app, name="memory")


@case_app.command("create")
def cmd_case_create(
    case_id: str = typer.Argument(..., help="Case ID e.g. CASE-2026-001"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Lead examiner name"),
    title: str = typer.Option("", "--title", "-t", help="Short case title"),
    description: str = typer.Option("", "--desc", "-d", help="Case description"),
    tags: str = typer.Option("", "--tags", help="Comma-separated tags"),
    priority: str = typer.Option("medium", "--priority", "-p", help="low|medium|high|critical"),
) -> None:
    """Create a new case in the evidence vault."""
    from core.chain_of_custody.case_manager import CaseManager

    mgr = CaseManager()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    case = mgr.create_case(
        case_id=case_id,
        examiner=examiner,
        title=title or case_id,
        description=description,
        tags=tag_list,
        priority=priority,
    )
    rprint("\n[bold green]✔ Case created[/bold green]")
    rprint(f"  Case ID   : [cyan]{case.case_id}[/cyan]")
    rprint(f"  Title     : {case.title}")
    rprint(f"  Examiner  : {case.examiner}")
    rprint(f"  Priority  : {case.priority}")
    rprint(f"  Tags      : {', '.join(case.tags) or '—'}")
    rprint(f"  Created   : {case.created_at}")


@case_app.command("list")
def cmd_case_list(
    status: str = typer.Option("", "--status", "-s", help="Filter: open|active|closed|archived"),
) -> None:
    """List all cases in the registry."""
    from core.chain_of_custody.case_manager import CaseManager, CaseStatus

    mgr = CaseManager()
    filter_status = CaseStatus(status) if status else None
    cases = mgr.list_cases(status=filter_status)

    if not cases:
        rprint("[yellow]No cases found.[/yellow]")
        return

    table = Table(title="Cases", show_lines=True)
    table.add_column("Case ID", style="cyan")
    table.add_column("Title")
    table.add_column("Examiner")
    table.add_column("Status", style="magenta")
    table.add_column("Priority")
    table.add_column("Evidence", justify="right")
    table.add_column("Tags")
    table.add_column("Created", style="dim")

    for c in cases:
        table.add_row(
            c.case_id,
            c.title,
            c.examiner,
            c.status.value,
            c.priority,
            str(len(c.evidence_ids)),
            ", ".join(c.tags) or "—",
            c.created_at[:10],
        )
    console.print(table)


@case_app.command("update")
def cmd_case_update(
    case_id: str = typer.Argument(..., help="Case ID to update"),
    status: str = typer.Option(
        "", "--status", "-s", help="New status: open|active|closed|archived"
    ),
    notes: str = typer.Option("", "--notes", "-n", help="Case notes"),
    tags: str = typer.Option("", "--tags", help="Replace tags (comma-separated)"),
    priority: str = typer.Option("", "--priority", "-p", help="New priority"),
) -> None:
    """Update case status, notes, tags, or priority."""
    from core.chain_of_custody.case_manager import CaseManager, CaseStatus

    mgr = CaseManager()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    case = mgr.update_case(
        case_id=case_id,
        status=CaseStatus(status) if status else None,
        notes=notes or None,
        tags=tag_list,
        priority=priority or None,
    )
    if case:
        rprint(f"[green]✔ Case {case_id} updated | status={case.status.value}[/green]")
    else:
        rprint(f"[red]Case {case_id} not found.[/red]")
        raise typer.Exit(1)


@case_app.command("search")
def cmd_case_search(
    query: str = typer.Argument(..., help="Search query"),
) -> None:
    """Search cases by ID, title, description, examiner, or tags."""
    from core.chain_of_custody.case_manager import CaseManager

    mgr = CaseManager()
    results = mgr.search_cases(query)

    if not results:
        rprint(f"[yellow]No cases matching '{query}'.[/yellow]")
        return

    table = Table(title=f"Search: '{query}'", show_lines=True)
    table.add_column("Case ID", style="cyan")
    table.add_column("Title")
    table.add_column("Examiner")
    table.add_column("Status")
    table.add_column("Tags")

    for c in results:
        table.add_row(c.case_id, c.title, c.examiner, c.status.value, ", ".join(c.tags) or "—")
    console.print(table)
    rprint(f"\n[dim]{len(results)} result(s)[/dim]")


@case_app.command("audit")
def cmd_case_audit(
    case_id: str = typer.Argument(..., help="Case ID"),
) -> None:
    """Show the full audit trail for a case (all evidence events)."""
    from core.chain_of_custody.evidence_manager import EvidenceManager

    mgr = EvidenceManager()
    events = mgr.get_audit_trail(case_id)

    if not events:
        rprint(f"[yellow]No audit events for case {case_id}.[/yellow]")
        return

    table = Table(title=f"Audit Trail — {case_id}", show_lines=True)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Timestamp", style="dim")
    table.add_column("Evidence ID", style="cyan")
    table.add_column("Event", style="magenta")
    table.add_column("Actor")
    table.add_column("Notes")

    for i, ev in enumerate(events, 1):
        table.add_row(
            str(i),
            ev.get("timestamp", "")[:19],
            ev.get("evidence_id", ""),
            ev.get("event_type", ""),
            ev.get("actor", ""),
            ev.get("notes", "")[:60],
        )
    console.print(table)
    rprint(f"\n[dim]{len(events)} event(s)[/dim]")


# ── V0.9 Vault commands ───────────────────────────────────────────────────────


@vault_app.command("tag")
def cmd_vault_tag(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    evidence_id: str = typer.Option(..., "--evidence", "-e", help="Evidence ID"),
    tags: str = typer.Argument(..., help="Comma-separated tags to add"),
    actor: str = typer.Option("analyst", "--actor", "-a", help="Who is tagging"),
) -> None:
    """Add tags to an evidence item."""
    from core.chain_of_custody.evidence_manager import EvidenceManager

    mgr = EvidenceManager()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    mgr.tag_evidence(case_id, evidence_id, tag_list, actor=actor)
    rprint(f"[green]✔ Tags added to {evidence_id}: {tag_list}[/green]")


@vault_app.command("search")
def cmd_vault_search(
    query: str = typer.Argument(..., help="Search query"),
    tag: str = typer.Option("", "--tag", "-t", help="Filter by tag"),
    case_id: str = typer.Option("", "--case", "-c", help="Filter by case ID"),
) -> None:
    """Search the evidence index."""
    from core.chain_of_custody.evidence_index import EvidenceIndex

    idx = EvidenceIndex()

    if tag:
        results = idx.get_by_tag(tag)
    elif case_id:
        results = idx.get_by_case(case_id)
    else:
        results = idx.search(query)

    if not results:
        rprint(f"[yellow]No evidence matching '{query or tag or case_id}'.[/yellow]")
        return

    table = Table(title=f"Evidence Search: '{query or tag or case_id}'", show_lines=True)
    table.add_column("Evidence ID", style="cyan")
    table.add_column("Case ID")
    table.add_column("Device")
    table.add_column("Examiner")
    table.add_column("Size")
    table.add_column("Verified")
    table.add_column("Tags")

    for e in results:
        table.add_row(
            e.evidence_id,
            e.case_id,
            e.device_model or e.device_id or "—",
            e.examiner,
            f"{e.size_gb} GB",
            "[green]✔[/green]" if e.verified else "[yellow]?[/yellow]",
            ", ".join(e.tags) or "—",
        )
    console.print(table)
    rprint(f"\n[dim]{len(results)} result(s)[/dim]")


@vault_app.command("index")
def cmd_vault_index() -> None:
    """Rebuild the evidence search index from disk."""
    from core.chain_of_custody.evidence_index import EvidenceIndex

    with console.status("[cyan]Rebuilding evidence index...[/cyan]"):
        idx = EvidenceIndex()
        count = idx.rebuild()
    rprint(f"[green]✔ Index rebuilt — {count} evidence item(s) indexed.[/green]")


@vault_app.command("repair")
def cmd_vault_repair(
    case_id: str = typer.Option("", "--case", "-c", help="Limit to a specific case (all cases if omitted)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be repaired without doing it"),
) -> None:
    """Reconstruct missing metadata.json for evidence items that have an image but no metadata."""
    import json as _json
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.hashing.hasher import Hasher, HashAlgorithm
    from core.config import settings

    mgr = EvidenceManager()
    cases = [case_id] if case_id else mgr.list_cases()

    rprint(f"\n[bold cyan]ForgeLens — Vault Repair[/bold cyan]")
    if dry_run:
        rprint("[yellow]DRY RUN — nothing will be written[/yellow]\n")

    repaired = 0
    skipped = 0

    for cid in cases:
        for eid in mgr.list_evidence(cid):
            ev_dir = mgr.evidence_dir(cid, eid)
            meta_path = ev_dir / "metadata.json"

            if meta_path.exists():
                skipped += 1
                continue

            # Find the image file
            image_exts = [".raw", ".dd", ".img", ".e01", ".aff", ".lime"]
            image_file = None
            for f in ev_dir.iterdir():
                if f.suffix.lower() in image_exts and f.stat().st_size > 0:
                    image_file = f
                    break

            if not image_file:
                rprint(f"  [yellow]—[/yellow] {cid}/{eid} — no image file found, skipping")
                continue

            # Read what we know from chain of custody
            coc_path = ev_dir / "chain_of_custody.json"
            examiner = "unknown"
            method = "unknown"
            created_at = ""
            if coc_path.exists():
                coc = _json.loads(coc_path.read_text(encoding="utf-8"))
                created_at = coc.get("created_at", "")
                for event in coc.get("events", []):
                    if event.get("actor") and event["actor"] != "system":
                        examiner = event["actor"]
                    notes = event.get("notes", "")
                    if "via physical" in notes:
                        method = "physical"
                    elif "via memory" in notes or "RAM" in notes:
                        method = "memory"
                    elif "via logical" in notes:
                        method = "logical"

            size = image_file.stat().st_size
            rprint(f"  [cyan]Repairing[/cyan] {cid}/{eid} — {image_file.name} ({size/(1024**3):.2f} GB)")

            if dry_run:
                repaired += 1
                continue

            # Hash the image
            with console.status(f"  [dim]Hashing {image_file.name}...[/dim]"):
                multi = Hasher.hash_file_multi(
                    image_file,
                    [HashAlgorithm.SHA256, HashAlgorithm.MD5, HashAlgorithm.SHA1],
                )
            sha256 = multi.hashes.get(HashAlgorithm.SHA256, "")
            md5    = multi.hashes.get(HashAlgorithm.MD5, "")
            sha1   = multi.hashes.get(HashAlgorithm.SHA1, "")

            meta = {
                "evidence_id": eid,
                "case_id": cid,
                "session_id": f"{eid.lower().replace('ev-', '')}-reconstructed",
                "examiner": examiner,
                "timestamp_utc": created_at,
                "acquisition_method": method,
                "tool_version": "ForgeLens 0.1.0",
                "notes": "metadata.json reconstructed by vault repair",
                "device": {"device_id": image_file.stem, "model": "Unknown", "size_bytes": size},
                "hash_sha256": sha256,
                "hash_md5": md5,
                "hash_sha1": sha1,
                "acquisition_start": created_at,
                "acquisition_end": "",
                "duration_seconds": 0.0,
                "bytes_acquired": size,
                "output_path": str(image_file.resolve()),
                "verified": True,
            }

            meta_path.write_text(
                _json.dumps(meta, indent=2, default=str), encoding="utf-8"
            )

            # Write hash manifest if missing
            hash_manifest = ev_dir / f"{image_file.name}.hashes"
            if not hash_manifest.exists():
                hash_manifest.write_text(
                    f"SHA256: {sha256}\nMD5:    {md5}\nSHA1:   {sha1}\n",
                    encoding="utf-8",
                )

            mgr.record_custody_event(eid, cid, "repaired", "system",
                                     "metadata.json reconstructed by vault repair")
            rprint(f"    [green]✔[/green] SHA256: {sha256[:32]}...")
            repaired += 1

    rprint(f"\n[bold]{'Would repair' if dry_run else 'Repaired'}:[/bold] {repaired} | Skipped (already have metadata): {skipped}")
    if repaired > 0 and not dry_run:
        rprint("[dim]Run 'python forgelens.py vault index' to rebuild the search index.[/dim]")


@vault_app.command("encrypt")
def cmd_vault_encrypt(
    file: Path = typer.Argument(..., help="File to encrypt"),
    key_file: Path | None = typer.Option(
        None, "--key", "-k", help="Key file (generates new if omitted)"
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Output path (default: <file>.enc)"
    ),
) -> None:
    """Encrypt an evidence file with AES-256-GCM."""
    from core.chain_of_custody.vault_crypto import VaultCrypto

    if not file.exists():
        rprint(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    # Load or generate key
    if key_file and key_file.exists():
        key = VaultCrypto.key_from_b64(key_file.read_text().strip())
        rprint(f"[dim]Using key from {key_file}[/dim]")
    else:
        key = VaultCrypto.generate_key()
        key_path = file.with_suffix(".key")
        key_path.write_text(VaultCrypto.key_to_b64(key))
        rprint(f"[yellow]New key saved to: {key_path}[/yellow]")
        rprint("[bold red]Keep this key safe — without it the file cannot be decrypted.[/bold red]")

    out_path = output or file.with_suffix(file.suffix + ".enc")

    with console.status(f"[cyan]Encrypting {file.name}...[/cyan]"):
        ok = VaultCrypto.encrypt_file(file, out_path, key)

    if ok:
        rprint(f"[green]✔ Encrypted: {out_path}[/green]")
    else:
        rprint("[red]✘ Encryption failed — is 'cryptography' installed?[/red]")
        raise typer.Exit(1)


@vault_app.command("decrypt")
def cmd_vault_decrypt(
    file: Path = typer.Argument(..., help="Encrypted file (.enc)"),
    key_file: Path = typer.Option(..., "--key", "-k", help="Key file"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output path"),
) -> None:
    """Decrypt an AES-256-GCM encrypted evidence file."""
    from core.chain_of_custody.vault_crypto import VaultCrypto

    if not file.exists():
        rprint(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)
    if not key_file.exists():
        rprint(f"[red]Key file not found: {key_file}[/red]")
        raise typer.Exit(1)

    key = VaultCrypto.key_from_b64(key_file.read_text().strip())
    out_path = output or file.with_suffix("")

    with console.status(f"[cyan]Decrypting {file.name}...[/cyan]"):
        ok = VaultCrypto.decrypt_file(file, out_path, key)

    if ok:
        rprint(f"[green]✔ Decrypted: {out_path}[/green]")
    else:
        rprint("[red]✘ Decryption failed — wrong key or corrupted file.[/red]")
        raise typer.Exit(1)


@vault_app.command("verify-sig")
def cmd_vault_verify_sig(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    evidence_id: str = typer.Option(..., "--evidence", "-e", help="Evidence ID"),
    key_file: Path = typer.Option(..., "--key", "-k", help="Key file used to sign"),
) -> None:
    """Verify the HMAC signature of signed metadata."""
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.chain_of_custody.vault_crypto import VaultCrypto

    mgr = EvidenceManager()
    key = VaultCrypto.key_from_b64(key_file.read_text().strip())

    try:
        _, is_valid = mgr.verify_signed_metadata(case_id, evidence_id, key)
        if is_valid:
            rprint(
                "[bold green]✔ Signature VALID — metadata has not been tampered with.[/bold green]"
            )
        else:
            rprint("[bold red]✘ Signature INVALID — metadata may have been modified.[/bold red]")
            raise typer.Exit(1) from None
    except FileNotFoundError:
        rprint(
            f"[yellow]No signed metadata found for {evidence_id}. Run 'vault sign' first.[/yellow]"
        )
        raise typer.Exit(1) from None


@memory_app.command("setup")
def cmd_memory_setup(
    arch: str = typer.Option("x64", "--arch", "-a", help="CPU architecture: x64 | x86"),
) -> None:
    """Download WinPmem into the tools/ directory."""
    import sys
    from pathlib import Path as _Path

    setup_script = _Path(__file__).resolve().parents[2] / "tools" / "setup_winpmem.py"
    if not setup_script.exists():
        rprint("[red]tools/setup_winpmem.py not found.[/red]")
        raise typer.Exit(1)

    # Run the setup script in-process
    import importlib.util

    spec = importlib.util.spec_from_file_location("setup_winpmem", setup_script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rc = mod.main(arch=arch)
    raise typer.Exit(rc)


@memory_app.command("acquire")
def cmd_memory_acquire(
    output: Path = typer.Option(
        ..., "--output", "-o", help="Output path for the memory dump (e.g. evidence/memory.raw)"
    ),
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID e.g. CASE-2026-001"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Examiner name"),
    notes: str = typer.Option("", "--notes", "-n", help="Acquisition notes"),
    location: str = typer.Option("", "--location", "-l", help="Lab or location name"),
    verify: bool = typer.Option(
        True, "--verify/--no-verify", help="Post-acquisition hash verification"
    ),
) -> None:
    """Acquire a live RAM dump using WinPmem (Windows only). Requires Administrator."""
    import platform as _platform

    if _platform.system() != "Windows":
        rprint("[red]Memory acquisition via WinPmem is Windows-only.[/red]")
        raise typer.Exit(1)

    from platforms.windows.memory import find_winpmem, get_ram_info, acquire_ram

    # ── Pre-flight checks ─────────────────────────────────────────────────────
    tool = find_winpmem()
    if not tool:
        rprint("\n[bold red]WinPmem not found.[/bold red]")
        rprint("Run this first to download it:")
        rprint("  [cyan]python forgelens.py memory setup[/cyan]\n")
        raise typer.Exit(1)

    ram = get_ram_info()
    total_gb = ram.get("total_gb", 0)
    avail_gb = ram.get("available_gb", 0)

    rprint("\n[bold cyan]ForgeLens — RAM Acquisition[/bold cyan]")
    rprint(f"  Tool     : [yellow]{tool.name}[/yellow]")
    rprint(f"  RAM      : {total_gb} GB total / {avail_gb} GB available")
    rprint(f"  Output   : {output}")
    rprint(f"  Case     : {case_id}")
    rprint(f"  Examiner : {examiner}")
    rprint(f"  Verify   : {'Yes' if verify else 'No'}")

    # Warn if output drive doesn't have enough space
    try:
        import shutil as _shutil
        free_gb = round(_shutil.disk_usage(output.parent if output.parent.exists() else Path(".")).free / (1024**3), 2)
        rprint(f"  Disk free: {free_gb} GB")
        if free_gb < total_gb * 1.1:
            rprint(f"\n[yellow]⚠ Warning: only {free_gb} GB free — dump may be ~{total_gb} GB[/yellow]")
    except Exception:
        pass

    rprint()
    confirm = typer.confirm("Start RAM acquisition?")
    if not confirm:
        rprint("[yellow]Aborted.[/yellow]")
        raise typer.Exit()

    with console.status("[cyan]Acquiring RAM — this may take several minutes...[/cyan]"):
        result = acquire_ram(
            output_path=output,
            case_id=case_id,
            examiner=examiner,
            notes=notes,
            geo_location=location,
            verify=verify,
        )

    if result.success:
        rprint("\n[bold green]✔ RAM acquisition complete[/bold green]")
        rprint(f"  Evidence ID : [cyan]{result.evidence_id}[/cyan]")
        rprint(f"  Dump        : {result.dump_path}")
        rprint(f"  Size        : {result.size_gb} GB")
        rprint(f"  SHA256      : {result.hash_sha256}")
        rprint(f"  MD5         : {result.hash_md5}")
        rprint(f"  Duration    : {result.duration_seconds}s")
        rprint(f"  Verified    : {'[green]PASS[/green]' if result.verified else '[red]FAIL[/red]'}")
        rprint(f"\n[dim]Analyse with:[/dim]")
        rprint(f"  [cyan]python forgelens.py memory processes {result.dump_path}[/cyan]")
        rprint(f"  [cyan]python forgelens.py memory connections {result.dump_path}[/cyan]")
        rprint(f"  [cyan]python forgelens.py memory malfind {result.dump_path}[/cyan]")
    else:
        rprint(f"\n[bold red]✘ Acquisition failed:[/bold red] {result.error}")
        if "Administrator" in result.error:
            rprint("[yellow]Tip: right-click your terminal and run as Administrator.[/yellow]")
        raise typer.Exit(1)


@memory_app.command("processes")
def cmd_memory_processes(
    dump: Path = typer.Argument(..., help="Memory dump file (.raw, .lime, .dmp)"),
    suspicious_only: bool = typer.Option(
        False, "--suspicious", "-s", help="Show only suspicious processes"
    ),
) -> None:
    """List processes from a memory dump via Volatility3."""
    from core.memory.volatility_engine import VolatilityEngine

    if not dump.exists():
        rprint(f"[red]Dump file not found: {dump}[/red]")
        raise typer.Exit(1)

    engine = VolatilityEngine(dump)
    with console.status("[cyan]Analysing processes...[/cyan]"):
        result = engine.list_processes()

    if not result.success:
        rprint(f"[red]✘ Failed: {result.error}[/red]")
        raise typer.Exit(1)

    rows = result.data
    if suspicious_only:
        rows = [r for r in rows if r.get("_suspicious")]

    table = Table(title=f"Processes — {dump.name}", show_lines=True)
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("PPID", justify="right")
    table.add_column("Name", style="white")
    table.add_column("Threads", justify="right")
    table.add_column("Created")
    table.add_column("Suspicious")

    for row in rows:
        is_sus = row.get("_suspicious", False)
        reasons = row.get("_suspicious_reasons", [])
        table.add_row(
            str(row.get("PID") or row.get("pid") or ""),
            str(row.get("PPID") or row.get("ppid") or ""),
            row.get("ImageFileName") or row.get("Name") or "",
            str(row.get("Threads") or ""),
            str(row.get("CreateTime") or "")[:19],
            f"[red]⚠ {reasons[0]}[/red]" if is_sus else "[green]—[/green]",
        )

    console.print(table)
    sus_count = sum(1 for r in result.data if r.get("_suspicious"))
    rprint(f"\n[dim]{result.row_count} process(es) | [red]{sus_count} suspicious[/red][/dim]")


@memory_app.command("dlls")
def cmd_memory_dlls(
    dump: Path = typer.Argument(..., help="Memory dump file"),
    pid: int = typer.Option(0, "--pid", "-p", help="Filter by PID (0 = all)"),
) -> None:
    """List loaded DLLs from a memory dump."""
    from core.memory.volatility_engine import VolatilityEngine

    if not dump.exists():
        rprint(f"[red]Dump file not found: {dump}[/red]")
        raise typer.Exit(1)

    engine = VolatilityEngine(dump)
    with console.status("[cyan]Extracting DLL list...[/cyan]"):
        result = engine.list_dlls(pid=pid if pid else None)

    if not result.success:
        rprint(f"[red]✘ Failed: {result.error}[/red]")
        raise typer.Exit(1)

    table = Table(title=f"DLLs — {dump.name}", show_lines=True)
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("Base", style="dim")
    table.add_column("Size", justify="right")
    table.add_column("Name")
    table.add_column("Path")

    for row in result.data[:200]:  # Limit display
        table.add_row(
            str(row.get("PID") or ""),
            str(row.get("Base") or ""),
            str(row.get("Size") or ""),
            row.get("Name") or "",
            row.get("FullDllName") or row.get("Path") or "",
        )

    console.print(table)
    rprint(f"\n[dim]{result.row_count} DLL(s)[/dim]")


@memory_app.command("connections")
def cmd_memory_connections(
    dump: Path = typer.Argument(..., help="Memory dump file"),
) -> None:
    """Extract network connections from a memory dump."""
    from core.memory.volatility_engine import VolatilityEngine

    if not dump.exists():
        rprint(f"[red]Dump file not found: {dump}[/red]")
        raise typer.Exit(1)

    engine = VolatilityEngine(dump)
    with console.status("[cyan]Extracting network connections...[/cyan]"):
        result = engine.list_connections()

    if not result.success:
        rprint(f"[red]✘ Failed: {result.error}[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Network Connections — {dump.name}", show_lines=True)
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("Process")
    table.add_column("Proto")
    table.add_column("Local")
    table.add_column("Remote")
    table.add_column("State")
    table.add_column("Created")

    for row in result.data:
        table.add_row(
            str(row.get("PID") or ""),
            row.get("Owner") or "",
            row.get("Proto") or "",
            f"{row.get('LocalAddr', '')}:{row.get('LocalPort', '')}",
            f"{row.get('ForeignAddr', '')}:{row.get('ForeignPort', '')}",
            row.get("State") or "",
            str(row.get("CreateTime") or "")[:19],
        )

    console.print(table)
    rprint(f"\n[dim]{result.row_count} connection(s)[/dim]")


@memory_app.command("malfind")
def cmd_memory_malfind(
    dump: Path = typer.Argument(..., help="Memory dump file"),
) -> None:
    """Detect injected code and process hollowing (malfind)."""
    from core.memory.volatility_engine import VolatilityEngine

    if not dump.exists():
        rprint(f"[red]Dump file not found: {dump}[/red]")
        raise typer.Exit(1)

    engine = VolatilityEngine(dump)
    with console.status("[cyan]Running malfind...[/cyan]"):
        result = engine.detect_malware()

    if not result.success:
        rprint(f"[red]✘ Failed: {result.error}[/red]")
        raise typer.Exit(1)

    if not result.data:
        rprint("[green]✔ No injected code detected.[/green]")
        return

    table = Table(title=f"Malfind Results — {dump.name}", show_lines=True)
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("Process", style="red")
    table.add_column("Start", style="dim")
    table.add_column("End", style="dim")
    table.add_column("Tag")
    table.add_column("Protection")

    for row in result.data:
        table.add_row(
            str(row.get("PID") or ""),
            row.get("Process") or "",
            str(row.get("Start VPN") or ""),
            str(row.get("End VPN") or ""),
            row.get("Tag") or "",
            row.get("Protection") or "",
        )

    console.print(table)
    rprint(f"\n[bold red]⚠ {result.row_count} suspicious memory region(s) found[/bold red]")


@memory_app.command("timeline")
def cmd_memory_timeline(
    dump: Path = typer.Argument(..., help="Memory dump file"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Export timeline to JSON"),
    suspicious_only: bool = typer.Option(
        False, "--suspicious", "-s", help="Show only suspicious events"
    ),
) -> None:
    """Build a forensic timeline from memory artifacts."""
    from core.memory.timeline import MemoryTimeline

    if not dump.exists():
        rprint(f"[red]Dump file not found: {dump}[/red]")
        raise typer.Exit(1)

    tl = MemoryTimeline(dump)
    with console.status("[cyan]Building memory timeline...[/cyan]"):
        events = tl.build()

    if suspicious_only:
        events = tl.get_suspicious_events()

    summary = tl.summary()
    rprint(f"\n[bold cyan]Memory Timeline — {dump.name}[/bold cyan]")
    rprint(f"  Total events     : {summary['total_events']}")
    rprint(f"  Process events   : {summary['process_events']}")
    rprint(f"  Network events   : {summary['network_events']}")
    rprint(f"  [red]Suspicious events: {summary['suspicious_events']}[/red]")

    if events:
        table = Table(show_lines=True)
        table.add_column("Timestamp", style="dim")
        table.add_column("Type", style="cyan")
        table.add_column("PID", justify="right")
        table.add_column("Process")
        table.add_column("Description")
        table.add_column("⚠")

        for ev in events[:100]:
            table.add_row(
                ev.timestamp[:19],
                ev.event_type,
                str(ev.pid),
                ev.process_name,
                ev.description[:60],
                "[red]⚠[/red]" if ev.is_suspicious else "",
            )
        console.print(table)

    if output:
        tl.export_json(output)
        rprint(f"\n[green]✔ Timeline exported: {output}[/green]")


@memory_app.command("hashes")
def cmd_memory_hashes(
    dump: Path = typer.Argument(..., help="Memory dump file"),
) -> None:
    """Extract NTLM password hashes from memory (hashdump)."""
    from core.memory.volatility_engine import VolatilityEngine

    if not dump.exists():
        rprint(f"[red]Dump file not found: {dump}[/red]")
        raise typer.Exit(1)

    engine = VolatilityEngine(dump)
    with console.status("[cyan]Extracting hashes...[/cyan]"):
        result = engine.find_hashes()

    if not result.success:
        rprint(f"[red]✘ Failed: {result.error}[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Password Hashes — {dump.name}", show_lines=True)
    table.add_column("Username", style="cyan")
    table.add_column("RID", justify="right")
    table.add_column("LM Hash", style="dim")
    table.add_column("NT Hash", style="yellow")

    for row in result.data:
        table.add_row(
            row.get("Username") or "",
            str(row.get("RID") or ""),
            row.get("LMHash") or "aad3b435b51404eeaad3b435b51404ee",
            row.get("NTHash") or "",
        )

    console.print(table)
    rprint(f"\n[dim]{result.row_count} hash(es) extracted[/dim]")


@memory_app.command("export")
def cmd_memory_export(
    dump: Path = typer.Argument(..., help="Memory dump file (.raw, .lime, .dmp)"),
    output: Path = typer.Option(None, "--output", "-o", help="Output JSON file (default: <dump>.processes.json)"),
    include_connections: bool = typer.Option(True, "--connections/--no-connections", help="Also export network connections"),
    include_dlls: bool = typer.Option(False, "--dlls/--no-dlls", help="Also export loaded DLLs (slow on large dumps)"),
    virustotal: bool = typer.Option(False, "--virustotal", "-v", help="Enrich process hashes via VirusTotal API"),
    vt_api_key: str = typer.Option("", "--vt-key", envvar="VT_API_KEY", help="VirusTotal API key (or set VT_API_KEY env var)"),
    yara_dir: Path = typer.Option(None, "--yara-rules", "-y", help="Directory of .yar/.yara rules to scan process names against"),
) -> None:
    """Export all processes from a memory dump to JSON for YARA/VirusTotal analysis."""
    import json as _json
    import hashlib
    import urllib.request
    import urllib.error
    from datetime import datetime, timezone
    from core.memory.volatility_engine import VolatilityEngine

    if not dump.exists():
        rprint(f"[red]Dump file not found: {dump}[/red]")
        raise typer.Exit(1)

    out_path = output or dump.with_suffix(".processes.json")
    engine = VolatilityEngine(dump)

    report: dict = {
        "dump": str(dump.resolve()),
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "processes": [],
        "connections": [],
        "dlls": [],
        "yara_hits": [],
        "virustotal": [],
    }

    # ── Processes ─────────────────────────────────────────────────────────────
    with console.status("[cyan]Extracting processes...[/cyan]"):
        proc_result = engine.list_processes()

    if not proc_result.success:
        rprint(f"[red]✘ Process extraction failed: {proc_result.error}[/red]")
        raise typer.Exit(1)

    report["processes"] = proc_result.data
    rprint(f"  [green]✔[/green] Processes    : {proc_result.row_count}")

    # ── Network connections ───────────────────────────────────────────────────
    if include_connections:
        with console.status("[cyan]Extracting network connections...[/cyan]"):
            conn_result = engine.list_connections()
        if conn_result.success:
            report["connections"] = conn_result.data
            rprint(f"  [green]✔[/green] Connections  : {conn_result.row_count}")
        else:
            rprint(f"  [yellow]—[/yellow] Connections  : {conn_result.error[:60]}")

    # ── DLLs ─────────────────────────────────────────────────────────────────
    if include_dlls:
        with console.status("[cyan]Extracting DLLs (this may take a while)...[/cyan]"):
            dll_result = engine.list_dlls()
        if dll_result.success:
            report["dlls"] = dll_result.data
            rprint(f"  [green]✔[/green] DLLs         : {dll_result.row_count}")
        else:
            rprint(f"  [yellow]—[/yellow] DLLs         : {dll_result.error[:60]}")

    # ── YARA ──────────────────────────────────────────────────────────────────
    if yara_dir and yara_dir.exists():
        try:
            import yara
            rule_files = list(yara_dir.glob("**/*.yar")) + list(yara_dir.glob("**/*.yara"))
            if rule_files:
                yara_hits: list[dict] = []
                with console.status(f"[cyan]Scanning with {len(rule_files)} YARA rule(s)...[/cyan]"):
                    for proc in report["processes"]:
                        name = proc.get("ImageFileName") or proc.get("Name") or ""
                        path = proc.get("Path") or proc.get("ImagePathName") or ""
                        scan_text = f"{name} {path}".encode()
                        for rf in rule_files:
                            try:
                                rules = yara.compile(str(rf))
                                matches = rules.match(data=scan_text)
                                for m in matches:
                                    yara_hits.append({
                                        "pid": proc.get("PID") or proc.get("pid"),
                                        "process": name,
                                        "rule": m.rule,
                                        "tags": list(m.tags),
                                        "rule_file": str(rf.name),
                                    })
                            except Exception:
                                pass
                report["yara_hits"] = yara_hits
                if yara_hits:
                    rprint(f"  [red]⚠[/red]  YARA hits    : {len(yara_hits)}")
                else:
                    rprint(f"  [green]✔[/green] YARA hits    : 0 (clean)")
            else:
                rprint(f"  [yellow]—[/yellow] YARA         : no .yar files in {yara_dir}")
        except ImportError:
            rprint("  [yellow]—[/yellow] YARA         : yara-python not installed (pip install yara-python)")

    # ── VirusTotal ────────────────────────────────────────────────────────────
    if virustotal:
        if not vt_api_key:
            rprint("  [red]✘[/red] VirusTotal   : no API key — use --vt-key or set VT_API_KEY env var")
        else:
            vt_results: list[dict] = []
            # Collect unique process image paths/hashes for lookup
            unique_names: set[str] = set()
            for proc in report["processes"]:
                name = (proc.get("ImageFileName") or proc.get("Name") or "").strip()
                if name and name not in unique_names:
                    unique_names.add(name)

            rprint(f"  [cyan]Querying VirusTotal for {len(unique_names)} unique process name(s)...[/cyan]")

            for name in sorted(unique_names):
                # Search VT for the process name
                try:
                    url = f"https://www.virustotal.com/api/v3/search?query={urllib.parse.quote(name)}"
                    req = urllib.request.Request(url, headers={"x-apikey": vt_api_key})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        data = _json.loads(resp.read())
                    hits = data.get("data", [])
                    if hits:
                        item = hits[0]
                        stats = item.get("attributes", {}).get("last_analysis_stats", {})
                        vt_results.append({
                            "process": name,
                            "vt_id": item.get("id", ""),
                            "malicious": stats.get("malicious", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "undetected": stats.get("undetected", 0),
                            "vt_link": f"https://www.virustotal.com/gui/file/{item.get('id', '')}",
                        })
                except urllib.error.HTTPError as e:
                    if e.code == 429:
                        rprint("  [yellow]⚠ VirusTotal rate limit hit — remaining results skipped[/yellow]")
                        break
                    vt_results.append({"process": name, "error": str(e)})
                except Exception as e:
                    vt_results.append({"process": name, "error": str(e)})

            report["virustotal"] = vt_results
            malicious = [r for r in vt_results if r.get("malicious", 0) > 0]
            if malicious:
                rprint(f"  [red]⚠[/red]  VirusTotal   : {len(malicious)} malicious detection(s)")
                for r in malicious:
                    rprint(f"    [red]{r['process']}[/red] — {r['malicious']} engine(s) detected")
            else:
                rprint(f"  [green]✔[/green] VirusTotal   : {len(vt_results)} queried, 0 malicious")

    # ── Write JSON ────────────────────────────────────────────────────────────
    out_path.write_text(
        _json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )

    rprint(f"\n[bold green]✔ Export complete[/bold green]")
    rprint(f"  Output  : [cyan]{out_path}[/cyan]")
    rprint(f"  Size    : {out_path.stat().st_size // 1024} KB")
    rprint(f"\n[dim]JSON structure:[/dim]")
    rprint(f"  [dim]processes ({len(report['processes'])}) — connections ({len(report['connections'])}) — yara_hits ({len(report['yara_hits'])}) — virustotal ({len(report['virustotal'])})[/dim]")


# ── Auth app ──────────────────────────────────────────────────────────────────
auth_app = typer.Typer(help="User authentication and access control")
# app.add_typer(auth_app, name="auth")


@auth_app.command("enable")
def cmd_auth_enable() -> None:
    """
    Enable authentication for ForgeLens.
    After this, every command requires a valid login.
    You will be prompted to create an admin account on first login.
    """
    from core.auth.gate import gate
    if gate.is_enabled():
        rprint("[yellow]Authentication is already enabled.[/yellow]")
        return
    # Ensure at least one user exists before enabling
    users = gate.list_users()
    if not users:
        rprint("[bold]No users exist yet. Create an admin account first.[/bold]")
        import getpass
        username = input("  Admin username: ").strip()
        if not username:
            rprint("[red]Username cannot be empty.[/red]")
            raise typer.Exit(1)
        password = getpass.getpass("  Admin password (min 8 chars): ")
        if len(password) < 8:
            rprint("[red]Password must be at least 8 characters.[/red]")
            raise typer.Exit(1)
        confirm = getpass.getpass("  Confirm password: ")
        if password != confirm:
            rprint("[red]Passwords do not match.[/red]")
            raise typer.Exit(1)
        from core.remote.rbac import Role
        gate.create_user(username, Role.ADMIN, password)
        rprint(f"[green]✔ Admin account '{username}' created.[/green]")

    gate.enable()
    rprint("\n[bold green]✔ Authentication ENABLED[/bold green]")
    rprint("[dim]From now on, every ForgeLens command requires a valid login.[/dim]")
    rprint("[dim]Login with: python forgelens.py auth login[/dim]")


@auth_app.command("disable")
def cmd_auth_disable(
    force: bool = typer.Option(False, "--force", "-f",
                               help="Skip confirmation prompt"),
) -> None:
    """
    Disable authentication (single-analyst offline mode).
    All users will still exist — re-enable any time.
    """
    from core.auth.gate import gate
    if not gate.is_enabled():
        rprint("[yellow]Authentication is already disabled.[/yellow]")
        return
    if not force:
        confirm = typer.confirm(
            "Disable authentication? Anyone with access to this machine can run ForgeLens."
        )
        if not confirm:
            rprint("[yellow]Aborted.[/yellow]")
            raise typer.Exit()
    gate.disable(confirm=True)
    rprint("[bold yellow]⚠ Authentication DISABLED — all commands are now open.[/bold yellow]")


@auth_app.command("login")
def cmd_auth_login(
    username: str = typer.Option("", "--username", "-u", help="Username"),
) -> None:
    """Log in and create a local session (valid for 8 hours)."""
    import getpass
    from core.auth.gate import gate

    if not gate.is_enabled():
        rprint("[yellow]Auth is disabled — no login required.[/yellow]")
        rprint("[dim]Enable with: python forgelens.py auth enable[/dim]")
        return

    existing = gate.whoami()
    if existing:
        rprint(f"[green]Already logged in as {existing.username} [{existing.role}][/green]")
        rprint(f"[dim]Session expires in {existing.expires_in_minutes}m[/dim]")
        rprint("[dim]Use 'auth logout' to log out.[/dim]")
        return

    if not username:
        username = input("  Username: ").strip()

    password = getpass.getpass("  Password: ")

    try:
        session = gate.login(username, password)
    except PermissionError as exc:
        rprint(f"[bold red]{exc}[/bold red]")
        raise typer.Exit(1)

    if not session:
        rprint("[bold red]✘ Invalid credentials.[/bold red]")
        raise typer.Exit(1)

    rprint(f"\n[bold green]✔ Logged in as {session.username} [{session.role}][/bold green]")
    rprint(f"[dim]Session valid for {session.expires_in_minutes} minutes.[/dim]")


@auth_app.command("logout")
def cmd_auth_logout() -> None:
    """Log out and invalidate the current session."""
    from core.auth.gate import gate
    session = gate.whoami()
    if not session:
        rprint("[yellow]No active session.[/yellow]")
        return
    gate.logout()
    rprint(f"[green]✔ Logged out ({session.username})[/green]")


@auth_app.command("whoami")
def cmd_auth_whoami() -> None:
    """Show the currently logged-in user and session info."""
    from core.auth.gate import gate

    enabled = gate.is_enabled()
    rprint(f"  Auth enabled : {'[green]Yes[/green]' if enabled else '[yellow]No[/yellow]'}")

    if not enabled:
        rprint("  [dim]Run 'auth enable' to require login.[/dim]")
        return

    session = gate.whoami()
    if session:
        rprint(f"  User         : [cyan]{session.username}[/cyan]")
        rprint(f"  Role         : {session.role}")
        rprint(f"  Expires in   : {session.expires_in_minutes} minute(s)")
        rprint(f"  Logged in at : {__import__('datetime').datetime.fromtimestamp(session.created_at).strftime('%Y-%m-%d %H:%M')}")
    else:
        rprint("  [yellow]Not logged in.[/yellow]")
        rprint("  [dim]Run 'auth login' to authenticate.[/dim]")


@auth_app.command("status")
def cmd_auth_status() -> None:
    """Show auth status, all users, and active session."""
    from core.auth.gate import gate

    enabled = gate.is_enabled()
    rprint(f"\n[bold cyan]ForgeLens — Auth Status[/bold cyan]")
    rprint(f"  Auth gate : {'[bold green]ENABLED[/bold green]' if enabled else '[bold yellow]DISABLED[/bold yellow]'}")

    session = gate.whoami()
    if session:
        rprint(f"  Session   : [green]{session.username}[/green] [{session.role}] — {session.expires_in_minutes}m remaining")
    else:
        rprint(f"  Session   : [dim]none[/dim]")

    users = gate.list_users()
    if users:
        rprint(f"\n  [bold]Users ({len(users)}):[/bold]")
        table = Table(show_lines=True, border_style="dim")
        table.add_column("Username", style="cyan")
        table.add_column("Role")
        table.add_column("Active")
        table.add_column("Last Login", style="dim")
        for u in users:
            active_str = "[green]Yes[/green]" if u.is_active else "[red]No[/red]"
            table.add_row(
                u.username,
                u.role.value,
                active_str,
                (u.last_login[:16] if u.last_login else "never"),
            )
        console.print(table)
    else:
        rprint("  [dim]No users created yet.[/dim]")


@auth_app.command("user-add")
def cmd_auth_user_add(
    username: str = typer.Argument(..., help="New username"),
    role: str = typer.Option("examiner", "--role", "-r",
                             help="Role: admin|examiner|analyst|viewer"),
    email: str = typer.Option("", "--email", "-e"),
    full_name: str = typer.Option("", "--name", "-n"),
) -> None:
    """Add a new user (admin only)."""
    import getpass
    from core.auth.gate import gate
    from core.remote.rbac import Role

    try:
        role_enum = Role(role.lower())
    except ValueError:
        rprint(f"[red]Invalid role '{role}'. Choose: admin|examiner|analyst|viewer[/red]")
        raise typer.Exit(1)

    password = getpass.getpass(f"  Password for '{username}' (min 8 chars): ")
    if len(password) < 8:
        rprint("[red]Password must be at least 8 characters.[/red]")
        raise typer.Exit(1)
    confirm = getpass.getpass("  Confirm password: ")
    if password != confirm:
        rprint("[red]Passwords do not match.[/red]")
        raise typer.Exit(1)

    try:
        gate.create_user(username, role_enum, password, email, full_name)
        rprint(f"[green]✔ User '{username}' created with role '{role}'[/green]")
    except ValueError as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(1)


@auth_app.command("user-remove")
def cmd_auth_user_remove(
    username: str = typer.Argument(..., help="Username to deactivate"),
    force: bool = typer.Option(False, "--force", "-f"),
) -> None:
    """Deactivate a user account (they cannot log in, data is preserved)."""
    from core.auth.gate import gate

    if not force:
        confirm = typer.confirm(f"Deactivate user '{username}'?")
        if not confirm:
            raise typer.Exit()

    ok = gate.deactivate_user(username)
    if ok:
        rprint(f"[green]✔ User '{username}' deactivated.[/green]")
    else:
        rprint(f"[red]User '{username}' not found.[/red]")
        raise typer.Exit(1)


@auth_app.command("user-role")
def cmd_auth_user_role(
    username: str = typer.Argument(..., help="Username"),
    role: str = typer.Argument(..., help="New role: admin|examiner|analyst|viewer"),
) -> None:
    """Change a user's role."""
    from core.auth.gate import gate
    from core.remote.rbac import Role

    try:
        role_enum = Role(role.lower())
    except ValueError:
        rprint(f"[red]Invalid role. Choose: admin|examiner|analyst|viewer[/red]")
        raise typer.Exit(1)

    ok = gate.update_role(username, role_enum)
    if ok:
        rprint(f"[green]✔ '{username}' role updated to '{role}'[/green]")
    else:
        rprint(f"[red]User '{username}' not found.[/red]")
        raise typer.Exit(1)


@auth_app.command("passwd")
def cmd_auth_passwd(
    username: str = typer.Argument(..., help="Username to update"),
) -> None:
    """Change a user's password."""
    import getpass
    from core.auth.gate import gate

    new_pw = getpass.getpass(f"  New password for '{username}' (min 8 chars): ")
    if len(new_pw) < 8:
        rprint("[red]Password must be at least 8 characters.[/red]")
        raise typer.Exit(1)
    confirm = getpass.getpass("  Confirm new password: ")
    if new_pw != confirm:
        rprint("[red]Passwords do not match.[/red]")
        raise typer.Exit(1)

    ok = gate.change_password(username, new_pw)
    if ok:
        rprint(f"[green]✔ Password updated for '{username}'[/green]")
        # Invalidate existing sessions for that user
        gate.logout()
        rprint("[dim]Existing sessions invalidated — please log in again.[/dim]")
    else:
        rprint(f"[red]User '{username}' not found.[/red]")
        raise typer.Exit(1)


# ── Setup app ────────────────────────────────────────────────────────────────
setup_app = typer.Typer(help="Check and install ForgeLens tool dependencies")
app.add_typer(setup_app, name="setup")


@setup_app.command("check")
def cmd_setup_check(
    all_platforms: bool = typer.Option(
        False, "--all", "-a", help="Show checks for all platforms, not just current OS"
    ),
) -> None:
    """Check all tool and package dependencies for ForgeLens."""
    from core.setup.checker import SetupChecker, Status
    import platform as _platform

    rprint(f"\n[bold cyan]ForgeLens — Dependency Check[/bold cyan]")
    rprint(f"[dim]Platform: {_platform.system()} {_platform.machine()}[/dim]\n")

    with console.status("[cyan]Checking dependencies...[/cyan]"):
        report = SetupChecker().check_all()

    # ── Required ──────────────────────────────────────────────────────────────
    req_table = Table(title="Required", show_lines=True, border_style="cyan")
    req_table.add_column("Tool", style="bold")
    req_table.add_column("Status", justify="center")
    req_table.add_column("Version", style="dim")
    req_table.add_column("Description")
    req_table.add_column("Fix")

    for c in report.checks:
        if not c.required:
            continue
        if c.status == Status.SKIPPED and not all_platforms:
            continue
        status_str = {
            Status.OK:               "[green]✔  OK[/green]",
            Status.MISSING:          "[red]✘  MISSING[/red]",
            Status.OPTIONAL_MISSING: "[yellow]⚠  MISSING[/yellow]",
            Status.SKIPPED:          "[dim]—  N/A[/dim]",
        }[c.status]
        req_table.add_row(c.name, status_str, c.version or "—", c.description,
                          c.install_hint[:50] if c.status != Status.OK else "")
    console.print(req_table)

    # ── Optional ──────────────────────────────────────────────────────────────
    opt_table = Table(title="Optional", show_lines=True, border_style="dim")
    opt_table.add_column("Tool", style="bold")
    opt_table.add_column("Status", justify="center")
    opt_table.add_column("Version", style="dim")
    opt_table.add_column("Description")

    for c in report.checks:
        if c.required:
            continue
        if c.status == Status.SKIPPED and not all_platforms:
            continue
        status_str = {
            Status.OK:               "[green]✔[/green]",
            Status.MISSING:          "[red]✘[/red]",
            Status.OPTIONAL_MISSING: "[yellow]—[/yellow]",
            Status.SKIPPED:          "[dim]N/A[/dim]",
        }[c.status]
        opt_table.add_row(c.name, status_str, c.version or "—", c.description)
    console.print(opt_table)

    # ── Summary ───────────────────────────────────────────────────────────────
    ok_count = len(report.ok)
    missing_count = len(report.missing)
    opt_missing = len(report.optional_missing)

    rprint(f"\n[bold]Summary:[/bold] {ok_count} OK  |  "
           f"[red]{missing_count} required missing[/red]  |  "
           f"[yellow]{opt_missing} optional missing[/yellow]")

    if report.missing:
        rprint("\n[bold red]Required tools are missing. Run:[/bold red]")
        rprint("  [cyan]python forgelens.py setup install[/cyan]")
    elif opt_missing:
        rprint("\n[dim]To install optional tools:[/dim]")
        rprint("  [cyan]python forgelens.py setup install --optional[/cyan]")
    else:
        rprint("\n[bold green]✔ All dependencies satisfied.[/bold green]")


@setup_app.command("mounter")
def cmd_setup_mounter(
    tool: str = typer.Option("aim", "--tool", "-t", help="Tool to setup: aim | imdisk | all"),
) -> None:
    """Download open-source disk image mount tools (Arsenal Image Mounter / ImDisk)."""
    import importlib.util as _ilu
    from pathlib import Path as _P

    setup_script = _P(__file__).resolve().parents[2] / "tools" / "setup_mounter.py"
    if not setup_script.exists():
        rprint("[red]tools/setup_mounter.py not found.[/red]")
        raise typer.Exit(1)

    spec = _ilu.spec_from_file_location("setup_mounter", setup_script)
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)

    import sys as _sys
    _sys.argv = ["setup_mounter", "--tool", tool]
    rc = mod.main()
    raise typer.Exit(rc or 0)
def cmd_setup_check(
    all_platforms: bool = typer.Option(
        False, "--all", "-a", help="Show checks for all platforms, not just current OS"
    ),
) -> None:
    """Check all tool and package dependencies for ForgeLens."""
    from core.setup.checker import SetupChecker, Status
    import platform as _platform

    rprint(f"\n[bold cyan]ForgeLens — Dependency Check[/bold cyan]")
    rprint(f"[dim]Platform: {_platform.system()} {_platform.machine()}[/dim]\n")

    with console.status("[cyan]Checking dependencies...[/cyan]"):
        report = SetupChecker().check_all()

    # ── Required ──────────────────────────────────────────────────────────────
    req_table = Table(title="Required", show_lines=True, border_style="cyan")
    req_table.add_column("Tool", style="bold")
    req_table.add_column("Status", justify="center")
    req_table.add_column("Version", style="dim")
    req_table.add_column("Description")
    req_table.add_column("Fix")

    for c in report.checks:
        if not c.required:
            continue
        if c.status == Status.SKIPPED and not all_platforms:
            continue
        status_str = {
            Status.OK:               "[green]✔  OK[/green]",
            Status.MISSING:          "[red]✘  MISSING[/red]",
            Status.OPTIONAL_MISSING: "[yellow]⚠  MISSING[/yellow]",
            Status.SKIPPED:          "[dim]—  N/A[/dim]",
        }[c.status]
        req_table.add_row(c.name, status_str, c.version or "—", c.description,
                          c.install_hint[:50] if c.status != Status.OK else "")
    console.print(req_table)

    # ── Optional ──────────────────────────────────────────────────────────────
    opt_table = Table(title="Optional", show_lines=True, border_style="dim")
    opt_table.add_column("Tool", style="bold")
    opt_table.add_column("Status", justify="center")
    opt_table.add_column("Version", style="dim")
    opt_table.add_column("Description")

    for c in report.checks:
        if c.required:
            continue
        if c.status == Status.SKIPPED and not all_platforms:
            continue
        status_str = {
            Status.OK:               "[green]✔[/green]",
            Status.MISSING:          "[red]✘[/red]",
            Status.OPTIONAL_MISSING: "[yellow]—[/yellow]",
            Status.SKIPPED:          "[dim]N/A[/dim]",
        }[c.status]
        opt_table.add_row(c.name, status_str, c.version or "—", c.description)
    console.print(opt_table)

    # ── Summary ───────────────────────────────────────────────────────────────
    ok_count = len(report.ok)
    missing_count = len(report.missing)
    opt_missing = len(report.optional_missing)

    rprint(f"\n[bold]Summary:[/bold] {ok_count} OK  |  "
           f"[red]{missing_count} required missing[/red]  |  "
           f"[yellow]{opt_missing} optional missing[/yellow]")

    if report.missing:
        rprint("\n[bold red]Required tools are missing. Run:[/bold red]")
        rprint("  [cyan]python forgelens.py setup install[/cyan]")
    elif opt_missing:
        rprint("\n[dim]To install optional tools:[/dim]")
        rprint("  [cyan]python forgelens.py setup install --optional[/cyan]")
    else:
        rprint("\n[bold green]✔ All dependencies satisfied.[/bold green]")


@setup_app.command("install")
def cmd_setup_install(
    optional: bool = typer.Option(
        False, "--optional", "-o", help="Also install optional tools"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be installed without doing it"
    ),
) -> None:
    """Install missing ForgeLens dependencies automatically where possible."""
    from core.setup.checker import SetupChecker, Status

    rprint(f"\n[bold cyan]ForgeLens — Dependency Installer[/bold cyan]")
    if dry_run:
        rprint("[yellow]DRY RUN — nothing will be installed[/yellow]\n")

    with console.status("[cyan]Checking dependencies...[/cyan]"):
        checker = SetupChecker()
        report = checker.check_all()

    targets = report.missing[:]
    if optional:
        targets += report.optional_missing

    auto = [c for c in targets if c.auto_installable]
    manual = [c for c in targets if not c.auto_installable]

    if not targets:
        rprint("[bold green]✔ Nothing to install — all dependencies satisfied.[/bold green]")
        return

    if auto:
        rprint(f"[bold]Auto-installing {len(auto)} tool(s):[/bold]")
        for c in auto:
            rprint(f"  [cyan]{c.name}[/cyan] — {c.description}")
        rprint()

        results = checker.install_missing(report, include_optional=optional, dry_run=dry_run)

        for name, success in results.items():
            if success:
                rprint(f"  [green]✔[/green] {name}")
            else:
                rprint(f"  [red]✘[/red] {name} — install manually")

    if manual:
        rprint(f"\n[bold yellow]Manual installation required for {len(manual)} tool(s):[/bold yellow]")
        for c in manual:
            rprint(f"\n  [bold]{c.name}[/bold] — {c.description}")
            for line in c.install_hint.splitlines():
                rprint(f"    [dim]{line}[/dim]")

    if not dry_run:
        rprint("\n[dim]Re-run 'python forgelens.py setup check' to verify.[/dim]")


@setup_app.command("info")
def cmd_setup_info() -> None:
    """Show detailed install instructions for every tool."""
    from core.setup.checker import SetupChecker, Status
    import platform as _platform

    report = SetupChecker().check_all()

    rprint(f"\n[bold cyan]ForgeLens — Tool Reference[/bold cyan]")
    rprint(f"[dim]Platform: {_platform.system()}[/dim]\n")

    categories = {
        "Memory Acquisition":   ["WinPmem", "AVML"],
        "Mobile":               ["ADB", "libimobiledevice", "pymobiledevice3"],
        "Memory Analysis":      ["Volatility3"],
        "Artifact Detection":   ["yara-python"],
        "Hashing":              ["blake3"],
        "Imaging":              ["pyewf", "pytsk3"],
        "Reporting":            ["reportlab"],
        "Encryption":           ["cryptography"],
        "Cloud / Container":    ["Docker CLI", "AWS CLI", "Azure CLI", "kubectl"],
    }

    check_map = {c.name: c for c in report.checks}

    for category, names in categories.items():
        rprint(f"[bold underline]{category}[/bold underline]")
        for name in names:
            c = check_map.get(name)
            if not c:
                continue
            status_icon = {
                Status.OK:               "[green]✔[/green]",
                Status.MISSING:          "[red]✘[/red]",
                Status.OPTIONAL_MISSING: "[yellow]—[/yellow]",
                Status.SKIPPED:          "[dim]N/A[/dim]",
            }[c.status]
            req = "[red]required[/red]" if c.required else "[dim]optional[/dim]"
            rprint(f"  {status_icon} [bold]{name}[/bold] ({req})")
            rprint(f"     {c.description}")
            if c.install_hint:
                for line in c.install_hint.splitlines():
                    rprint(f"     [dim]{line}[/dim]")
        rprint()


# ── Platform acquisition apps ─────────────────────────────────────────────────
acquire_app = typer.Typer(help="Platform-specific acquisition (Windows/Linux/macOS/Android/iOS/MS-DOS)")
# app.add_typer(acquire_app, name="acquire")


# ── Windows ───────────────────────────────────────────────────────────────────

@acquire_app.command("windows")
def cmd_acquire_windows(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Examiner name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    artifacts: bool = typer.Option(True, "--artifacts/--no-artifacts", help="Collect live artifacts (processes, network, registry)"),
    memory: bool = typer.Option(False, "--memory/--no-memory", help="Acquire RAM dump via WinPmem"),
    notes: str = typer.Option("", "--notes", "-n", help="Acquisition notes"),
    location: str = typer.Option("", "--location", "-l", help="Lab or location"),
) -> None:
    """Acquire artifacts from a live Windows system (processes, network, registry, RAM)."""
    import platform as _platform
    if _platform.system() != "Windows":
        rprint("[red]Windows acquisition requires a Windows host.[/red]")
        raise typer.Exit(1)

    from platforms.windows.live_response import collect_all_live_response
    from platforms.windows.enumeration import enumerate_physical_drives, get_windows_version, get_bitlocker_status
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.acquisition.metadata_collector import MetadataCollector, DeviceMetadata
    import json

    rprint("\n[bold cyan]ForgeLens — Windows Acquisition[/bold cyan]")
    rprint(f"  Case     : {case_id}")
    rprint(f"  Examiner : {examiner}")
    rprint(f"  Output   : {output}")
    rprint(f"  Artifacts: {'Yes' if artifacts else 'No'}")
    rprint(f"  Memory   : {'Yes' if memory else 'No'}\n")

    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)

    meta = MetadataCollector.new_session(
        case_id=case_id, examiner=examiner, device_id="Windows-Live",
        acquisition_method="live", notes=notes, geo_location=location,
        device_meta=DeviceMetadata(device_id="Windows-Live", model="Live Windows System"),
    )
    mgr = EvidenceManager()
    ev_dir = mgr.create_evidence_entry(meta)

    results: dict = {"platform": "windows", "evidence_id": meta.evidence_id}

    if artifacts:
        with console.status("[cyan]Collecting live response data...[/cyan]"):
            sys_info = get_windows_version()
            drives = enumerate_physical_drives()
            bitlocker = get_bitlocker_status()
            live = collect_all_live_response()

        results["system_info"] = vars(sys_info)
        results["drives"] = [vars(d) for d in drives]
        results["bitlocker"] = [vars(b) for b in bitlocker]
        results.update(live)

        artifact_path = ev_dir / "windows_artifacts.json"
        artifact_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")

        rprint(f"  [green]✔[/green] Processes   : {len(live.get('processes', []))}")
        rprint(f"  [green]✔[/green] Connections : {len(live.get('network_connections', []))}")
        rprint(f"  [green]✔[/green] Tasks       : {len(live.get('scheduled_tasks', []))}")
        rprint(f"  [green]✔[/green] Drives      : {len(drives)}")
        rprint(f"  [green]✔[/green] BitLocker   : {len(bitlocker)} volume(s) checked")

    if memory:
        rprint("\n[cyan]Acquiring RAM...[/cyan]")
        from platforms.windows.memory import acquire_ram
        ram_result = acquire_ram(
            output_path=ev_dir / f"{meta.evidence_id}.raw",
            case_id=case_id, examiner=examiner, notes=notes,
        )
        if ram_result.success:
            rprint(f"  [green]✔[/green] RAM dump    : {ram_result.size_gb} GB | SHA256: {ram_result.hash_sha256[:16]}...")
        else:
            rprint(f"  [red]✘[/red] RAM failed  : {ram_result.error}")

    meta = MetadataCollector.finalize(meta, output_path=str(ev_dir))
    mgr.write_metadata(meta)

    rprint(f"\n[bold green]✔ Windows acquisition complete[/bold green]")
    rprint(f"  Evidence ID : [cyan]{meta.evidence_id}[/cyan]")
    rprint(f"  Output      : {ev_dir}")


# ── Linux ─────────────────────────────────────────────────────────────────────

@acquire_app.command("linux")
def cmd_acquire_linux(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Examiner name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    artifacts: bool = typer.Option(True, "--artifacts/--no-artifacts", help="Collect artifacts"),
    memory: bool = typer.Option(False, "--memory/--no-memory", help="Acquire RAM via AVML/LiME"),
    notes: str = typer.Option("", "--notes", "-n", help="Acquisition notes"),
    location: str = typer.Option("", "--location", "-l", help="Lab or location"),
) -> None:
    """Acquire artifacts from a live Linux system (block devices, artifacts, RAM)."""
    import platform as _platform
    if _platform.system() != "Linux":
        rprint("[red]Linux acquisition requires a Linux host.[/red]")
        raise typer.Exit(1)

    from platforms.linux import LinuxAcquisition

    rprint("\n[bold cyan]ForgeLens — Linux Acquisition[/bold cyan]")
    rprint(f"  Case     : {case_id}")
    rprint(f"  Examiner : {examiner}")
    rprint(f"  Output   : {output}\n")

    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.acquisition.metadata_collector import MetadataCollector, DeviceMetadata

    meta = MetadataCollector.new_session(
        case_id=case_id, examiner=examiner, device_id="Linux-Live",
        acquisition_method="live", notes=notes, geo_location=location,
        device_meta=DeviceMetadata(device_id="Linux-Live", model="Live Linux System"),
    )
    mgr = EvidenceManager()
    ev_dir = mgr.create_evidence_entry(meta)

    with console.status("[cyan]Collecting Linux artifacts...[/cyan]"):
        summary = LinuxAcquisition.collect_all(
            output_dir=ev_dir,
            include_artifacts=artifacts,
            include_ram=memory,
            ram_output_path=ev_dir / f"{meta.evidence_id}.lime" if memory else None,
        )

    meta = MetadataCollector.finalize(meta, output_path=str(ev_dir))
    mgr.write_metadata(meta)

    rprint(f"[bold green]✔ Linux acquisition complete[/bold green]")
    rprint(f"  Evidence ID   : [cyan]{meta.evidence_id}[/cyan]")
    rprint(f"  Block devices : {summary['counts'].get('block_devices', 0)}")
    rprint(f"  LVM volumes   : {summary['counts'].get('lvm_volumes', 0)}")
    rprint(f"  Bash history  : {summary['counts'].get('bash_history', 0)}")
    rprint(f"  Output        : {ev_dir}")


# ── macOS ─────────────────────────────────────────────────────────────────────

@acquire_app.command("macos")
def cmd_acquire_macos(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Examiner name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    artifacts: bool = typer.Option(True, "--artifacts/--no-artifacts", help="Collect artifacts"),
    notes: str = typer.Option("", "--notes", "-n", help="Acquisition notes"),
    location: str = typer.Option("", "--location", "-l", help="Lab or location"),
) -> None:
    """Acquire artifacts from a live macOS system (APFS, FileVault, Safari, LaunchAgents)."""
    import platform as _platform
    if _platform.system() != "Darwin":
        rprint("[red]macOS acquisition requires a macOS host.[/red]")
        raise typer.Exit(1)

    from platforms.macos import MacOSAcquisition
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.acquisition.metadata_collector import MetadataCollector, DeviceMetadata

    rprint("\n[bold cyan]ForgeLens — macOS Acquisition[/bold cyan]")
    rprint(f"  Case     : {case_id}")
    rprint(f"  Examiner : {examiner}")
    rprint(f"  Output   : {output}\n")

    meta = MetadataCollector.new_session(
        case_id=case_id, examiner=examiner, device_id="macOS-Live",
        acquisition_method="live", notes=notes, geo_location=location,
        device_meta=DeviceMetadata(device_id="macOS-Live", model="Live macOS System"),
    )
    mgr = EvidenceManager()
    ev_dir = mgr.create_evidence_entry(meta)

    with console.status("[cyan]Collecting macOS artifacts...[/cyan]"):
        summary = MacOSAcquisition.collect_all(output_dir=ev_dir, include_artifacts=artifacts)

    meta = MetadataCollector.finalize(meta, output_path=str(ev_dir))
    mgr.write_metadata(meta)

    rprint(f"[bold green]✔ macOS acquisition complete[/bold green]")
    rprint(f"  Evidence ID    : [cyan]{meta.evidence_id}[/cyan]")
    rprint(f"  Disks          : {summary['counts'].get('disks', 0)}")
    rprint(f"  APFS containers: {summary['counts'].get('apfs_containers', 0)}")
    rprint(f"  Unified logs   : {summary['counts'].get('unified_logs', 0)}")
    rprint(f"  Safari history : {summary['counts'].get('safari_history', 0)}")
    rprint(f"  Output         : {ev_dir}")


# ── Android ───────────────────────────────────────────────────────────────────

@acquire_app.command("android")
def cmd_acquire_android(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Examiner name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    serial: str = typer.Option("", "--serial", "-s", help="Device serial (auto-detect if omitted)"),
    notes: str = typer.Option("", "--notes", "-n", help="Acquisition notes"),
    location: str = typer.Option("", "--location", "-l", help="Lab or location"),
) -> None:
    """Acquire logical artifacts from a connected Android device via ADB."""
    from platforms.android.acquisition import detect_devices, collect_all
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.acquisition.metadata_collector import MetadataCollector, DeviceMetadata

    with console.status("[cyan]Detecting Android devices...[/cyan]"):
        devices = detect_devices()

    if not devices:
        rprint("[red]No Android devices found. Check USB connection and ADB authorization.[/red]")
        rprint("[dim]Tip: enable USB debugging in Developer Options on the device.[/dim]")
        raise typer.Exit(1)

    # Pick device
    if serial:
        device = next((d for d in devices if d.serial == serial), None)
        if not device:
            rprint(f"[red]Device {serial} not found.[/red]")
            raise typer.Exit(1)
    else:
        device = devices[0]
        if len(devices) > 1:
            rprint(f"[yellow]Multiple devices found — using first: {device.serial}[/yellow]")
            for d in devices:
                rprint(f"  [dim]{d.serial} — {d.manufacturer} {d.model}[/dim]")

    rprint(f"\n[bold cyan]ForgeLens — Android Acquisition[/bold cyan]")
    rprint(f"  Device   : {device.manufacturer} {device.model}")
    rprint(f"  Serial   : {device.serial}")
    rprint(f"  Android  : {device.android_version}")
    rprint(f"  Rooted   : {'[red]Yes[/red]' if device.is_rooted else '[green]No[/green]'}")
    rprint(f"  Case     : {case_id}\n")

    meta = MetadataCollector.new_session(
        case_id=case_id, examiner=examiner, device_id=device.serial,
        acquisition_method="logical", notes=notes, geo_location=location,
        device_meta=DeviceMetadata(
            device_id=device.serial,
            model=f"{device.manufacturer} {device.model}",
            serial=device.serial,
            interface="USB/ADB",
        ),
    )
    mgr = EvidenceManager()
    ev_dir = mgr.create_evidence_entry(meta)

    with console.status("[cyan]Acquiring Android artifacts...[/cyan]"):
        results = collect_all(device.serial, ev_dir)

    with console.status("[cyan]Verifying Android acquired files...[/cyan]"):
        from core.hashing.hasher import Hasher, HashAlgorithm
        EXCLUDED_FILES = {
            "metadata.json",
            "metadata.signed.json",
            "logical_manifest.hashes",
            "acquisition.log",
            "chain_of_custody.json",
            "tags.json",
        }
        file_hashes = {}
        for path in ev_dir.rglob("*"):
            if path.is_file() and path.name not in EXCLUDED_FILES:
                rel_path = path.relative_to(ev_dir).as_posix()
                res = Hasher.hash_file(path, HashAlgorithm.SHA256)
                file_hashes[rel_path] = res.hex_digest

        mgr.write_logical_manifest(case_id, meta.evidence_id, file_hashes)
        verified = mgr.verify_logical_integrity(case_id, meta.evidence_id)

    meta = MetadataCollector.finalize(meta, output_path=str(ev_dir), verified=verified)
    mgr.write_metadata(meta)

    rprint(f"[bold green]✔ Android acquisition complete[/bold green]")
    rprint(f"  Evidence ID : [cyan]{meta.evidence_id}[/cyan]")
    rprint(f"  Apps        : {len(results.get('installed_apps', []))}")
    sms = results.get("sms", {})
    rprint(f"  SMS         : {'[green]✔[/green]' if not sms.get('error') else '[yellow]' + sms.get('error','') + '[/yellow]'}")
    contacts = results.get("contacts", {})
    rprint(f"  Contacts    : {'[green]✔[/green]' if not contacts.get('error') else '[yellow]' + contacts.get('error','') + '[/yellow]'}")
    whatsapp = results.get("whatsapp", {})
    rprint(f"  WhatsApp    : {'[green]✔[/green]' if not whatsapp.get('error') else '[yellow]' + whatsapp.get('error','') + '[/yellow]'}")
    telegram = results.get("telegram", {})
    rprint(f"  Telegram    : {'[green]✔[/green]' if not telegram.get('error') else '[yellow]' + telegram.get('error','') + '[/yellow]'}")
    gmail = results.get("gmail", {})
    rprint(f"  Gmail       : {'[green]✔[/green]' if not gmail.get('error') else '[yellow]' + gmail.get('error','') + '[/yellow]'}")
    googledrive = results.get("googledrive", {})
    rprint(f"  Google Drive: {'[green]✔[/green]' if not googledrive.get('error') else '[yellow]' + googledrive.get('error','') + '[/yellow]'}")
    googlephotos = results.get("googlephotos", {})
    rprint(f"  Google Photos: {'[green]✔[/green]' if not googlephotos.get('error') else '[yellow]' + googlephotos.get('error','') + '[/yellow]'}")
    signal = results.get("signal", {})
    rprint(f"  Signal      : {'[green]✔[/green]' if not signal.get('error') else '[yellow]' + signal.get('error','') + '[/yellow]'}")
    facebook = results.get("facebook", {})
    rprint(f"  Facebook    : {'[green]✔[/green]' if not facebook.get('error') else '[yellow]' + facebook.get('error','') + '[/yellow]'}")
    messenger = results.get("messenger", {})
    rprint(f"  Messenger   : {'[green]✔[/green]' if not messenger.get('error') else '[yellow]' + messenger.get('error','') + '[/yellow]'}")
    instagram = results.get("instagram", {})
    rprint(f"  Instagram   : {'[green]✔[/green]' if not instagram.get('error') else '[yellow]' + instagram.get('error','') + '[/yellow]'}")
    rprint(f"  Output      : {ev_dir}")


# ── iOS ───────────────────────────────────────────────────────────────────────

@acquire_app.command("ios")
def cmd_acquire_ios(
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Examiner name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    udid: str = typer.Option("", "--udid", "-u", help="Device UDID (auto-detect if omitted)"),
    backup: bool = typer.Option(True, "--backup/--no-backup", help="Extract iTunes backup"),
    media: bool = typer.Option(True, "--media/--no-media", help="Extract media via AFC"),
    notes: str = typer.Option("", "--notes", "-n", help="Acquisition notes"),
    location: str = typer.Option("", "--location", "-l", help="Lab or location"),
) -> None:
    """Acquire logical artifacts from a connected iOS device via libimobiledevice."""
    from platforms.ios.acquisition import detect_devices, collect_all, _get_device_info
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.acquisition.metadata_collector import MetadataCollector, DeviceMetadata

    with console.status("[cyan]Detecting iOS devices...[/cyan]"):
        devices = detect_devices()

    if not devices:
        rprint("[red]No iOS devices found.[/red]")
        rprint("[dim]Ensure the device is unlocked, trusted this computer, and libimobiledevice is installed.[/dim]")
        rprint("[dim]Install: https://libimobiledevice.org  or  pip install pymobiledevice3[/dim]")
        raise typer.Exit(1)

    device = next((d for d in devices if d.udid == udid), devices[0]) if udid else devices[0]
    if len(devices) > 1 and not udid:
        rprint(f"[yellow]Multiple devices — using first: {device.udid}[/yellow]")

    rprint(f"\n[bold cyan]ForgeLens — iOS Acquisition[/bold cyan]")
    rprint(f"  Device   : {device.name} ({device.product_type})")
    rprint(f"  UDID     : {device.udid}")
    rprint(f"  iOS      : {device.ios_version}")
    rprint(f"  Jailbreak: {'[red]Yes[/red]' if device.is_jailbroken else '[green]No[/green]'}")
    rprint(f"  Case     : {case_id}\n")

    meta = MetadataCollector.new_session(
        case_id=case_id, examiner=examiner, device_id=device.udid,
        acquisition_method="logical", notes=notes, geo_location=location,
        device_meta=DeviceMetadata(
            device_id=device.udid,
            model=device.product_type,
            serial=device.serial_number,
            interface="USB/libimobiledevice",
            is_encrypted=device.encryption_enabled,
        ),
    )
    mgr = EvidenceManager()
    ev_dir = mgr.create_evidence_entry(meta)

    with console.status("[cyan]Acquiring iOS artifacts (this may take a while)...[/cyan]"):
        results = collect_all(device.udid, ev_dir)

    meta = MetadataCollector.finalize(meta, output_path=str(ev_dir))
    mgr.write_metadata(meta)

    rprint(f"[bold green]✔ iOS acquisition complete[/bold green]")
    rprint(f"  Evidence ID : [cyan]{meta.evidence_id}[/cyan]")
    backup_r = results.get("itunes_backup", {})
    rprint(f"  Backup      : {'[green]✔[/green]' if not backup_r.get('error') else '[yellow]' + str(backup_r.get('error',''))[:60] + '[/yellow]'}")
    afc_r = results.get("afc", {})
    rprint(f"  AFC media   : {'[green]✔[/green]' if not afc_r.get('error') else '[yellow]' + str(afc_r.get('error',''))[:60] + '[/yellow]'}")
    rprint(f"  Output      : {ev_dir}")


# ── MS-DOS / Legacy FAT ───────────────────────────────────────────────────────

@acquire_app.command("msdos")
def cmd_acquire_msdos(
    source: str = typer.Option(..., "--source", "-s", help="Source device or image path"),
    case_id: str = typer.Option(..., "--case", "-c", help="Case ID"),
    examiner: str = typer.Option(..., "--examiner", "-e", help="Examiner name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    format: str = typer.Option("dd", "--format", "-f", help="Image format: dd | e01"),
    notes: str = typer.Option("", "--notes", "-n", help="Acquisition notes"),
    location: str = typer.Option("", "--location", "-l", help="Lab or location"),
) -> None:
    """Acquire a MS-DOS / legacy FAT disk image (sector-by-sector DD/E01)."""
    from core.imaging.imager import DiskImager, ImageFormat

    rprint("\n[bold cyan]ForgeLens — MS-DOS / Legacy Disk Acquisition[/bold cyan]")
    rprint(f"  Source   : [yellow]{source}[/yellow]")
    rprint(f"  Format   : {format.upper()}")
    rprint(f"  Case     : {case_id}")
    rprint(f"  Examiner : {examiner}\n")
    rprint("[dim]MS-DOS/FAT disks are acquired as sector-by-sector images (same as physical imaging).[/dim]\n")

    confirm = typer.confirm("Start acquisition?")
    if not confirm:
        rprint("[yellow]Aborted.[/yellow]")
        raise typer.Exit()

    fmt = ImageFormat(format.lower())
    imager = DiskImager()
    result = imager.acquire(
        source=source,
        output_dir=output,
        case_id=case_id,
        examiner=examiner,
        image_format=fmt,
        notes=notes or "MS-DOS/legacy FAT disk acquisition",
        geo_location=location,
        post_verify=True,
    )

    if result.success:
        rprint(f"\n[bold green]✔ MS-DOS acquisition complete[/bold green]")
        rprint(f"  Evidence ID : [cyan]{result.evidence_id}[/cyan]")
        rprint(f"  Image       : {result.image_path}")
        rprint(f"  SHA256      : {result.hash_sha256}")
        rprint(f"  Verified    : {'[green]PASS[/green]' if result.verified else '[red]FAIL[/red]'}")
        rprint(f"\n[dim]Analyse with pytsk3 or mount the image to browse FAT filesystem.[/dim]")
    else:
        rprint(f"\n[bold red]✘ Acquisition failed:[/bold red] {result.error}")
        raise typer.Exit(1)


# ── detect (cross-platform) ───────────────────────────────────────────────────

@acquire_app.command("detect")
def cmd_acquire_detect() -> None:
    """Detect all connected devices across all platforms (disks, Android, iOS, USB)."""
    import platform as _platform
    from core.acquisition.device_detector import DeviceDetector

    rprint("\n[bold cyan]ForgeLens — Device Detection[/bold cyan]\n")

    # Physical disks
    with console.status("[cyan]Scanning physical disks...[/cyan]"):
        disks = DeviceDetector.detect()

    if disks:
        table = Table(title="Physical Disks", show_lines=True)
        table.add_column("Device", style="cyan")
        table.add_column("Type")
        table.add_column("Model")
        table.add_column("Size (GB)", justify="right")
        table.add_column("Interface")
        table.add_column("Removable")
        for d in disks:
            table.add_row(d.device_id, d.device_type.value, d.label or "—",
                          str(d.size_gb), d.interface or "—", "Yes" if d.is_removable else "No")
        console.print(table)
    else:
        rprint("[yellow]No physical disks detected.[/yellow]")

    # Android
    with console.status("[cyan]Scanning for Android devices (ADB)...[/cyan]"):
        try:
            from platforms.android.acquisition import detect_devices as detect_android
            android_devs = detect_android()
        except Exception:
            android_devs = []

    if android_devs:
        table2 = Table(title="Android Devices", show_lines=True)
        table2.add_column("Serial", style="cyan")
        table2.add_column("Manufacturer")
        table2.add_column("Model")
        table2.add_column("Android")
        table2.add_column("Rooted")
        for d in android_devs:
            table2.add_row(d.serial, d.manufacturer, d.model, d.android_version,
                           "[red]Yes[/red]" if d.is_rooted else "No")
        console.print(table2)
    else:
        rprint("[dim]No Android devices detected (ADB).[/dim]")

    # iOS
    with console.status("[cyan]Scanning for iOS devices...[/cyan]"):
        try:
            from platforms.ios.acquisition import detect_devices as detect_ios
            ios_devs = detect_ios()
        except Exception:
            ios_devs = []

    if ios_devs:
        table3 = Table(title="iOS Devices", show_lines=True)
        table3.add_column("UDID", style="cyan")
        table3.add_column("Name")
        table3.add_column("Model")
        table3.add_column("iOS")
        table3.add_column("Jailbroken")
        for d in ios_devs:
            table3.add_row(d.udid, d.name, d.product_type, d.ios_version,
                           "[red]Yes[/red]" if d.is_jailbroken else "No")
        console.print(table3)
    else:
        rprint("[dim]No iOS devices detected (libimobiledevice/pymobiledevice3).[/dim]")

    total = len(disks) + len(android_devs) + len(ios_devs)
    rprint(f"\n[dim]Total: {total} device(s) found[/dim]")


# ── Offensive DFIR app ────────────────────────────────────────────────────────
dfir_app = typer.Typer(help="Offensive DFIR: persistence hunting, beacon detection, ransomware triage (v2.3)")
if "dfir" not in settings.features.disabled:
    app.add_typer(dfir_app, name="dfir")


def _print_dfir_report(report, label: str) -> None:
    """Pretty-print a DFIRReport to the terminal."""
    from core.dfir.offensive import DFIRReport
    critical = report.critical
    high = report.high

    rprint(f"\n[bold cyan]{'═'*60}[/bold cyan]")
    rprint(f"[bold]{label}[/bold]")
    rprint(f"[bold cyan]{'═'*60}[/bold cyan]")
    rprint(f"  Risk Level : {_risk_badge(report.risk_level)}")
    rprint(f"  Risk Score : {report.risk_score}/10")
    rprint(f"  Findings   : {len(report.findings)} total  |  "
           f"[red]{len(critical)} critical[/red]  |  "
           f"[yellow]{len(high)} high[/yellow]")
    rprint(f"  Summary    : {report.summary}\n")

    # Show critical + high findings
    shown = (critical + high)[:15]
    if shown:
        table = Table(show_lines=True, border_style="dim")
        table.add_column("Severity", justify="center", width=10)
        table.add_column("Title", style="bold", min_width=30)
        table.add_column("MITRE", style="dim", width=12)
        table.add_column("Score", justify="right", width=6)

        sev_colors = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim", "info": "dim"}
        for f in shown:
            color = sev_colors.get(f.severity, "white")
            table.add_row(
                f"[{color}]{f.severity.upper()}[/{color}]",
                f.title[:55],
                f.mitre_technique,
                str(round(f.score, 1)),
            )
        console.print(table)

    if len(report.findings) > 15:
        rprint(f"  [dim]... and {len(report.findings)-15} more findings in the JSON report[/dim]")


def _risk_badge(level: str) -> str:
    badges = {
        "critical": "[bold red]◆ CRITICAL[/bold red]",
        "high":     "[bold yellow]▲ HIGH[/bold yellow]",
        "medium":   "[cyan]● MEDIUM[/cyan]",
        "low":      "[green]○ LOW[/green]",
    }
    return badges.get(level, level)


def _save_dfir_report(report, output: Path | None, prefix: str) -> None:
    if not output:
        return
    import json as _json
    output.mkdir(parents=True, exist_ok=True)
    path = output / f"dfir_{prefix}.json"
    path.write_text(_json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
    rprint(f"  [dim]Report saved: {path}[/dim]")


def _load_processes_json(path: Path | None) -> list[dict]:
    if not path or not path.exists():
        return []
    import json as _json
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        return data.get("processes", [])
    except Exception:
        return []


def _load_connections_json(path: Path | None) -> list[dict]:
    if not path or not path.exists():
        return []
    import json as _json
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        return data.get("connections", [])
    except Exception:
        return []


def _load_events_json(path: Path | None) -> list[dict]:
    if not path or not path.exists():
        return []
    import json as _json
    try:
        data = _json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        return data.get("events", data.get("EventRecords", []))
    except Exception:
        return []


@dfir_app.command("persist")
def cmd_dfir_persist(
    output: Path | None = typer.Option(None, "--output", "-o", help="Save JSON report to directory"),
) -> None:
    """Hunt all persistence mechanisms on the live system (Windows)."""
    import platform as _p
    if _p.system() != "Windows":
        rprint("[red]Persistence hunting requires a live Windows system.[/red]")
        raise typer.Exit(1)

    from core.dfir.offensive import hunt_persistence
    rprint("\n[bold cyan]ForgeLens DFIR — Persistence Hunt[/bold cyan]")
    rprint("[dim]Scanning: Run keys, scheduled tasks, services, WMI, IFEO, startup folders...[/dim]\n")

    with console.status("[cyan]Hunting persistence mechanisms...[/cyan]"):
        report = hunt_persistence()

    _print_dfir_report(report, "Persistence Hunt Results")
    _save_dfir_report(report, output, "persistence")


@dfir_app.command("beacons")
def cmd_dfir_beacons(
    processes_file: Path | None = typer.Option(None, "--processes", "-p", help="Processes JSON file"),
    connections_file: Path | None = typer.Option(None, "--connections", "-c", help="Connections JSON file"),
    history_file: Path | None = typer.Option(None, "--history", help="Connection history JSON for interval analysis"),
    dump: Path | None = typer.Option(None, "--dump", "-d", help="Memory dump file — auto-extract processes/connections"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save JSON report"),
) -> None:
    """Detect C2 beaconing patterns in process and network data."""
    from core.dfir.offensive import detect_beacons

    processes: list[dict] = []
    connections: list[dict] = []

    # Load from memory dump if provided
    if dump and dump.exists():
        rprint(f"[dim]Extracting data from memory dump: {dump.name}[/dim]")
        from core.memory.volatility_engine import VolatilityEngine
        eng = VolatilityEngine(dump)
        with console.status("[cyan]Extracting processes from dump...[/cyan]"):
            p_result = eng.list_processes()
            c_result = eng.list_connections()
        if p_result.success:
            processes = p_result.data
        if c_result.success:
            connections = c_result.data
    else:
        processes = _load_processes_json(processes_file)
        connections = _load_connections_json(connections_file)

    history = _load_events_json(history_file)

    if not connections and not processes:
        rprint("[yellow]No data provided. Use --dump <memory.raw> or --connections <file.json>[/yellow]")
        raise typer.Exit(1)

    rprint(f"\n[bold cyan]ForgeLens DFIR — Beacon Detection[/bold cyan]")
    rprint(f"  Processes  : {len(processes)}")
    rprint(f"  Connections: {len(connections)}")
    rprint(f"  History    : {len(history)}\n")

    with console.status("[cyan]Analyzing for beaconing patterns...[/cyan]"):
        report = detect_beacons(connections, processes, history or None)

    _print_dfir_report(report, "Beacon Detection Results")
    _save_dfir_report(report, output, "beacons")


@dfir_app.command("creds")
def cmd_dfir_creds(
    processes_file: Path | None = typer.Option(None, "--processes", "-p", help="Processes JSON file"),
    events_file: Path | None = typer.Option(None, "--events", "-e", help="Events JSON file"),
    dump: Path | None = typer.Option(None, "--dump", "-d", help="Memory dump file"),
    live: bool = typer.Option(True, "--live/--offline", help="Check live registry (Windows)"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save JSON report"),
) -> None:
    """Detect credential theft artifacts: mimikatz, kerberoasting, DCSync, WDigest."""
    from core.dfir.offensive import detect_credential_theft

    processes: list[dict] = []
    events: list[dict] = []

    if dump and dump.exists():
        from core.memory.volatility_engine import VolatilityEngine
        eng = VolatilityEngine(dump)
        with console.status("[cyan]Extracting from dump...[/cyan]"):
            p = eng.list_processes()
            if p.success:
                processes = p.data
    else:
        processes = _load_processes_json(processes_file)
        events = _load_events_json(events_file)

    rprint(f"\n[bold cyan]ForgeLens DFIR — Credential Theft Detection[/bold cyan]")
    rprint(f"  Processes: {len(processes)}  |  Events: {len(events)}\n")

    with console.status("[cyan]Detecting credential theft artifacts...[/cyan]"):
        report = detect_credential_theft(processes or None, events or None, live=live)

    _print_dfir_report(report, "Credential Theft Detection Results")
    _save_dfir_report(report, output, "credentials")


@dfir_app.command("ransomware")
def cmd_dfir_ransomware(
    scan_path: Path = typer.Argument(Path("C:\\"), help="Root path to scan"),
    processes_file: Path | None = typer.Option(None, "--processes", "-p", help="Processes JSON"),
    events_file: Path | None = typer.Option(None, "--events", "-e", help="Events JSON"),
    max_files: int = typer.Option(50000, "--max-files", help="Max files to scan"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save JSON report"),
) -> None:
    """Rapid ransomware triage: detect notes, encrypted extensions, VSS deletion, blast radius."""
    from core.dfir.offensive import triage_ransomware

    processes = _load_processes_json(processes_file)
    events = _load_events_json(events_file)

    rprint(f"\n[bold cyan]ForgeLens DFIR — Ransomware Triage[/bold cyan]")
    rprint(f"  Scan path  : {scan_path}")
    rprint(f"  Max files  : {max_files:,}\n")
    rprint("[yellow]Scanning for ransom notes, encrypted files, and shadow copy deletion...[/yellow]\n")

    with console.status(f"[cyan]Triaging ransomware indicators in {scan_path}...[/cyan]"):
        report = triage_ransomware(scan_path, processes or None, events or None, max_files)

    _print_dfir_report(report, "Ransomware Triage Results")
    _save_dfir_report(report, output, "ransomware")


@dfir_app.command("lateral")
def cmd_dfir_lateral(
    processes_file: Path | None = typer.Option(None, "--processes", "-p", help="Processes JSON"),
    connections_file: Path | None = typer.Option(None, "--connections", "-c", help="Connections JSON"),
    events_file: Path | None = typer.Option(None, "--events", "-e", help="Events JSON (security log)"),
    dump: Path | None = typer.Option(None, "--dump", "-d", help="Memory dump file"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save JSON report"),
) -> None:
    """Map lateral movement: logon paths, admin shares, remote services, PsExec/WMI/RDP."""
    from core.dfir.offensive import map_lateral_movement

    processes: list[dict] = []
    connections: list[dict] = []
    events = _load_events_json(events_file)

    if dump and dump.exists():
        from core.memory.volatility_engine import VolatilityEngine
        eng = VolatilityEngine(dump)
        with console.status("[cyan]Extracting from dump...[/cyan]"):
            p = eng.list_processes()
            c = eng.list_connections()
            if p.success:
                processes = p.data
            if c.success:
                connections = c.data
    else:
        processes = _load_processes_json(processes_file)
        connections = _load_connections_json(connections_file)

    rprint(f"\n[bold cyan]ForgeLens DFIR — Lateral Movement Mapping[/bold cyan]")
    rprint(f"  Processes  : {len(processes)}")
    rprint(f"  Connections: {len(connections)}")
    rprint(f"  Events     : {len(events)}\n")

    with console.status("[cyan]Mapping lateral movement...[/cyan]"):
        report = map_lateral_movement(events or None, processes or None, connections or None)

    _print_dfir_report(report, "Lateral Movement Mapping Results")
    _save_dfir_report(report, output, "lateral_movement")


@dfir_app.command("full-triage")
def cmd_dfir_full(
    scan_path: Path = typer.Argument(Path("C:\\"), help="Root path for ransomware scan"),
    dump: Path | None = typer.Option(None, "--dump", "-d", help="Memory dump for process/network data"),
    events_file: Path | None = typer.Option(None, "--events", "-e", help="Event log JSON file"),
    output: Path = typer.Option(Path("evidence/dfir"), "--output", "-o", help="Output directory for all reports"),
) -> None:
    """Run all DFIR modules in sequence: persistence + beacons + creds + ransomware + lateral movement."""
    import json as _json
    from core.dfir.offensive import OffensiveDFIR

    processes: list[dict] = []
    connections: list[dict] = []
    events = _load_events_json(events_file)

    if dump and dump.exists():
        rprint(f"[dim]Extracting memory data from: {dump.name}[/dim]")
        from core.memory.volatility_engine import VolatilityEngine
        eng = VolatilityEngine(dump)
        with console.status("[cyan]Extracting processes and connections from dump...[/cyan]"):
            p = eng.list_processes()
            c = eng.list_connections()
            if p.success:
                processes = p.data
                rprint(f"  [dim]Processes: {len(processes)}[/dim]")
            if c.success:
                connections = c.data
                rprint(f"  [dim]Connections: {len(connections)}[/dim]")

    rprint(f"\n[bold cyan]ForgeLens DFIR — Full Triage[/bold cyan]")
    rprint(f"  Scan path  : {scan_path}")
    rprint(f"  Output     : {output}\n")

    dfir = OffensiveDFIR()
    output.mkdir(parents=True, exist_ok=True)

    modules = [
        ("persistence",     lambda: dfir.hunt_persistence(),                                  "Persistence Hunt"),
        ("beacons",         lambda: dfir.detect_beacons(connections, processes),              "Beacon Detection"),
        ("credentials",     lambda: dfir.detect_credential_theft(processes, events),          "Credential Theft"),
        ("ransomware",      lambda: dfir.triage_ransomware(scan_path, processes, events),     "Ransomware Triage"),
        ("lateral_movement",lambda: dfir.map_lateral_movement(events, processes, connections),"Lateral Movement"),
    ]

    all_critical = 0
    all_high = 0

    for key, fn, label in modules:
        with console.status(f"[cyan]{label}...[/cyan]"):
            report = fn()

        path = output / f"dfir_{key}.json"
        path.write_text(_json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")

        crit = len(report.critical)
        high = len(report.high)
        all_critical += crit
        all_high += high

        badge = _risk_badge(report.risk_level)
        rprint(f"  {badge}  {label}: {len(report.findings)} findings "
               f"([red]{crit} critical[/red] / [yellow]{high} high[/yellow]) → [dim]{path.name}[/dim]")

    rprint(f"\n{'═'*60}")
    rprint(f"[bold]Full Triage Complete[/bold]")
    rprint(f"  Total critical : [bold red]{all_critical}[/bold red]")
    rprint(f"  Total high     : [bold yellow]{all_high}[/bold yellow]")
    rprint(f"  Reports saved  : {output}")

    if all_critical:
        rprint("\n[bold red]⚠ CRITICAL FINDINGS — Immediate incident response required.[/bold red]")


# ── Mobile advanced app ───────────────────────────────────────────────────────
mobile_app = typer.Typer(help="Advanced mobile forensics — Android & iOS (v2.2)")
# app.add_typer(mobile_app, name="mobile")


def _print_mobile_result(result, label: str) -> None:
    if result.success:
        rprint(f"\n[bold green]✔ {label}[/bold green]")
        rprint(f"  Method    : {result.method}")
        if result.size_bytes:
            rprint(f"  Size      : {round(result.size_bytes/(1024**2), 1)} MB")
        rprint(f"  Artifacts : {len(result.artifacts)}")
        for a in result.artifacts[:5]:
            rprint(f"  [dim]{a}[/dim]")
        for note in result.notes:
            rprint(f"  [yellow]→[/yellow] {note}")
    else:
        rprint(f"\n[bold red]✘ {label} failed:[/bold red] {result.error}")


@mobile_app.command("android-filesystem")
def cmd_mobile_android_fs(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    serial: str = typer.Option("", "--serial", "-s", help="Device serial (auto-detect)"),
    method: str = typer.Option("auto", "--method", "-m", help="auto|tar_root|adb_backup|dd_image|twrp_backup"),
    partition: str = typer.Option("/data", "--partition", "-p", help="Partition to extract"),
) -> None:
    """Extract the full Android filesystem (root recommended for /data)."""
    from platforms.android.acquisition import detect_devices
    from platforms.android.advanced import AndroidAdvanced

    if not serial:
        devices = detect_devices()
        if not devices:
            rprint("[red]No Android devices found.[/red]")
            raise typer.Exit(1)
        serial = devices[0].serial
        rprint(f"[dim]Using device: {serial}[/dim]")

    adv = AndroidAdvanced(serial)
    rprint(f"\n[bold cyan]Android Filesystem Extraction[/bold cyan]")
    rprint(f"  Serial : {serial}")
    rprint(f"  Root   : {'[green]Yes[/green]' if adv._is_root else '[yellow]No[/yellow]'}")
    rprint(f"  Method : {method}  |  Partition: {partition}\n")

    with console.status("[cyan]Extracting filesystem...[/cyan]"):
        result = adv.extract_full_filesystem(output, partition=partition, method=method)
    _print_mobile_result(result, "Android Filesystem Extraction")
    if not result.success:
        raise typer.Exit(1)


@mobile_app.command("android-recover")
def cmd_mobile_android_recover(
    db: Path = typer.Argument(..., help="SQLite database file (local path after pull)"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory for recovered data"),
    serial: str = typer.Option("", "--serial", "-s", help="Device serial for remote pull"),
    remote_path: str = typer.Option("", "--remote", "-r", help="Remote DB path to pull first"),
) -> None:
    """Recover deleted SQLite records via WAL + freelist page scanning."""
    from platforms.android.advanced import AndroidAdvanced, _adb_pull

    if remote_path and serial:
        rprint(f"[dim]Pulling {remote_path} from device...[/dim]")
        local_db = output / Path(remote_path).name
        output.mkdir(parents=True, exist_ok=True)
        ok, size = _adb_pull(serial, remote_path, local_db)
        if ok:
            db = local_db
            rprint(f"[dim]Pulled: {local_db} ({size//1024} KB)[/dim]")

    if not db.exists():
        rprint(f"[red]Database not found: {db}[/red]")
        raise typer.Exit(1)

    adv = AndroidAdvanced(serial or "local")
    rprint(f"\n[bold cyan]SQLite Deleted Record Recovery[/bold cyan]  db={db.name}\n")

    with console.status("[cyan]Scanning for deleted records...[/cyan]"):
        result = adv.recover_deleted_sqlite(db, output)
    _print_mobile_result(result, "SQLite Recovery")
    if result.success:
        rprint(f"\n  Recovered deleted records: [bold]{result.recovered_records}[/bold]")


@mobile_app.command("android-keystore")
def cmd_mobile_android_keystore(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    serial: str = typer.Option("", "--serial", "-s", help="Device serial (auto-detect)"),
) -> None:
    """Enumerate Android Keystore/TEE artifacts and generate secure enclave research doc."""
    from platforms.android.acquisition import detect_devices
    from platforms.android.advanced import AndroidAdvanced

    if not serial:
        devices = detect_devices()
        if not devices:
            rprint("[red]No Android devices found.[/red]")
            raise typer.Exit(1)
        serial = devices[0].serial

    adv = AndroidAdvanced(serial)
    with console.status("[cyan]Enumerating keystore...[/cyan]"):
        result = adv.enumerate_keystore_artifacts(output)
    _print_mobile_result(result, "Android Keystore Enumeration")


@mobile_app.command("android-deep")
def cmd_mobile_android_deep(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    serial: str = typer.Option("", "--serial", "-s", help="Device serial (auto-detect)"),
) -> None:
    """Deep Android artifact collection: /proc, dmesg, WiFi, Bluetooth, network."""
    from platforms.android.acquisition import detect_devices
    from platforms.android.advanced import AndroidAdvanced

    if not serial:
        devices = detect_devices()
        if not devices:
            rprint("[red]No Android devices found.[/red]")
            raise typer.Exit(1)
        serial = devices[0].serial

    adv = AndroidAdvanced(serial)
    rprint(f"\n  Root: {'[green]Yes[/green]' if adv._is_root else '[yellow]No[/yellow]'}\n")
    with console.status("[cyan]Collecting deep artifacts...[/cyan]"):
        result = adv.collect_deep_artifacts(output)
    _print_mobile_result(result, "Android Deep Collection")


@mobile_app.command("ios-filesystem")
def cmd_mobile_ios_fs(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    udid: str = typer.Option("", "--udid", "-u", help="Device UDID (auto-detect)"),
    method: str = typer.Option("auto", "--method", "-m", help="auto|itunes_backup|afc2|ssh_tar|pymobile_fs"),
) -> None:
    """Extract the full iOS filesystem (jailbreak recommended for complete access)."""
    from platforms.ios.acquisition import detect_devices
    from platforms.ios.advanced import IOSAdvanced

    if not udid:
        devices = detect_devices()
        if not devices:
            rprint("[red]No iOS devices found.[/red]")
            raise typer.Exit(1)
        udid = devices[0].udid

    adv = IOSAdvanced(udid)
    rprint(f"\n[bold cyan]iOS Filesystem Extraction[/bold cyan]")
    rprint(f"  UDID       : {udid[:16]}...")
    rprint(f"  Jailbroken : {'[green]Yes[/green]' if adv._is_jailbroken else '[yellow]No[/yellow]'}")
    rprint(f"  Method     : {method}\n")

    with console.status("[cyan]Extracting iOS filesystem...[/cyan]"):
        result = adv.extract_full_filesystem(output, method=method)
    _print_mobile_result(result, "iOS Filesystem Extraction")
    if not result.success:
        raise typer.Exit(1)


@mobile_app.command("ios-keychain")
def cmd_mobile_ios_keychain(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    udid: str = typer.Option("", "--udid", "-u", help="Device UDID (auto-detect)"),
) -> None:
    """Extract iOS keychain data (jailbreak required for full access)."""
    from platforms.ios.acquisition import detect_devices
    from platforms.ios.advanced import IOSAdvanced

    if not udid:
        devices = detect_devices()
        if not devices:
            rprint("[red]No iOS devices found.[/red]")
            raise typer.Exit(1)
        udid = devices[0].udid

    adv = IOSAdvanced(udid)
    with console.status("[cyan]Extracting keychain...[/cyan]"):
        result = adv.extract_keychain(output)
    _print_mobile_result(result, "iOS Keychain Extraction")


@mobile_app.command("ios-sep")
def cmd_mobile_ios_sep(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
) -> None:
    """Generate SEP/keybag research doc: architecture, key classes, acquisition strategies."""
    from platforms.ios.advanced import IOSAdvanced
    adv = IOSAdvanced("research")
    with console.status("[cyan]Generating SEP research document...[/cyan]"):
        result = adv.document_sep_research(output)
    _print_mobile_result(result, "SEP Research Documentation")
    rprint(f"\n[dim]View: {result.output_path}[/dim]")


@mobile_app.command("ios-decrypt")
def cmd_mobile_ios_decrypt(
    backup: Path = typer.Argument(..., help="Encrypted iTunes backup directory"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    password: str = typer.Option(..., "--password", "-p", help="Backup password",
                                  prompt=True, hide_input=True),
) -> None:
    """Decrypt an encrypted iTunes backup (requires: pip install iphone-backup-decrypt)."""
    if not backup.exists():
        rprint(f"[red]Backup not found: {backup}[/red]")
        raise typer.Exit(1)
    from platforms.ios.advanced import IOSAdvanced
    adv = IOSAdvanced("local")
    with console.status("[cyan]Decrypting backup...[/cyan]"):
        result = adv.decrypt_backup(backup, password, output)
    _print_mobile_result(result, "iOS Backup Decryption")
    if not result.success:
        raise typer.Exit(1)


@mobile_app.command("ios-crashes")
def cmd_mobile_ios_crashes(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    udid: str = typer.Option("", "--udid", "-u", help="Device UDID (auto-detect)"),
) -> None:
    """Collect iOS crash reports and diagnostic logs from the device."""
    from platforms.ios.acquisition import detect_devices
    from platforms.ios.advanced import IOSAdvanced

    if not udid:
        devices = detect_devices()
        if not devices:
            rprint("[red]No iOS devices found.[/red]")
            raise typer.Exit(1)
        udid = devices[0].udid

    adv = IOSAdvanced(udid)
    with console.status("[cyan]Collecting crash logs...[/cyan]"):
        result = adv.collect_crash_logs(output)
    _print_mobile_result(result, "iOS Crash Logs")


# ── Cloud & Container app ─────────────────────────────────────────────────────
cloud_app = typer.Typer(help="Cloud & container forensics (AWS / Azure / GCP / Docker / Kubernetes)")
if "cloud" not in settings.features.disabled:
    app.add_typer(cloud_app, name="cloud")


def _print_cloud_result(result, label: str) -> None:
    """Pretty-print a CloudAcquisitionResult."""
    if result.success:
        rprint(f"\n[bold green]✔ {label} complete[/bold green]")
        rprint(f"  Provider  : {result.provider}")
        rprint(f"  Resource  : {result.resource_id}")
        rprint(f"  Artifacts : {len(result.artifacts)}")
        rprint(f"  Duration  : {result.duration_seconds}s")
        if result.sha256:
            rprint(f"  SHA256    : {result.sha256[:32]}...")
        for path in result.artifacts[:6]:
            rprint(f"  [dim]{path}[/dim]")
        if len(result.artifacts) > 6:
            rprint(f"  [dim]... and {len(result.artifacts)-6} more[/dim]")
    else:
        rprint(f"\n[bold red]✘ {label} failed:[/bold red] {result.error}")


# ── AWS ───────────────────────────────────────────────────────────────────────

@cloud_app.command("aws-snapshot")
def cmd_cloud_aws_snapshot(
    volume_id: str = typer.Argument(..., help="EBS volume ID e.g. vol-0123456789abcdef0"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS region"),
    wait: int = typer.Option(10, "--wait", help="Max wait minutes for snapshot completion"),
) -> None:
    """Acquire an AWS EBS volume snapshot for forensic analysis."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status(f"[cyan]Creating EBS snapshot of {volume_id}...[/cyan]"):
        result = acq.acquire_aws_snapshot(volume_id, output, region=region, wait_minutes=wait)
    _print_cloud_result(result, "AWS EBS Snapshot")
    if not result.success:
        raise typer.Exit(1)


@cloud_app.command("aws-collect")
def cmd_cloud_aws_collect(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    region: str = typer.Option("us-east-1", "--region", "-r", help="AWS region"),
    cloudtrail: bool = typer.Option(True, "--cloudtrail/--no-cloudtrail", help="Collect CloudTrail config"),
) -> None:
    """Collect AWS forensic artifacts: IAM, EC2, VPC, S3, CloudTrail."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status("[cyan]Collecting AWS artifacts...[/cyan]"):
        result = acq.collect_aws_artifacts(output, region=region, include_cloudtrail=cloudtrail)
    _print_cloud_result(result, "AWS Collection")


# ── Azure ─────────────────────────────────────────────────────────────────────

@cloud_app.command("azure-disk")
def cmd_cloud_azure_disk(
    resource_group: str = typer.Argument(..., help="Azure resource group name"),
    disk_name: str = typer.Argument(..., help="Managed disk name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    duration: int = typer.Option(3600, "--duration", help="SAS access duration in seconds"),
) -> None:
    """Generate a SAS URL for read-only access to an Azure managed disk."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status(f"[cyan]Granting read access to {disk_name}...[/cyan]"):
        result = acq.acquire_azure_vm_disk(resource_group, disk_name, output, duration_seconds=duration)
    _print_cloud_result(result, "Azure Disk Access")
    if not result.success:
        raise typer.Exit(1)


@cloud_app.command("azure-collect")
def cmd_cloud_azure_collect(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    subscription: str = typer.Option("", "--subscription", "-s", help="Subscription ID (uses default if omitted)"),
) -> None:
    """Collect Azure forensic artifacts: VMs, NSGs, Activity Log, RBAC, AD."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status("[cyan]Collecting Azure artifacts...[/cyan]"):
        result = acq.collect_azure_artifacts(output, subscription_id=subscription)
    _print_cloud_result(result, "Azure Collection")


# ── GCP ───────────────────────────────────────────────────────────────────────

@cloud_app.command("gcp-snapshot")
def cmd_cloud_gcp_snapshot(
    disk_name: str = typer.Argument(..., help="GCP persistent disk name"),
    project: str = typer.Option(..., "--project", "-p", help="GCP project ID"),
    zone: str = typer.Option(..., "--zone", "-z", help="GCP zone e.g. us-central1-a"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
) -> None:
    """Create a GCP persistent disk snapshot for forensic analysis."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status(f"[cyan]Creating GCP snapshot of {disk_name}...[/cyan]"):
        result = acq.acquire_gcp_disk_snapshot(disk_name, project, zone, output)
    _print_cloud_result(result, "GCP Snapshot")
    if not result.success:
        raise typer.Exit(1)


@cloud_app.command("gcp-collect")
def cmd_cloud_gcp_collect(
    project: str = typer.Argument(..., help="GCP project ID"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    zone: str = typer.Option("", "--zone", "-z", help="Zone filter (optional)"),
) -> None:
    """Collect GCP forensic artifacts: instances, IAM, firewall, audit logs."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status(f"[cyan]Collecting GCP artifacts for {project}...[/cyan]"):
        result = acq.collect_gcp_artifacts(project, output, zone=zone)
    _print_cloud_result(result, "GCP Collection")


# ── Docker ────────────────────────────────────────────────────────────────────

@cloud_app.command("docker-collect")
def cmd_cloud_docker_collect(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
) -> None:
    """Collect Docker host inventory: containers, images, volumes, networks."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status("[cyan]Collecting Docker artifacts...[/cyan]"):
        result = acq.collect_docker_artifacts(output)
    _print_cloud_result(result, "Docker Collection")


@cloud_app.command("docker-acquire")
def cmd_cloud_docker_acquire(
    container: str = typer.Argument(..., help="Container ID or name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    logs: bool = typer.Option(True, "--logs/--no-logs", help="Collect container logs"),
    include_env: bool = typer.Option(False, "--env", help="Include environment variables (sensitive)"),
) -> None:
    """Acquire a Docker container: filesystem, metadata, processes, logs."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status(f"[cyan]Acquiring container {container[:12]}...[/cyan]"):
        result = acq.acquire_docker_container(container, output, include_logs=logs, include_env=include_env)
    _print_cloud_result(result, "Docker Container Acquisition")
    if not result.success:
        raise typer.Exit(1)


@cloud_app.command("docker-memory")
def cmd_cloud_docker_memory(
    container: str = typer.Argument(..., help="Container ID or name"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
) -> None:
    """Acquire container memory via /proc and nsenter (Linux host, requires root)."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    import platform as _platform
    if _platform.system() != "Linux":
        rprint("[red]Container memory acquisition requires a Linux host.[/red]")
        raise typer.Exit(1)
    acq = CloudAcquisition()
    with console.status(f"[cyan]Acquiring memory for container {container[:12]}...[/cyan]"):
        result = acq.acquire_container_memory(container, output)
    _print_cloud_result(result, "Container Memory Acquisition")
    if not result.success:
        raise typer.Exit(1)


# ── Kubernetes ────────────────────────────────────────────────────────────────

@cloud_app.command("k8s-collect")
def cmd_cloud_k8s_collect(
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    namespace: str = typer.Option("default", "--namespace", "-n", help="Kubernetes namespace"),
    all_namespaces: bool = typer.Option(False, "--all-namespaces", "-A", help="Collect from all namespaces"),
) -> None:
    """Collect Kubernetes forensic artifacts: pods, services, events, RBAC."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    ns_label = "all namespaces" if all_namespaces else f"namespace={namespace}"
    with console.status(f"[cyan]Collecting Kubernetes artifacts ({ns_label})...[/cyan]"):
        result = acq.collect_kubernetes_artifacts(namespace, output, all_namespaces=all_namespaces)
    _print_cloud_result(result, "Kubernetes Collection")


@cloud_app.command("k8s-timeline")
def cmd_cloud_k8s_timeline(
    output: Path = typer.Option(..., "--output", "-o", help="Output JSON file or directory"),
    namespace: str = typer.Option("default", "--namespace", "-n", help="Kubernetes namespace"),
    all_namespaces: bool = typer.Option(False, "--all-namespaces", "-A", help="All namespaces"),
) -> None:
    """Reconstruct a forensic timeline of Kubernetes cluster activity."""
    from core.enterprise.cloud_acquisition import CloudAcquisition
    acq = CloudAcquisition()
    with console.status("[cyan]Reconstructing cluster timeline...[/cyan]"):
        result = acq.reconstruct_cluster_timeline(namespace, output, all_namespaces=all_namespaces)

    if result.success:
        meta = result.metadata
        rprint(f"\n[bold green]✔ Cluster timeline complete[/bold green]")
        rprint(f"  Total events     : {meta.get('total_events', 0)}")
        rprint(f"  [red]Suspicious events: {meta.get('suspicious_events', 0)}[/red]")
        rprint(f"  Output           : [cyan]{result.output_path}[/cyan]")
        if meta.get("suspicious_events", 0) > 0:
            rprint("\n[yellow]⚠ Suspicious events found — review the timeline JSON for details[/yellow]")
    else:
        rprint(f"[red]✘ Timeline failed: {result.error}[/red]")
        raise typer.Exit(1)


# ── V3.0 Battlefield Edition ──────────────────────────────────────────────────
v3_app = typer.Typer(help="V3.0 Battlefield Edition: distributed, ledger, threat graph, timeline fusion, collaboration")
if "v3" not in settings.features.disabled:
    app.add_typer(v3_app, name="v3")


def _load_json_file(path: Path | None) -> list[dict]:
    if not path or not path.exists():
        return []
    import json as _j
    try:
        d = _j.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else d.get("processes", d.get("events", d.get("connections", [])))
    except Exception:
        return []


# ── Distributed acquisition ───────────────────────────────────────────────────

@v3_app.command("agents")
def cmd_v3_agents() -> None:
    """List all registered distributed agents and their status."""
    from core.v3.distributed import DistributedAcquisition
    coord = DistributedAcquisition()
    agents = coord.list_agents()
    if not agents:
        rprint("[yellow]No agents registered. Use 'v3 agent-add' to register one.[/yellow]")
        return
    table = Table(title="Distributed Agents", show_lines=True)
    table.add_column("ID", style="cyan")
    table.add_column("Label")
    table.add_column("URL")
    table.add_column("State")
    table.add_column("OS")
    table.add_column("Latency")
    table.add_column("Tasks")
    for a in agents:
        state_color = {"online": "green", "offline": "red", "busy": "yellow", "error": "red"}.get(a.state.value, "white")
        table.add_row(
            a.agent_id, a.label, a.url,
            f"[{state_color}]{a.state.value}[/{state_color}]",
            a.os_name or "—",
            f"{a.latency_ms}ms" if a.latency_ms else "—",
            str(a.tasks_completed),
        )
    console.print(table)


@v3_app.command("agent-add")
def cmd_v3_agent_add(
    url: str = typer.Argument(..., help="Agent URL e.g. http://192.168.1.10:8765"),
    token: str = typer.Option(..., "--token", "-t", help="HMAC authentication token"),
    label: str = typer.Option("", "--label", "-l", help="Human-readable label"),
) -> None:
    """Register a remote acquisition agent."""
    from core.v3.distributed import DistributedAcquisition
    coord = DistributedAcquisition()
    node = coord.add_agent(url, token, label)
    rprint(f"[green]✔ Agent registered[/green]  ID={node.agent_id}  label={node.label}")


@v3_app.command("ping")
def cmd_v3_ping() -> None:
    """Ping all registered agents and update their status."""
    from core.v3.distributed import DistributedAcquisition
    coord = DistributedAcquisition()
    with console.status("[cyan]Pinging agents...[/cyan]"):
        results = coord.ping_all()
    for agent_id, reachable in results.items():
        icon = "[green]✔[/green]" if reachable else "[red]✘[/red]"
        rprint(f"  {icon} {agent_id}")
    online = sum(1 for v in results.values() if v)
    rprint(f"\n[dim]{online}/{len(results)} online[/dim]")


@v3_app.command("acquire-all")
def cmd_v3_acquire_all(
    case_id: str = typer.Option(..., "--case", "-c"),
    examiner: str = typer.Option(..., "--examiner", "-e"),
    task: str = typer.Option("live_response", "--task", "-t", help="live_response|artifact_collect|memory"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    wait: bool = typer.Option(True, "--wait/--async", help="Wait for completion"),
) -> None:
    """Dispatch acquisition to all online agents simultaneously."""
    from core.v3.distributed import DistributedAcquisition, JobState
    coord = DistributedAcquisition()

    rprint(f"\n[bold cyan]Distributed Acquisition[/bold cyan]")
    rprint(f"  Task    : {task}")
    rprint(f"  Case    : {case_id}\n")

    try:
        job = coord.acquire_all(case_id, examiner, task, async_run=not wait)
    except RuntimeError as exc:
        rprint(f"[red]✘ {exc}[/red]")
        rprint("[dim]Run 'python forgelens.py v3 ping' first[/dim]")
        raise typer.Exit(1)

    if wait:
        with console.status(f"[cyan]Running on {job.total_agents} agent(s)...[/cyan]"):
            try:
                coord.wait(job.job_id, timeout=600)
            except TimeoutError:
                rprint("[yellow]⚠ Timed out waiting — job still running[/yellow]")

    report = coord.get_job_report(job.job_id)
    rprint(f"[bold green]✔ Job {job.job_id}[/bold green]  state={report['state']}")
    rprint(f"  Agents: {report['successful']}/{report['total_agents']} succeeded")
    for r in report.get("results", []):
        icon = "[green]✔[/green]" if r["success"] else "[red]✘[/red]"
        rprint(f"  {icon} {r['agent']}  {r['duration']}s  {r.get('error','')}")


# ── Immutable ledger ──────────────────────────────────────────────────────────

@v3_app.command("ledger")
def cmd_v3_ledger(
    case_id: str = typer.Argument(..., help="Case ID"),
    evidence_id: str = typer.Option("", "--evidence", "-e", help="Filter by evidence ID"),
    verify: bool = typer.Option(False, "--verify", "-v", help="Verify hash-chain integrity"),
    export: Path | None = typer.Option(None, "--export", help="Export ledger to JSON"),
    migrate: bool = typer.Option(False, "--migrate", "-m", help="Migrate CoC events into ledger"),
) -> None:
    """View or verify the immutable evidence ledger for a case."""
    from core.v3.ledger import EvidenceLedger
    from dataclasses import asdict

    if migrate:
        with console.status("[cyan]Migrating chain of custody events...[/cyan]"):
            ledger = EvidenceLedger.migrate_from_coc(case_id)
        entries = ledger.get_entries()
        rprint(f"[green]✔ Migrated {len(entries)} event(s) into ledger[/green]")
        return

    ledger = EvidenceLedger(case_id)

    if verify:
        with console.status("[cyan]Verifying hash chain...[/cyan]"):
            valid, report = ledger.verify_chain()
        if valid:
            rprint(f"[bold green]✔ CHAIN VALID — {report.total_entries} entries verified[/bold green]")
        else:
            rprint(f"[bold red]✘ TAMPERING DETECTED — {len(report.tampered_entries)} entry/entries compromised[/bold red]")
            rprint(f"  Tampered seq numbers: {report.tampered_entries}")
        rprint(f"  {report.integrity_note}")
        return

    if export:
        ledger.export_json(export)
        rprint(f"[green]✔ Ledger exported: {export}[/green]")
        return

    entries = ledger.get_entries(evidence_id=evidence_id or None)
    if not entries:
        rprint("[yellow]No ledger entries found.[/yellow]")
        return

    table = Table(title=f"Ledger — {case_id}", show_lines=True)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Evidence", style="cyan")
    table.add_column("Event")
    table.add_column("Actor")
    table.add_column("Timestamp", style="dim")
    table.add_column("Hash (first 12)", style="dim")
    for e in entries[-50:]:
        table.add_row(str(e.seq), e.evidence_id, e.event_type, e.actor,
                      e.timestamp[:19], e.entry_hash[:12] + "...")
    console.print(table)
    rprint(f"\n[dim]{len(entries)} total entries[/dim]")


# ── Threat graph ──────────────────────────────────────────────────────────────

@v3_app.command("graph")
def cmd_v3_graph(
    case_id: str = typer.Argument(..., help="Case ID"),
    output: Path = typer.Option(..., "--output", "-o", help="Output directory"),
    processes: Path | None = typer.Option(None, "--processes", "-p", help="Processes JSON file"),
    connections: Path | None = typer.Option(None, "--connections", "-c", help="Connections JSON file"),
    ioc_file: Path | None = typer.Option(None, "--iocs", help="IOC JSON file"),
    stix: bool = typer.Option(False, "--stix", help="Also export STIX 2.1 bundle"),
    dot: bool = typer.Option(True, "--dot/--no-dot", help="Also export Graphviz DOT"),
) -> None:
    """Build and export the AI threat graph for a case."""
    from core.v3.threat_graph import ThreatGraph

    output.mkdir(parents=True, exist_ok=True)
    graph = ThreatGraph(case_id)

    procs = _load_json_file(processes)
    conns = _load_json_file(connections)

    if procs:
        graph.ingest_processes(procs)
        rprint(f"  [dim]Ingested {len(procs)} process(es)[/dim]")
    if conns:
        graph.ingest_connections(conns)
        rprint(f"  [dim]Ingested {len(conns)} connection(s)[/dim]")

    rprint(f"\n[bold cyan]Threat Graph — {case_id}[/bold cyan]")
    rprint(graph.summary())

    json_path = output / f"{case_id}_threat_graph.json"
    graph.export_json(json_path)
    rprint(f"\n  [green]✔[/green] JSON  : {json_path}")

    if dot:
        dot_path = output / f"{case_id}_threat_graph.dot"
        graph.export_dot(dot_path)
        rprint(f"  [green]✔[/green] DOT   : {dot_path}")
        rprint(f"  [dim]Render: dot -Tpng {dot_path} -o graph.png[/dim]")

    if stix:
        stix_path = output / f"{case_id}_stix.json"
        graph.export_stix(stix_path)
        rprint(f"  [green]✔[/green] STIX  : {stix_path}")


# ── Cross-device timeline fusion ──────────────────────────────────────────────

@v3_app.command("timeline-fuse")
def cmd_v3_timeline_fuse(
    case_id: str = typer.Argument(..., help="Case ID"),
    output: Path = typer.Option(..., "--output", "-o", help="Output JSON file"),
    sources: list[str] = typer.Option([], "--source", "-s",
        help="<label>:<type>:<file.json>  (repeat for each source)"),
    correlate: bool = typer.Option(True, "--correlate/--no-correlate", help="Run cross-device correlation"),
    suspicious_only: bool = typer.Option(False, "--suspicious", help="Show only suspicious events"),
) -> None:
    """Fuse timelines from multiple devices into a single correlated timeline."""
    from core.v3.timeline_fusion import TimelineFusion
    import json as _j

    fusion = TimelineFusion(case_id)

    for src in sources:
        parts = src.split(":", 2)
        if len(parts) != 3:
            rprint(f"[red]Invalid source format: {src}  (use label:type:file.json)[/red]")
            raise typer.Exit(1)
        label, stype, fpath = parts
        fpath_p = Path(fpath)
        if not fpath_p.exists():
            rprint(f"[red]Source file not found: {fpath}[/red]")
            raise typer.Exit(1)
        try:
            data = _j.loads(fpath_p.read_text(encoding="utf-8"))
        except Exception as exc:
            rprint(f"[red]Failed to parse {fpath}: {exc}[/red]")
            raise typer.Exit(1)
        count = fusion.add_source(label, stype, data)
        rprint(f"  [dim]{label} ({stype}): {count} events[/dim]")

    if not sources:
        # Auto-load from evidence vault
        from core.chain_of_custody.evidence_manager import EvidenceManager
        mgr = EvidenceManager()
        for eid in mgr.list_evidence(case_id):
            ev_dir = mgr.evidence_dir(case_id, eid)
            for pf in ev_dir.glob("*.processes.json"):
                try:
                    data = _j.loads(pf.read_text(encoding="utf-8"))
                    procs = data.get("processes", []) if isinstance(data, dict) else data
                    count = fusion.add_source(eid, "memory", procs)
                    rprint(f"  [dim]{eid} (memory): {count} events[/dim]")
                except Exception:
                    pass

    rprint(f"\n[bold cyan]Timeline Fusion — {case_id}[/bold cyan]")

    with console.status("[cyan]Fusing timelines...[/cyan]"):
        events = fusion.build()
        if suspicious_only:
            events = [e for e in events if e.is_suspicious]

    sus = sum(1 for e in events if e.is_suspicious)
    rprint(f"  Total events     : {len(events)}")
    rprint(f"  Suspicious events: [red]{sus}[/red]")
    rprint(f"  Sources          : {len(fusion._sources)}")

    if correlate:
        with console.status("[cyan]Correlating cross-device events...[/cyan]"):
            clusters = fusion.correlate()
        rprint(f"  Correlated clusters: {len(clusters)}")
        for c in clusters[:5]:
            rprint(f"    [yellow]→[/yellow] {c.correlation_type}: {c.description[:80]}")

    fusion.export(output)
    rprint(f"\n[green]✔ Timeline exported: {output}[/green]")


# ── Collaboration ─────────────────────────────────────────────────────────────

@v3_app.command("collab")
def cmd_v3_collab(
    case_id: str = typer.Argument(..., help="Case ID"),
) -> None:
    """Show the collaboration dashboard for a case."""
    from core.v3.collaboration import CollaborationManager
    collab = CollaborationManager(case_id)
    dash = collab.get_dashboard()

    rprint(f"\n[bold cyan]Collaboration Dashboard — {case_id}[/bold cyan]")
    t = dash["tasks"]
    rprint(f"  Tasks    : {t['total']} total  |  {t['open']} open  |  {t['in_progress']} in-progress  |  {t['done']} done")
    ann = dash["annotations"]
    rprint(f"  Notes    : {dash['notes']}")
    rprint(f"  Flags    : {ann['flags']}  |  Critical: [red]{ann['critical']}[/red]")

    workload = dash.get("workload_by_examiner", {})
    if workload:
        rprint(f"\n  [bold]Workload:[/bold]")
        for examiner, count in workload.items():
            rprint(f"    {examiner}: {count} task(s)")

    activity = dash.get("recent_activity", [])
    if activity:
        rprint(f"\n  [bold]Recent Activity:[/bold]")
        for ev in activity[:5]:
            rprint(f"    [dim]{ev['ts'][:16]}[/dim]  {ev['actor']}  {ev['action']}  → {ev['target']}")


@v3_app.command("note")
def cmd_v3_note(
    case_id: str = typer.Option(..., "--case", "-c"),
    author: str = typer.Option(..., "--author", "-a"),
    text: str = typer.Argument(..., help="Note text"),
    evidence_id: str = typer.Option("", "--evidence", "-e"),
) -> None:
    """Add an investigator note to a case or evidence item."""
    from core.v3.collaboration import CollaborationManager
    collab = CollaborationManager(case_id)
    note = collab.add_note(author, text, evidence_id)
    rprint(f"[green]✔ Note added[/green]  ID={note.note_id}  author={author}")


@v3_app.command("task")
def cmd_v3_task(
    case_id: str = typer.Option(..., "--case", "-c"),
    from_examiner: str = typer.Option(..., "--from", "-f"),
    to_examiner: str = typer.Option(..., "--to", "-t"),
    title: str = typer.Argument(..., help="Task title"),
    description: str = typer.Option("", "--desc", "-d"),
    evidence_id: str = typer.Option("", "--evidence", "-e"),
    priority: str = typer.Option("medium", "--priority", "-p"),
) -> None:
    """Assign a task to an investigator."""
    from core.v3.collaboration import CollaborationManager
    collab = CollaborationManager(case_id)
    task = collab.assign_task(from_examiner, to_examiner, title, description, evidence_id, priority)
    rprint(f"[green]✔ Task assigned[/green]  ID={task.task_id}  {from_examiner} → {to_examiner}: {title}")


@v3_app.command("handoff")
def cmd_v3_handoff(
    case_id: str = typer.Option(..., "--case", "-c"),
    from_examiner: str = typer.Option(..., "--from", "-f"),
    to_examiner: str = typer.Option(..., "--to", "-t"),
    summary: str = typer.Argument(..., help="Handoff summary"),
) -> None:
    """Initiate a formal case handoff between investigators."""
    from core.v3.collaboration import CollaborationManager
    collab = CollaborationManager(case_id)
    handoff = collab.initiate_handoff(from_examiner, to_examiner, summary)
    rprint(f"\n[bold green]✔ Case Handoff Recorded[/bold green]")
    rprint(f"  ID          : {handoff['handoff_id']}")
    rprint(f"  From        : {from_examiner}")
    rprint(f"  To          : {to_examiner}")
    rprint(f"  Open tasks  : {handoff['open_tasks']}")
    rprint(f"  Notes       : {handoff['total_notes']}")
    rprint(f"  Critical ann: {handoff['critical_annotations']}")


# ── GUI Launcher ──────────────────────────────────────────────────────────────

@app.command("gui")
def cmd_gui() -> None:
    """Launch the ForgeLens Desktop GUI application."""
    import sys
    from pathlib import Path
    project_root = Path(__file__).resolve().parents[2]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    try:
        from frontend.app import main
        main()
    except Exception as exc:
        rprint(f"[red]Error starting GUI: {exc}[/red]")
        raise typer.Exit(1)


# ── TUI Launcher ──────────────────────────────────────────────────────────────

@app.command("tui")
def cmd_tui(
    dump: str = typer.Option("", "--dump", "-d", help="Path to memory dump to analyze on startup"),
) -> None:
    """Launch the interactive Terminal User Interface (TUI)."""
    try:
        from cli.tui import ForgeLensTUI
        tui_app = ForgeLensTUI(dump_path=dump)
        tui_app.run()
    except ImportError as e:
        rprint("[bold red]ImportError when loading TUI.[/bold red]")
        rprint(f"Exception details: {e}")
        rprint("Please ensure textual is installed: [cyan]pip install textual[/cyan]")
        raise typer.Exit(1)
    except Exception as exc:
        rprint(f"[red]Error starting TUI: {exc}[/red]")
        raise typer.Exit(1)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()

