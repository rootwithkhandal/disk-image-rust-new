# main.py — ThirdEye CLI
import platform
import sys
from datetime import datetime
from pathlib import Path

import click

from utils.config_loader import get_config
from utils.logger_config import setup_logger
from utils.reporter import ReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _init_logger(cfg: dict) -> None:
    log_cfg = cfg.get("logging", {})
    setup_logger(
        log_file=log_cfg.get("log_file", "logs/thirdeye.log"),
        level=log_cfg.get("level", "INFO"),
    )


def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


# ---------------------------------------------------------------------------
# CLI root
# ---------------------------------------------------------------------------

@click.group()
@click.version_option("2.0.0", prog_name="thirdeye")
def cli():
    """ThirdEye — Digital Forensics & Malware Analysis Toolkit"""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--image",       required=True,  help="Path to the disk image (.img)")
@click.option("--mount-point", required=True,  help="Directory to mount the image at")
@click.option("--vt-key",      default=None,   help="VirusTotal API key (overrides config)")
@click.option("--rules",       default=None,   help="YARA rules file or directory (overrides config)")
@click.option("--output-dir",  default=None,   help="Report output directory (overrides config)")
@click.option("--dry-run",     is_flag=True,   help="Simulate without performing any operations")
def scan(image, mount_point, vt_key, rules, output_dir, dry_run):
    """Mount an image, run VirusTotal + YARA scans, generate a report, then unmount."""
    from loguru import logger
    from imaging.mounter import mount_img, unmount_img
    from analysis.virus_total_checker import VirusTotalScanner
    from ioc.ioc_detector import IOCDetector

    cfg = get_config()
    _init_logger(cfg)

    vt_api_key  = vt_key   or cfg.get("virustotal", {}).get("api_key", "")
    rules_path  = rules    or cfg.get("yara", {}).get("rules_path", "malware_rules.yar")
    report_dir  = output_dir or cfg.get("reporting", {}).get("output_dir", "reports")
    rate_sleep  = cfg.get("virustotal", {}).get("rate_limit_sleep", 15)

    if dry_run:
        click.echo(f"[DRY RUN] Would mount '{image}' at '{mount_point}'")
        click.echo(f"[DRY RUN] Would run VT scan with key ending ...{vt_api_key[-4:] if len(vt_api_key) > 4 else '****'}")
        click.echo(f"[DRY RUN] Would run YARA scan with rules: '{rules_path}'")
        click.echo(f"[DRY RUN] Would save report to '{report_dir}'")
        return

    logger.info("=== ThirdEye Scan Starting ===")
    report = ReportGenerator(output_dir=report_dir)

    # Mount
    mounted = mount_img(image, mount_point)
    if not mounted:
        click.echo("[Error] Failed to mount image. Aborting.", err=True)
        sys.exit(1)

    try:
        mount_path = Path(mounted)

        # VirusTotal scan
        logger.info("Starting VirusTotal scan...")
        vt = VirusTotalScanner(api_key=vt_api_key, rate_limit_sleep=rate_sleep)
        vt_results = vt.check_directory(mount_path)
        report.add_section("virustotal", vt_results)

        # YARA / IOC scan
        logger.info("Starting YARA IOC scan...")
        ioc = IOCDetector(rules_path)
        ioc_results = ioc.scan_directory(mount_path)
        report.add_section("ioc_matches", ioc_results)

    finally:
        unmount_img(mount_point, image)

    # Save report
    base_name = f"scan_{_timestamp()}"
    report.save_all(base_name)
    click.echo(f"[Done] Report saved to '{report_dir}/{base_name}'")


# ---------------------------------------------------------------------------
# hash
# ---------------------------------------------------------------------------

@cli.command(name="hash")
@click.option("--directory",  required=True, help="Directory to hash")
@click.option("--output-dir", default=None,  help="Report output directory (overrides config)")
@click.option("--dry-run",    is_flag=True,  help="Simulate without performing any operations")
def hash_cmd(directory, output_dir, dry_run):
    """Hash all files in a directory and export results."""
    from loguru import logger
    from analysis.file_hasher import DirectoryHasher

    cfg = get_config()
    _init_logger(cfg)

    report_dir = output_dir or cfg.get("reporting", {}).get("output_dir", "reports")
    dir_path   = Path(directory)

    if dry_run:
        click.echo(f"[DRY RUN] Would hash all files under '{directory}'")
        click.echo(f"[DRY RUN] Would save report to '{report_dir}'")
        return

    if not dir_path.is_dir():
        click.echo(f"[Error] '{directory}' is not a valid directory.", err=True)
        sys.exit(1)

    logger.info("=== ThirdEye Hash Analysis Starting ===")
    hasher  = DirectoryHasher()
    results = hasher.analyze(dir_path)

    report = ReportGenerator(output_dir=report_dir)
    report.add_section("hashes", results)
    base_name = f"hashes_{_timestamp()}"
    report.save_all(base_name)
    click.echo(f"[Done] {len(results)} files hashed. Report saved to '{report_dir}/{base_name}'")


# ---------------------------------------------------------------------------
# ioc
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--directory",  required=True, help="Directory to scan")
@click.option("--rules",      default=None,  help="YARA rules file or directory (overrides config)")
@click.option("--output-dir", default=None,  help="Report output directory (overrides config)")
@click.option("--dry-run",    is_flag=True,  help="Simulate without performing any operations")
def ioc(directory, rules, output_dir, dry_run):
    """Run a YARA IOC scan on a directory."""
    from loguru import logger
    from ioc.ioc_detector import IOCDetector

    cfg = get_config()
    _init_logger(cfg)

    rules_path = rules      or cfg.get("yara", {}).get("rules_path", "malware_rules.yar")
    report_dir = output_dir or cfg.get("reporting", {}).get("output_dir", "reports")
    dir_path   = Path(directory)

    if dry_run:
        click.echo(f"[DRY RUN] Would scan '{directory}' with rules '{rules_path}'")
        click.echo(f"[DRY RUN] Would save report to '{report_dir}'")
        return

    if not dir_path.is_dir():
        click.echo(f"[Error] '{directory}' is not a valid directory.", err=True)
        sys.exit(1)

    logger.info("=== ThirdEye IOC Scan Starting ===")
    detector = IOCDetector(rules_path)
    results  = detector.scan_directory(dir_path)

    report = ReportGenerator(output_dir=report_dir)
    report.add_section("ioc_matches", results)
    base_name = f"ioc_{_timestamp()}"
    report.save_all(base_name)
    click.echo(f"[Done] {len(results)} match(es) found. Report saved to '{report_dir}/{base_name}'")


# ---------------------------------------------------------------------------
# sysinfo
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--output-dir", default=None, help="Report output directory (overrides config)")
def sysinfo(output_dir):
    """Collect system info (logs, processes, network) for the current OS."""
    from loguru import logger

    cfg = get_config()
    _init_logger(cfg)

    report_dir = output_dir or cfg.get("reporting", {}).get("output_dir", "reports")
    report     = ReportGenerator(output_dir=report_dir)
    os_name    = platform.system()

    logger.info(f"=== ThirdEye Sysinfo Collection ({os_name}) ===")

    if os_name == "Linux":
        from automation.auto_linux import LinuxAutomation
        auto = LinuxAutomation()

        procs = auto.list_running_processes()
        report.add_section("processes", procs)

        net = auto.scan_network_connections()
        report.add_section("network", [{"output": net}] if net else [])

        crons = auto.collect_cron_jobs()
        report.add_section("cron_jobs", [crons])

    elif os_name == "Windows":
        from automation.auto_win import WindowsAutomation
        auto = WindowsAutomation()

        procs = auto.list_running_processes()
        report.add_section("processes", procs)

        net = auto.list_network_connections()
        report.add_section("network", [{"output": net}] if net else [])

        startup = auto.list_startup_items()
        report.add_section("startup_items", [{"output": startup}] if startup else [])

        prefetch = auto.collect_prefetch_list()
        report.add_section("prefetch", prefetch)

    else:
        click.echo(f"[Warning] Unsupported OS: {os_name}. No collection performed.")

    base_name = f"sysinfo_{_timestamp()}"
    report.save_all(base_name)
    click.echo(f"[Done] Sysinfo collected. Report saved to '{report_dir}/{base_name}'")


# ---------------------------------------------------------------------------
# image
# ---------------------------------------------------------------------------

@cli.command(name="image")
@click.option("--device",  default=None, help="Block device to image (e.g. /dev/sdb)")
@click.option("--output",  default=None, help="Output .img file path")
@click.option("--dry-run", is_flag=True, help="Simulate without performing any operations")
def image_cmd(device, output, dry_run):
    """Image a disk device to a .img file (Linux only)."""
    from loguru import logger
    from imaging.disk_imager import DiskImager

    cfg = get_config()
    _init_logger(cfg)

    if platform.system() != "Linux":
        click.echo("[Warning] Disk imaging is currently only supported on Linux.")
        sys.exit(1)

    block_size_mb = cfg.get("imaging", {}).get("block_size_mb", 4)
    imager = DiskImager(block_size_mb=block_size_mb)

    if not device:
        device = imager.select_device()
    if not device:
        sys.exit(1)

    if not output:
        output = imager.get_output_image_path()

    logger.info("=== ThirdEye Disk Imaging Starting ===")
    success = imager.create_image(device, output, dry_run=dry_run)

    if success:
        click.echo(f"[Done] Image saved to '{output}'")
    else:
        click.echo("[Error] Imaging failed.", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
