"""
ForgeLens Setup & Dependency Checker
======================================
Checks, reports, and installs all tools required by ForgeLens.

Covers:
  - Python packages (pip-installable)
  - Binary tools (winpmem, avml, adb, volatility3, etc.)
  - Platform-specific system tools

Usage:
    from core.setup.checker import SetupChecker
    report = SetupChecker().check_all()
    SetupChecker().install_missing(report)
"""

from __future__ import annotations

import importlib
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from loguru import logger

# ── Project root ──────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[3]
TOOLS_DIR = ROOT / "tools"
TOOLS_DIR.mkdir(exist_ok=True)

OS = platform.system()  # Windows | Linux | Darwin


class Status(str, Enum):
    OK = "ok"
    MISSING = "missing"
    OPTIONAL_MISSING = "optional_missing"
    SKIPPED = "skipped"          # not applicable on this OS


@dataclass
class ToolCheck:
    name: str
    description: str
    status: Status
    version: str = ""
    install_hint: str = ""
    auto_installable: bool = False   # can ForgeLens install it automatically?
    platforms: list[str] = field(default_factory=lambda: ["Windows", "Linux", "Darwin"])
    required: bool = True


@dataclass
class SetupReport:
    checks: list[ToolCheck] = field(default_factory=list)

    @property
    def ok(self) -> list[ToolCheck]:
        return [c for c in self.checks if c.status == Status.OK]

    @property
    def missing(self) -> list[ToolCheck]:
        return [c for c in self.checks if c.status == Status.MISSING]

    @property
    def optional_missing(self) -> list[ToolCheck]:
        return [c for c in self.checks if c.status == Status.OPTIONAL_MISSING]

    @property
    def skipped(self) -> list[ToolCheck]:
        return [c for c in self.checks if c.status == Status.SKIPPED]

    @property
    def all_required_ok(self) -> bool:
        return len(self.missing) == 0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _pip_install(package: str) -> tuple[bool, str]:
    """Install a Python package via pip."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", package],
            capture_output=True, text=True, timeout=120,
        )
        return result.returncode == 0, result.stderr.strip()
    except Exception as exc:
        return False, str(exc)


def _check_python_pkg(import_name: str) -> tuple[bool, str]:
    """Check if a Python package is importable and return its version."""
    import io, contextlib
    try:
        # Suppress any stdout/stderr noise from broken native extensions (e.g. libyara.dll)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            mod = importlib.import_module(import_name)
        version = getattr(mod, "__version__", "")
        return True, version
    except Exception:
        # Catches ImportError, FileNotFoundError (broken native DLLs), OSError, etc.
        return False, ""


def _check_binary(names: list[str]) -> tuple[bool, str]:
    """Check if any of the given binary names are on PATH or in tools/."""
    for name in names:
        # tools/ first
        candidate = TOOLS_DIR / name
        if candidate.exists():
            return True, str(candidate)
        # PATH
        found = shutil.which(name)
        if found:
            return True, found
    return False, ""


def _run_version(cmd: list[str]) -> str:
    """Run a command and return its first line of output."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return (r.stdout.strip() or r.stderr.strip()).splitlines()[0][:80]
    except Exception:
        return ""


# ── Individual checkers ───────────────────────────────────────────────────────

def _check_winpmem() -> ToolCheck:
    names = ["winpmem_mini_x64_rc2.exe", "winpmem_mini_x64.exe",
             "winpmem_mini_x86.exe", "winpmem.exe", "DumpIt.exe"]
    found, path = _check_binary(names)
    return ToolCheck(
        name="WinPmem",
        description="Windows live RAM acquisition",
        status=Status.OK if found else Status.MISSING,
        version=Path(path).name if found else "",
        install_hint="python forgelens.py memory setup",
        auto_installable=True,
        platforms=["Windows"],
        required=True,
    )


def _check_avml() -> ToolCheck:
    found, path = _check_binary(["avml", "avml-memory"])
    return ToolCheck(
        name="AVML",
        description="Linux live RAM acquisition (no kernel module required)",
        status=Status.OK if found else Status.OPTIONAL_MISSING,
        version=Path(path).name if found else "",
        install_hint="Download from https://github.com/microsoft/avml/releases → place in tools/",
        auto_installable=True,
        platforms=["Linux"],
        required=False,
    )


def _check_adb() -> ToolCheck:
    found, path = _check_binary(["adb", "adb.exe"])
    version = _run_version(["adb", "version"]) if found else ""
    return ToolCheck(
        name="ADB",
        description="Android device acquisition (Android Platform Tools)",
        status=Status.OK if found else Status.OPTIONAL_MISSING,
        version=version,
        install_hint="https://developer.android.com/tools/releases/platform-tools",
        auto_installable=False,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_volatility3() -> ToolCheck:
    found_bin, path = _check_binary(["vol3", "vol", "volatility3"])
    if not found_bin:
        # Try python -m volatility3
        try:
            r = subprocess.run(
                [sys.executable, "-m", "volatility3", "--help"],
                capture_output=True, timeout=5,
            )
            found_bin = r.returncode == 0
            path = "python -m volatility3"
        except Exception:
            pass
    pkg_ok, ver = _check_python_pkg("volatility3")
    ok = found_bin or pkg_ok
    return ToolCheck(
        name="Volatility3",
        description="Memory image forensics framework",
        status=Status.OK if ok else Status.MISSING,
        version=ver,
        install_hint="pip install volatility3==2.7.0",
        auto_installable=True,
        platforms=["Windows", "Linux", "Darwin"],
        required=True,
    )


def _check_libimobiledevice() -> ToolCheck:
    tools = ["idevice_id", "ideviceinfo", "idevicebackup2"]
    found, path = _check_binary(tools)
    # Fallback: pymobiledevice3
    if not found:
        pkg_ok, _ = _check_python_pkg("pymobiledevice3")
        if pkg_ok:
            return ToolCheck(
                name="libimobiledevice",
                description="iOS device acquisition",
                status=Status.OK,
                version="pymobiledevice3 (Python fallback)",
                install_hint="",
                platforms=["Windows", "Linux", "Darwin"],
                required=False,
            )
    return ToolCheck(
        name="libimobiledevice",
        description="iOS device acquisition (idevicebackup2, ideviceinfo, etc.)",
        status=Status.OK if found else Status.OPTIONAL_MISSING,
        version=Path(path).name if found else "",
        install_hint=(
            "Linux/macOS: apt install libimobiledevice-utils  or  brew install libimobiledevice\n"
            "  Windows: pip install pymobiledevice3  (requires MSVC Build Tools)"
        ),
        auto_installable=False,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_pymobiledevice3() -> ToolCheck:
    ok, ver = _check_python_pkg("pymobiledevice3")
    return ToolCheck(
        name="pymobiledevice3",
        description="iOS acquisition Python library (fallback for libimobiledevice)",
        status=Status.OK if ok else Status.OPTIONAL_MISSING,
        version=ver,
        install_hint="pip install pymobiledevice3  (requires MSVC Build Tools on Windows)",
        auto_installable=True,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_yara() -> ToolCheck:
    ok, ver = _check_python_pkg("yara")
    return ToolCheck(
        name="yara-python",
        description="YARA rule scanning for malware detection",
        status=Status.OK if ok else Status.OPTIONAL_MISSING,
        version=ver,
        install_hint="pip install yara-python  (requires C compiler / MSVC Build Tools on Windows)",
        auto_installable=True,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_blake3() -> ToolCheck:
    ok, ver = _check_python_pkg("blake3")
    return ToolCheck(
        name="blake3",
        description="BLAKE3 hashing algorithm (faster than SHA256)",
        status=Status.OK if ok else Status.OPTIONAL_MISSING,
        version=ver,
        install_hint="pip install blake3",
        auto_installable=True,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_reportlab() -> ToolCheck:
    ok, ver = _check_python_pkg("reportlab")
    return ToolCheck(
        name="reportlab",
        description="PDF report generation",
        status=Status.OK if ok else Status.OPTIONAL_MISSING,
        version=ver,
        install_hint="pip install reportlab",
        auto_installable=True,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_pyewf() -> ToolCheck:
    ok, ver = _check_python_pkg("pyewf")
    return ToolCheck(
        name="pyewf",
        description="E01 forensic image format support",
        status=Status.OK if ok else Status.OPTIONAL_MISSING,
        version=ver,
        install_hint=(
            "Linux: apt install libewf-dev && pip install pyewf\n"
            "  Windows: requires libewf build — see https://github.com/libyal/libewf"
        ),
        auto_installable=False,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_pytsk3() -> ToolCheck:
    ok, ver = _check_python_pkg("pytsk3")
    return ToolCheck(
        name="pytsk3",
        description="The Sleuth Kit bindings — filesystem parsing",
        status=Status.OK if ok else Status.MISSING,
        version=ver,
        install_hint="pip install pytsk3",
        auto_installable=True,
        platforms=["Windows", "Linux", "Darwin"],
        required=True,
    )


def _check_cryptography() -> ToolCheck:
    ok, ver = _check_python_pkg("cryptography")
    return ToolCheck(
        name="cryptography",
        description="AES-256-GCM encryption and HMAC signing for evidence vault",
        status=Status.OK if ok else Status.MISSING,
        version=ver,
        install_hint="pip install cryptography",
        auto_installable=True,
        platforms=["Windows", "Linux", "Darwin"],
        required=True,
    )


def _check_docker() -> ToolCheck:
    found, path = _check_binary(["docker", "docker.exe"])
    version = _run_version(["docker", "--version"]) if found else ""
    return ToolCheck(
        name="Docker CLI",
        description="Container forensics (docker export, inspect)",
        status=Status.OK if found else Status.OPTIONAL_MISSING,
        version=version,
        install_hint="https://docs.docker.com/get-docker/",
        auto_installable=False,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_aws_cli() -> ToolCheck:
    found, path = _check_binary(["aws", "aws.exe"])
    version = _run_version(["aws", "--version"]) if found else ""
    return ToolCheck(
        name="AWS CLI",
        description="AWS cloud acquisition (EBS snapshots, IAM artifacts)",
        status=Status.OK if found else Status.OPTIONAL_MISSING,
        version=version,
        install_hint="https://aws.amazon.com/cli/",
        auto_installable=False,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_azure_cli() -> ToolCheck:
    found, path = _check_binary(["az", "az.cmd", "az.exe"])
    version = _run_version(["az", "--version"]) if found else ""
    return ToolCheck(
        name="Azure CLI",
        description="Azure cloud acquisition (managed disk SAS access)",
        status=Status.OK if found else Status.OPTIONAL_MISSING,
        version=version,
        install_hint="https://docs.microsoft.com/en-us/cli/azure/install-azure-cli",
        auto_installable=False,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_kubectl() -> ToolCheck:
    found, path = _check_binary(["kubectl", "kubectl.exe"])
    version = _run_version(["kubectl", "version", "--client"]) if found else ""
    return ToolCheck(
        name="kubectl",
        description="Kubernetes forensics (pods, services, events)",
        status=Status.OK if found else Status.OPTIONAL_MISSING,
        version=version,
        install_hint="https://kubernetes.io/docs/tasks/tools/",
        auto_installable=False,
        platforms=["Windows", "Linux", "Darwin"],
        required=False,
    )


def _check_avml_auto_install() -> bool:
    """Download AVML binary from GitHub (Linux only)."""
    if OS != "Linux":
        return False
    import urllib.request, json as _json
    try:
        api = "https://api.github.com/repos/microsoft/avml/releases/latest"
        req = urllib.request.Request(api, headers={"User-Agent": "ForgeLens/0.1"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = _json.loads(resp.read())
        assets = data.get("assets", [])
        asset = next((a for a in assets if "avml" in a["name"].lower()
                      and not a["name"].endswith(".sha256")), None)
        if not asset:
            return False
        dest = TOOLS_DIR / asset["name"]
        logger.info("Downloading AVML: {}", asset["name"])
        urllib.request.urlretrieve(asset["browser_download_url"], dest)
        dest.chmod(0o755)
        return True
    except Exception as exc:
        logger.error("AVML download failed: {}", exc)
        return False


# ── Main checker ──────────────────────────────────────────────────────────────

# Map: check_fn → pip_package (for auto-install)
_PIP_AUTO: dict[str, str] = {
    "Volatility3":     "volatility3==2.7.0",
    "yara-python":     "yara-python",
    "blake3":          "blake3",
    "reportlab":       "reportlab",
    "pytsk3":          "pytsk3",
    "cryptography":    "cryptography>=44.0.0",
    "pymobiledevice3": "pymobiledevice3",
}


class SetupChecker:
    """Run all dependency checks and optionally install missing tools."""

    def check_all(self) -> SetupReport:
        """Run every check and return a SetupReport."""
        report = SetupReport()
        checkers = [
            # Python packages — required
            _check_cryptography,
            _check_pytsk3,
            _check_volatility3,
            # Python packages — optional
            _check_yara,
            _check_blake3,
            _check_reportlab,
            _check_pyewf,
            _check_pymobiledevice3,
            # Binary tools
            _check_winpmem,
            _check_avml,
            _check_adb,
            _check_libimobiledevice,
            # Cloud / container
            _check_docker,
            _check_aws_cli,
            _check_azure_cli,
            _check_kubectl,
        ]

        for fn in checkers:
            check = fn()
            # Mark as SKIPPED if not applicable on this OS
            if OS not in check.platforms:
                check.status = Status.SKIPPED
            report.checks.append(check)
            logger.debug("Check {}: {}", check.name, check.status.value)

        return report

    def install_missing(
        self,
        report: SetupReport,
        include_optional: bool = False,
        dry_run: bool = False,
    ) -> dict[str, bool]:
        """
        Install missing tools where possible.

        Args:
            report:           SetupReport from check_all().
            include_optional: Also install optional missing tools.
            dry_run:          Print what would be installed without doing it.

        Returns:
            Dict of {tool_name: success}.
        """
        results: dict[str, bool] = {}
        targets = report.missing[:]
        if include_optional:
            targets += report.optional_missing

        for check in targets:
            if check.status == Status.SKIPPED:
                continue
            if not check.auto_installable:
                logger.info("Skipping {} — manual install required", check.name)
                results[check.name] = False
                continue

            # WinPmem — special downloader
            if check.name == "WinPmem" and OS == "Windows":
                if dry_run:
                    logger.info("[DRY RUN] Would download WinPmem via setup_winpmem.py")
                    results[check.name] = False
                    continue
                logger.info("Downloading WinPmem...")
                try:
                    import importlib.util as _ilu
                    spec = _ilu.spec_from_file_location(
                        "setup_winpmem", ROOT / "tools" / "setup_winpmem.py"
                    )
                    mod = _ilu.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    rc = mod.main()
                    results[check.name] = rc == 0
                except Exception as exc:
                    logger.error("WinPmem install failed: {}", exc)
                    results[check.name] = False
                continue

            # AVML — GitHub binary download
            if check.name == "AVML" and OS == "Linux":
                if dry_run:
                    logger.info("[DRY RUN] Would download AVML from GitHub")
                    results[check.name] = False
                    continue
                logger.info("Downloading AVML...")
                results[check.name] = _check_avml_auto_install()
                continue

            # pip packages
            pip_pkg = _PIP_AUTO.get(check.name)
            if pip_pkg:
                if dry_run:
                    logger.info("[DRY RUN] Would run: pip install {}", pip_pkg)
                    results[check.name] = False
                    continue
                logger.info("Installing {} via pip...", check.name)
                ok, err = _pip_install(pip_pkg)
                if not ok:
                    logger.error("pip install {} failed: {}", pip_pkg, err)
                results[check.name] = ok
            else:
                results[check.name] = False

        return results
