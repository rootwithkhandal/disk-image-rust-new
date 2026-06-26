"""
Forensic Disk Image Mounter
============================
Read-only mounting of forensic disk images for analysis.

Supports:
  Windows  — Arsenal Image Mounter (AIM), OSFMount, ImDisk (auto-detected)
  Linux    — loop device + mount (built-in kernel support)
  macOS    — hdiutil (built-in)

All mounts are enforced read-only to preserve evidence integrity.
Chain of custody events are recorded for every mount/unmount.

Usage:
    from core.imaging.mounter import ImageMounter

    mounter = ImageMounter()
    result = mounter.mount("evidence/image.dd", case_id="CASE-001", examiner="Analyst")
    print(result.mount_point)

    mounter.unmount(result.mount_id)
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

OS = platform.system()

# ── Windows mount tools (in preference order) ─────────────────────────────────
# All are open-source:
#   Arsenal Image Mounter (AGPL): https://github.com/ArsenalRecon/Arsenal-Image-Mounter
#   ImDisk Toolkit (GPL):         https://sourceforge.net/projects/imdisk-toolkit/
_WIN_TOOLS = [
    "aim_cli.exe",      # Arsenal Image Mounter CLI (AGPL, supports DD/E01/VHD/AFF)
    "AIM_CLI.exe",      # alternate casing
    "imdisk.exe",       # ImDisk (GPL, supports DD/RAW)
]

# State file — tracks all active mounts across sessions
_MOUNT_STATE_FILE = Path(__file__).resolve().parents[3] / "evidence" / ".mount_state.json"


@dataclass
class MountResult:
    success: bool
    mount_id: str = ""
    image_path: str = ""
    mount_point: str = ""    # Drive letter (Windows) or /mnt/... (Linux/macOS)
    tool_used: str = ""
    case_id: str = ""
    evidence_id: str = ""
    mounted_at: str = ""
    partitions: list[dict] = field(default_factory=list)
    error: str = ""

    def __str__(self) -> str:
        if self.success:
            return f"[MOUNTED] {self.image_path} → {self.mount_point} (id={self.mount_id})"
        return f"[FAILED] {self.error}"


@dataclass
class ActiveMount:
    mount_id: str
    image_path: str
    mount_point: str
    tool_used: str
    case_id: str
    evidence_id: str
    mounted_at: str
    os: str = OS


class ImageMounter:
    """
    Read-only forensic image mounter.
    Supports DD/RAW, E01 (via AIM on Windows), and split images.
    """

    def __init__(self) -> None:
        self._active: dict[str, ActiveMount] = self._load_state()

    # ── Public API ────────────────────────────────────────────────────────────

    def mount(
        self,
        image_path: str | Path,
        case_id: str = "",
        evidence_id: str = "",
        examiner: str = "analyst",
        mount_point: str | Path | None = None,
        partition_index: int = 0,
    ) -> MountResult:
        """
        Mount a forensic image read-only for analysis.

        Args:
            image_path:      Path to the .dd / .raw / .e01 image file.
            case_id:         Case ID for chain of custody logging.
            evidence_id:     Evidence ID (auto-derived from filename if empty).
            examiner:        Examiner name for custody log.
            mount_point:     Where to mount (auto-assigned if None).
            partition_index: Which partition to mount (0 = first / auto).

        Returns:
            MountResult with mount_point and mount_id.
        """
        image = Path(image_path).resolve()
        if not image.exists():
            return MountResult(success=False, error=f"Image not found: {image}")

        eid = evidence_id or image.stem
        mid = str(uuid.uuid4())[:8].upper()

        logger.info("Mounting image | {} | case={} | evidence={}", image.name, case_id, eid)

        if OS == "Windows":
            result = self._mount_windows(image, mid, mount_point, partition_index)
        elif OS == "Linux":
            result = self._mount_linux(image, mid, mount_point, partition_index)
        elif OS == "Darwin":
            result = self._mount_macos(image, mid, mount_point)
        else:
            return MountResult(success=False, error=f"Unsupported OS: {OS}")

        if result.success:
            result.case_id = case_id
            result.evidence_id = eid
            result.mounted_at = datetime.now(timezone.utc).isoformat()

            # Track active mount
            self._active[mid] = ActiveMount(
                mount_id=mid,
                image_path=str(image),
                mount_point=result.mount_point,
                tool_used=result.tool_used,
                case_id=case_id,
                evidence_id=eid,
                mounted_at=result.mounted_at,
            )
            self._save_state()

            # Chain of custody
            self._record_coc(case_id, eid, examiner, "mounted",
                             f"Image mounted read-only at {result.mount_point} via {result.tool_used}")
            logger.info("Mounted: {} → {}", image.name, result.mount_point)

        return result

    def unmount(self, mount_id: str, examiner: str = "analyst") -> bool:
        """
        Unmount a previously mounted image by its mount_id.
        Returns True on success.
        """
        active = self._active.get(mount_id)
        if not active:
            logger.error("Mount ID not found: {}", mount_id)
            return False

        logger.info("Unmounting {} ({})", active.mount_point, mount_id)

        if OS == "Windows":
            ok = self._unmount_windows(active)
        elif OS == "Linux":
            ok = self._unmount_linux(active)
        elif OS == "Darwin":
            ok = self._unmount_macos(active)
        else:
            ok = False

        if ok:
            self._record_coc(
                active.case_id, active.evidence_id, examiner,
                "unmounted", f"Image unmounted from {active.mount_point}",
            )
            del self._active[mount_id]
            self._save_state()
            logger.info("Unmounted: {}", active.mount_point)

        return ok

    def unmount_all(self) -> int:
        """Unmount all active mounts. Returns count unmounted."""
        ids = list(self._active.keys())
        count = 0
        for mid in ids:
            if self.unmount(mid):
                count += 1
        return count

    def list_mounts(self) -> list[ActiveMount]:
        """Return all currently active mounts."""
        return list(self._active.values())

    # ── Windows ───────────────────────────────────────────────────────────────

    def _mount_windows(
        self,
        image: Path,
        mount_id: str,
        mount_point: str | Path | None,
        partition_index: int,
    ) -> MountResult:
        tool = self._find_win_tool()

        # Auto-pick a free drive letter if none given
        drive = str(mount_point) if mount_point else self._free_drive_letter()
        if not drive:
            return MountResult(success=False, error="No free drive letters available")

        # Normalise: ensure single letter
        drive_letter = drive.rstrip(":\\").upper()

        if tool is None:
            # Fallback: try to mount via PowerShell (works for raw/dd only, no E01)
            return self._mount_windows_ps(image, drive_letter, mount_id)

        tool_name = Path(tool).name.lower()

        # ── Arsenal Image Mounter ─────────────────────────────────────────────
        if "aim_cli" in tool_name:
            return self._mount_aim(image, drive_letter, mount_id, tool)

        # ── ImDisk (GPL) ──────────────────────────────────────────────────────
        if "imdisk" in tool_name:
            return self._mount_imdisk(image, drive_letter, mount_id, tool)

        return MountResult(success=False, error="No supported Windows mount tool found")

    def _mount_aim(self, image: Path, drive_letter: str, mount_id: str, tool: str) -> MountResult:
        """
        Mount using Arsenal Image Mounter CLI (open-source, AGPL).
        AIM mounts as a full virtual SCSI disk — Windows then assigns a drive letter.

        CLI reference: https://github.com/ArsenalRecon/Arsenal-Image-Mounter
        """
        # AIM CLI syntax: aim_cli --mount --filename=<img> --readonly [--fakembr] [--driveletter=X]
        cmd = [
            tool,
            "--mount",
            f"--filename={image}",
            "--readonly",
            "--fakembr",          # present as complete MBR disk
        ]
        if drive_letter:
            cmd.append(f"--driveletter={drive_letter}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode == 0:
            # Parse assigned drive letter from output
            assigned = drive_letter
            for line in stdout.splitlines():
                if "drive" in line.lower() and ":" in line:
                    parts = line.split(":")
                    for p in parts:
                        p = p.strip()
                        if len(p) == 1 and p.isalpha():
                            assigned = p.upper()
                            break
            return MountResult(
                success=True, mount_id=mount_id,
                image_path=str(image),
                mount_point=f"{assigned}:\\",
                tool_used="Arsenal Image Mounter (AGPL)",
            )

        error = stderr or stdout
        return MountResult(
            success=False,
            error=f"Arsenal Image Mounter failed (rc={result.returncode}): {error[:300]}",
        )

    def _mount_imdisk(self, image: Path, drive_letter: str, mount_id: str, tool: str) -> MountResult:
        """
        Mount using ImDisk (open-source, GPL).
        Supports raw DD/IMG images read-only.

        CLI reference: https://sourceforge.net/projects/imdisk-toolkit/
        Syntax: imdisk -a -t file -f <image> -m <drive>: -o ro[,...]
        """
        cmd = [
            tool, "-a",
            "-t", "file",
            "-f", str(image),
            "-m", f"{drive_letter}:",
            "-o", "ro,awe",      # ro=read-only, awe=use AWE memory mapping
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)

        if result.returncode == 0:
            return MountResult(
                success=True, mount_id=mount_id,
                image_path=str(image),
                mount_point=f"{drive_letter}:\\",
                tool_used="ImDisk (GPL)",
            )

        # Retry without awe flag (some ImDisk versions don't support it)
        cmd_simple = [
            tool, "-a",
            "-t", "file",
            "-f", str(image),
            "-m", f"{drive_letter}:",
            "-o", "ro",
        ]
        result2 = subprocess.run(cmd_simple, capture_output=True, text=True, timeout=90)
        if result2.returncode == 0:
            return MountResult(
                success=True, mount_id=mount_id,
                image_path=str(image),
                mount_point=f"{drive_letter}:\\",
                tool_used="ImDisk (GPL)",
            )

        error = result2.stderr.strip() or result2.stdout.strip() or result.stderr.strip()
        return MountResult(
            success=False,
            error=f"ImDisk failed (rc={result2.returncode}): {error[:300]}",
        )

    def _mount_windows_ps(self, image: Path, drive_letter: str, mount_id: str) -> MountResult:
        """
        Mount a disk image on Windows.
        - .vhd / .vhdx / .iso  → PowerShell Mount-DiskImage (built-in)
        - .dd / .raw / .img    → Requires Arsenal Image Mounter, OSFMount, or ImDisk
        """
        suffix = image.suffix.lower()
        native_formats = {".vhd", ".vhdx", ".iso"}

        if suffix not in native_formats:
            return MountResult(
                success=False,
                error=(
                    f"Raw DD/E01 images cannot be mounted by Windows without a third-party tool.\n"
                    f"Install one of these tools and place the executable in tools/:\n"
                    f"  • Arsenal Image Mounter (aim_cli.exe) — https://arsenalrecon.com/downloads\n"
                    f"  • OSFMount (osfmount.com)             — https://www.osforensics.com/tools/mount-disk-images.html\n"
                    f"  • ImDisk (imdisk.exe)                 — https://sourceforge.net/projects/imdisk-toolkit/"
                ),
            )

        # Native VHD/VHDX/ISO mount via PowerShell
        abs_path = str(image.resolve())
        ps = (
            f"$disk = Mount-DiskImage -ImagePath '{abs_path}' -Access ReadOnly -PassThru; "
            f"$part = $disk | Get-Disk | Get-Partition | "
            f"Where-Object {{ $_.Type -ne 'Reserved' -and $_.Size -gt 1MB }} | "
            f"Select-Object -First 1; "
            f"if ($part.DriveLetter) {{ Write-Output $part.DriveLetter }} "
            f"else {{ $part | Add-PartitionAccessPath -AccessPath '{drive_letter}:' -ErrorAction SilentlyContinue; "
            f"Write-Output '{drive_letter}' }}"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            assigned = result.stdout.strip().splitlines()[-1].strip().rstrip(":\\")
            if not assigned:
                assigned = drive_letter
            return MountResult(
                success=True, mount_id=mount_id,
                image_path=str(image), mount_point=f"{assigned}:\\",
                tool_used="PowerShell Mount-DiskImage",
            )
        error = result.stderr.strip() or result.stdout.strip()
        return MountResult(success=False, error=f"Mount-DiskImage failed: {error[:300]}")

    def _unmount_windows(self, active: ActiveMount) -> bool:
        tool = self._find_win_tool()
        tool_name = Path(tool).name.lower() if tool else ""

        if "aim_cli" in tool_name:
            result = subprocess.run(
                [tool, "--dismount", f"--filename={active.image_path}"],
                capture_output=True, text=True, timeout=30,
            )
            return result.returncode == 0

        if "imdisk" in tool_name:
            drive = active.mount_point.rstrip("\\:")
            result = subprocess.run(
                [tool, "-d", "-m", f"{drive}:"],
                capture_output=True, text=True, timeout=30,
            )
            return result.returncode == 0

        # PowerShell fallback (VHD/VHDX/ISO only)
        ps = f"Dismount-DiskImage -ImagePath '{active.image_path}'"
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0

    def _find_win_tool(self) -> str | None:
        tools_dir = Path(__file__).resolve().parents[3] / "tools"
        for name in _WIN_TOOLS:
            candidate = tools_dir / name
            if candidate.exists():
                return str(candidate)
            found = shutil.which(name)
            if found:
                return found
        return None

    def _free_drive_letter(self) -> str | None:
        """Find the first free drive letter on Windows."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "[char[]](67..90) | Where-Object { -not (Test-Path \"$_:\") } | Select-Object -First 1"],
                capture_output=True, text=True, timeout=10,
            )
            letter = result.stdout.strip()
            return letter if letter else None
        except Exception:
            return "Z"

    def _aim_find_drive(self, image: Path) -> str:
        """Find the drive letter AIM assigned to a mounted image."""
        try:
            result = subprocess.run(
                ["aim_cli.exe", "--list"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if image.name.lower() in line.lower():
                    parts = line.split()
                    for p in parts:
                        if len(p) == 1 and p.isalpha():
                            return p.upper()
        except Exception:
            pass
        return "Z"

    # ── Linux ─────────────────────────────────────────────────────────────────

    def _mount_linux(
        self,
        image: Path,
        mount_id: str,
        mount_point: str | Path | None,
        partition_index: int,
    ) -> MountResult:
        mp = Path(mount_point) if mount_point else Path(f"/mnt/forgelens_{mount_id}")
        mp.mkdir(parents=True, exist_ok=True)

        # Calculate partition offset using fdisk
        offset = self._linux_partition_offset(image, partition_index)
        offset_arg = []
        if offset > 0:
            offset_arg = ["-o", str(offset)]

        # Setup loop device
        loop_result = subprocess.run(
            ["losetup", "--find", "--show", "--read-only"] + offset_arg + [str(image)],
            capture_output=True, text=True, timeout=15,
        )
        if loop_result.returncode != 0:
            # Try without offset (flat image)
            loop_result = subprocess.run(
                ["losetup", "--find", "--show", "--read-only", str(image)],
                capture_output=True, text=True, timeout=15,
            )
            if loop_result.returncode != 0:
                return MountResult(
                    success=False,
                    error=f"losetup failed: {loop_result.stderr.strip()[:200]}",
                )

        loop_dev = loop_result.stdout.strip()

        # Mount read-only
        mount_result = subprocess.run(
            ["mount", "-o", "ro,noexec,nosuid,nodev", loop_dev, str(mp)],
            capture_output=True, text=True, timeout=15,
        )
        if mount_result.returncode != 0:
            # Try with specific filesystem types
            for fstype in ["ntfs", "vfat", "ext4", "ext3", "xfs"]:
                r = subprocess.run(
                    ["mount", "-t", fstype, "-o", "ro,noexec,nosuid,nodev", loop_dev, str(mp)],
                    capture_output=True, text=True, timeout=15,
                )
                if r.returncode == 0:
                    break
            else:
                subprocess.run(["losetup", "-d", loop_dev], capture_output=True, timeout=10)
                return MountResult(
                    success=False,
                    error=f"mount failed: {mount_result.stderr.strip()[:200]}",
                )

        return MountResult(
            success=True, mount_id=mount_id,
            image_path=str(image), mount_point=str(mp),
            tool_used=f"losetup+mount ({loop_dev})",
        )

    def _unmount_linux(self, active: ActiveMount) -> bool:
        try:
            subprocess.run(["umount", active.mount_point], capture_output=True, timeout=15)
            # Detach loop device
            result = subprocess.run(
                ["losetup", "--associated", active.image_path],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                loop_dev = line.split(":")[0]
                subprocess.run(["losetup", "-d", loop_dev], capture_output=True, timeout=10)
            # Remove mount point if we created it
            mp = Path(active.mount_point)
            if mp.exists() and "forgelens_" in mp.name:
                mp.rmdir()
            return True
        except Exception as exc:
            logger.error("Linux unmount error: {}", exc)
            return False

    def _linux_partition_offset(self, image: Path, partition_index: int) -> int:
        """Get byte offset of a partition using fdisk -l."""
        if partition_index == 0:
            return 0
        try:
            result = subprocess.run(
                ["fdisk", "-l", "-u=sectors", str(image)],
                capture_output=True, text=True, timeout=10,
            )
            count = 0
            for line in result.stdout.splitlines():
                if str(image) in line or "Device" in line:
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[0].startswith(str(image)):
                    if count == partition_index:
                        try:
                            return int(parts[1]) * 512
                        except (ValueError, IndexError):
                            pass
                    count += 1
        except Exception:
            pass
        return 0

    # ── macOS ─────────────────────────────────────────────────────────────────

    def _mount_macos(
        self,
        image: Path,
        mount_id: str,
        mount_point: str | Path | None,
    ) -> MountResult:
        cmd = [
            "hdiutil", "attach",
            str(image),
            "-readonly",
            "-nobrowse",       # don't show in Finder
            "-noautoopen",
        ]
        if mount_point:
            cmd += ["-mountpoint", str(mount_point)]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return MountResult(
                success=False,
                error=f"hdiutil attach failed: {result.stderr.strip()[:200]}",
            )

        # Parse mount point from output
        mp = ""
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[-1].startswith("/"):
                mp = parts[-1].strip()

        return MountResult(
            success=True, mount_id=mount_id,
            image_path=str(image), mount_point=mp or str(mount_point or "/Volumes/forgelens"),
            tool_used="hdiutil",
        )

    def _unmount_macos(self, active: ActiveMount) -> bool:
        result = subprocess.run(
            ["hdiutil", "detach", active.mount_point, "-force"],
            capture_output=True, text=True, timeout=30,
        )
        return result.returncode == 0

    # ── State persistence ─────────────────────────────────────────────────────

    def _load_state(self) -> dict[str, ActiveMount]:
        if not _MOUNT_STATE_FILE.exists():
            return {}
        try:
            data = json.loads(_MOUNT_STATE_FILE.read_text(encoding="utf-8"))
            return {k: ActiveMount(**v) for k, v in data.items()}
        except Exception:
            return {}

    def _save_state(self) -> None:
        try:
            _MOUNT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            data = {k: vars(v) for k, v in self._active.items()}
            _MOUNT_STATE_FILE.write_text(
                json.dumps(data, indent=2, default=str), encoding="utf-8"
            )
        except Exception as exc:
            logger.debug("Mount state save error: {}", exc)

    # ── Chain of custody ──────────────────────────────────────────────────────

    def _record_coc(
        self, case_id: str, evidence_id: str,
        actor: str, event_type: str, notes: str,
    ) -> None:
        if not case_id or not evidence_id:
            return
        try:
            from core.chain_of_custody.evidence_manager import EvidenceManager
            EvidenceManager().record_custody_event(
                evidence_id, case_id, event_type, actor, notes
            )
        except Exception as exc:
            logger.debug("CoC record error: {}", exc)


# ── Tool install helper ────────────────────────────────────────────────────────

def get_windows_mount_tool_status() -> dict[str, str]:
    """Return availability status of each open-source Windows mount tool."""
    tools_dir = Path(__file__).resolve().parents[3] / "tools"
    status = {}
    for name in _WIN_TOOLS:
        if (tools_dir / name).exists() or shutil.which(name):
            status[name] = "available"
        else:
            status[name] = "missing"
    return status
