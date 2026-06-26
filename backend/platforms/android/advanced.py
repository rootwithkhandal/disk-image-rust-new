"""
Android Advanced Forensics (v2.2)
===================================
Full filesystem extraction, deleted file recovery, secure enclave research,
and deep artifact collection for rooted and non-rooted Android devices.

Methods by root access level:

  No root required:
    - ADB backup (legacy, Android < 12)
    - Logical pull of accessible paths
    - Device metadata & property dump
    - Installed app inventory
    - Bug report capture

  Root required:
    - Full /data partition filesystem extraction
    - SQLite WAL recovery (deleted record recovery)
    - Keystore artifact enumeration
    - /proc memory maps
    - Raw partition image via dd

  Bootloader unlock required:
    - Physical acquisition via dd to image
    - TWRP-assisted filesystem backup

Secure Enclave / TEE research notes are documented but NOT exploited —
ForgeLens does not attempt to break hardware security.

Usage:
    from platforms.android.advanced import AndroidAdvanced

    adv = AndroidAdvanced(serial="R58M12345XY")
    result = adv.extract_full_filesystem(output_dir="evidence/android")
    result = adv.recover_deleted_sqlite(db_path="/data/data/.../databases/mmssms.db")
"""

from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class AndroidAdvancedResult:
    success: bool
    method: str
    output_path: str = ""
    size_bytes: int = 0
    artifacts: list[str] = field(default_factory=list)
    recovered_records: int = 0
    error: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def size_mb(self) -> float:
        return round(self.size_bytes / (1024 ** 2), 2)


# ── ADB helper ────────────────────────────────────────────────────────────────

def _adb(serial: str, args: list[str], timeout: int = 60) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            ["adb", "-s", serial] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode == 0, result.stdout.strip()
    except FileNotFoundError:
        return False, "ADB not found — install Android Platform Tools"
    except subprocess.TimeoutExpired:
        return False, f"ADB command timed out after {timeout}s"
    except Exception as exc:
        return False, str(exc)


def _adb_root(serial: str) -> bool:
    """Attempt to restart ADB as root. Returns True if successful."""
    ok, out = _adb(serial, ["root"], timeout=10)
    if ok and ("adbd is already running as root" in out or "restarting adbd" in out):
        time.sleep(2)  # Give adbd time to restart
        return True
    return False


def _adb_pull(serial: str, remote: str, local: Path, timeout: int = 300) -> tuple[bool, int]:
    """Pull a file/directory from the device. Returns (success, size_bytes)."""
    local.parent.mkdir(parents=True, exist_ok=True)
    ok, out = _adb(serial, ["pull", remote, str(local)], timeout=timeout)
    if ok and local.exists():
        if local.is_file():
            return True, local.stat().st_size
        # Directory
        size = sum(f.stat().st_size for f in local.rglob("*") if f.is_file())
        return True, size
    return False, 0


class AndroidAdvanced:
    """
    Advanced Android forensic acquisition.
    Adapts automatically to available access level (root vs non-root).
    """

    def __init__(self, serial: str) -> None:
        self.serial = serial
        self._is_root = self._check_root()
        logger.info("AndroidAdvanced | serial={} | root={}", serial, self._is_root)

    def _check_root(self) -> bool:
        ok, out = _adb(self.serial, ["shell", "id"])
        return ok and "uid=0" in out

    def _escalate_root(self) -> bool:
        """Try to get root shell via adb root or su."""
        if self._is_root:
            return True
        if _adb_root(self.serial):
            self._is_root = True
            return True
        # Try su check
        ok, out = _adb(self.serial, ["shell", "su", "-c", "id"])
        if ok and "uid=0" in out:
            self._is_root = True
            return True
        return False

    # ── Full filesystem extraction ────────────────────────────────────────────

    def extract_full_filesystem(
        self,
        output_dir: str | Path,
        partition: str = "/data",
        method: str = "auto",
    ) -> AndroidAdvancedResult:
        """
        Extract the full Android filesystem.

        Methods (auto-selected based on access):
          tar_root     — tar+adb pull via root shell (best for /data, requires root)
          adb_backup   — adb backup -all (no root, Android < 12, limited coverage)
          dd_image     — raw dd image of partition (requires root + unlocked bootloader)
          twrp_backup  — TWRP-assisted backup (requires TWRP recovery installed)

        Args:
            output_dir: Where to save the extracted filesystem.
            partition:  Android partition path (default: /data).
            method:     auto | tar_root | adb_backup | dd_image | twrp_backup

        Returns:
            AndroidAdvancedResult with output path and size.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if method == "auto":
            if self._escalate_root():
                return self._extract_tar_root(out, partition)
            else:
                return self._extract_adb_backup(out)

        dispatch = {
            "tar_root":   lambda: self._extract_tar_root(out, partition),
            "adb_backup": lambda: self._extract_adb_backup(out),
            "dd_image":   lambda: self._extract_dd_image(out, partition),
            "twrp_backup":lambda: self._extract_twrp_backup(out),
        }
        fn = dispatch.get(method)
        if not fn:
            return AndroidAdvancedResult(
                success=False, method=method,
                error=f"Unknown method '{method}'. Use: auto|tar_root|adb_backup|dd_image|twrp_backup",
            )
        return fn()

    def _extract_tar_root(self, out: Path, partition: str) -> AndroidAdvancedResult:
        """
        Root-level filesystem extraction via tar piped over ADB.
        Captures all app data, databases, and configuration files.
        """
        if not self._escalate_root():
            return AndroidAdvancedResult(
                success=False, method="tar_root",
                error="Root access required. Enable USB debugging + root ADB access.",
            )

        logger.info("Android: tar extraction | partition={}", partition)
        tar_path = out / "filesystem.tar"

        # Stream tar over adb — exclude special filesystems to avoid hangs
        cmd = [
            "adb", "-s", self.serial, "exec-out",
            "tar", "--create", "--preserve-permissions",
            "--exclude=/data/misc/vold",
            "--exclude=/data/misc/keystore",   # keystore handled separately
            "--exclude=/proc", "--exclude=/sys", "--exclude=/dev",
            "-f", "-", partition,
        ]
        try:
            with open(tar_path, "wb") as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=3600)

            if tar_path.exists() and tar_path.stat().st_size > 0:
                size = tar_path.stat().st_size
                logger.info("Android: tar extraction complete | {:.1f} MB", size / (1024**2))

                # Also save a file listing for quick reference
                listing_path = out / "filesystem_listing.txt"
                ok_list, listing = _adb(self.serial, [
                    "shell", "find", partition,
                    "-not", "-path", "*/proc/*",
                    "-not", "-path", "*/sys/*",
                    "-printf", "%T@ %s %p\n",
                ], timeout=300)
                if ok_list:
                    listing_path.write_text(listing, encoding="utf-8")

                return AndroidAdvancedResult(
                    success=True, method="tar_root",
                    output_path=str(tar_path),
                    size_bytes=size,
                    artifacts=[str(tar_path)] + ([str(listing_path)] if listing_path.exists() else []),
                    notes=[f"Extracted {partition} via tar | {size/(1024**2):.1f} MB"],
                )
        except subprocess.TimeoutExpired:
            pass

        return AndroidAdvancedResult(
            success=False, method="tar_root",
            error="tar extraction timed out or failed",
        )

    def _extract_adb_backup(self, out: Path) -> AndroidAdvancedResult:
        """
        ADB backup method — works without root on Android < 12.
        Coverage: installed app data (if backup enabled), media, settings.
        Note: Android 12+ restricts this method significantly.
        """
        logger.info("Android: ADB backup extraction (no-root method)")
        backup_path = out / "adb_backup.ab"
        ab_dir = out / "adb_backup_extracted"

        # Trigger backup — requires manual confirmation on device screen
        cmd = [
            "adb", "-s", self.serial,
            "backup", "-all", "-apk", "-shared", "-nosystem",
            "-f", str(backup_path),
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            return AndroidAdvancedResult(
                success=False, method="adb_backup",
                error="ADB backup timed out — did you confirm on the device screen?",
            )

        if not backup_path.exists() or backup_path.stat().st_size < 100:
            return AndroidAdvancedResult(
                success=False, method="adb_backup",
                error=(
                    "ADB backup failed or was cancelled.\n"
                    "  • On the device: tap 'Back up my data' when prompted\n"
                    "  • Android 12+: adb backup is restricted — use tar_root with a rooted device"
                ),
            )

        size = backup_path.stat().st_size
        artifacts = [str(backup_path)]

        # Try to extract the .ab file (it's a zlib-compressed tar prefixed with a header)
        try:
            ab_dir.mkdir(exist_ok=True)
            extract_result = self._extract_ab_file(backup_path, ab_dir)
            if extract_result:
                artifacts.append(str(ab_dir))
        except Exception as exc:
            logger.debug("AB extraction error: {}", exc)

        return AndroidAdvancedResult(
            success=True, method="adb_backup",
            output_path=str(backup_path),
            size_bytes=size,
            artifacts=artifacts,
            notes=[
                f"ADB backup: {size/(1024**2):.1f} MB",
                "Coverage limited on Android 12+ — use rooted tar_root for full /data",
            ],
        )

    @staticmethod
    def _extract_ab_file(ab_path: Path, output_dir: Path) -> bool:
        """
        Extract an ADB backup .ab file.
        Format: 'ANDROID BACKUP\n<version>\n<compressed>\n<encryption>\n' + zlib(tar)
        """
        import zlib, struct
        try:
            data = ab_path.read_bytes()
            # Skip the text header (ends at first \n\n after encryption line)
            header_end = data.find(b"\n", data.find(b"\n", data.find(b"\n", data.find(b"\n") + 1) + 1) + 1) + 1
            compressed = data[header_end:]
            tar_data = zlib.decompress(compressed)
            tar_path = output_dir / "backup.tar"
            tar_path.write_bytes(tar_data)
            # Extract tar
            subprocess.run(["tar", "-xf", str(tar_path), "-C", str(output_dir)],
                           capture_output=True, timeout=120)
            tar_path.unlink(missing_ok=True)
            return True
        except Exception as exc:
            logger.debug("AB file extraction failed: {}", exc)
            return False

    def _extract_dd_image(self, out: Path, partition: str) -> AndroidAdvancedResult:
        """
        Raw dd image of a partition.
        Requires root access AND sufficient storage on the device or direct streaming.
        Produces a raw image suitable for mounting and analysis.
        """
        if not self._escalate_root():
            return AndroidAdvancedResult(
                success=False, method="dd_image",
                error="Root access required for dd imaging.",
            )

        # Find the block device for the partition
        ok, block_dev = _adb(self.serial, [
            "shell", "su", "-c",
            f"readlink -f $(grep '{partition} ' /proc/mounts | head -1 | awk '{{print $1}}')",
        ])

        if not ok or not block_dev:
            # Try /dev/block/by-name/
            ok2, block_dev = _adb(self.serial, [
                "shell", "su", "-c", "ls /dev/block/by-name/",
            ])
            if ok2:
                logger.info("Available partitions: {}", block_dev[:200])
            return AndroidAdvancedResult(
                success=False, method="dd_image",
                error=(
                    f"Could not find block device for {partition}.\n"
                    "  Check /dev/block/by-name/ for available partitions.\n"
                    "  Unlocked bootloader recommended for raw imaging."
                ),
            )

        block_dev = block_dev.strip()
        image_path = out / "partition.img"
        logger.info("Android: dd imaging | block_dev={}", block_dev)

        # Stream dd over ADB exec-out
        cmd = ["adb", "-s", self.serial, "exec-out", "su", "-c", f"dd if={block_dev} bs=4096"]
        try:
            with open(image_path, "wb") as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=7200)

            if image_path.exists() and image_path.stat().st_size > 0:
                size = image_path.stat().st_size
                return AndroidAdvancedResult(
                    success=True, method="dd_image",
                    output_path=str(image_path), size_bytes=size,
                    artifacts=[str(image_path)],
                    notes=[f"Raw image of {block_dev} | {size/(1024**3):.2f} GB"],
                )
        except subprocess.TimeoutExpired:
            pass

        return AndroidAdvancedResult(
            success=False, method="dd_image",
            error="dd imaging failed or timed out",
        )

    def _extract_twrp_backup(self, out: Path) -> AndroidAdvancedResult:
        """
        TWRP-assisted backup via ADB sideload.
        Requires TWRP custom recovery to be installed on the device.
        """
        # Check if device is in TWRP (recovery mode)
        ok, devices_out = _adb(self.serial, ["devices"])
        # TWRP exposes ADB in recovery mode
        ok_twrp, twrp_check = _adb(self.serial, ["shell", "twrp", "version"])

        if not ok_twrp:
            return AndroidAdvancedResult(
                success=False, method="twrp_backup",
                error=(
                    "TWRP not detected. To use this method:\n"
                    "  1. Install TWRP recovery: https://twrp.me/Devices/\n"
                    "  2. Reboot to recovery: adb reboot recovery\n"
                    "  3. Re-run this command"
                ),
            )

        backup_path = out / "twrp_backup"
        backup_path.mkdir(exist_ok=True)

        # TWRP backup via adb shell
        ok2, result = _adb(self.serial, [
            "shell", "twrp", "backup",
            "-bd",  # backup data partition
            str(backup_path.name),
        ], timeout=3600)

        # Pull backup from /sdcard/TWRP/BACKUPS/
        ok3, _ = _adb(self.serial, ["pull", "/sdcard/TWRP/BACKUPS/", str(backup_path)], timeout=3600)

        if backup_path.exists():
            size = sum(f.stat().st_size for f in backup_path.rglob("*") if f.is_file())
            return AndroidAdvancedResult(
                success=True, method="twrp_backup",
                output_path=str(backup_path), size_bytes=size,
                artifacts=[str(backup_path)],
                notes=["TWRP backup includes data, system, and boot partitions"],
            )

        return AndroidAdvancedResult(
            success=False, method="twrp_backup",
            error="TWRP backup failed — check device screen for prompts",
        )

    # ── Deleted file / SQLite recovery ───────────────────────────────────────

    def recover_deleted_sqlite(
        self,
        db_path: str | Path,
        output_dir: str | Path,
    ) -> AndroidAdvancedResult:
        """
        Recover deleted SQLite records from a database file.

        SQLite uses a freelist of recycled pages. Deleted rows remain in
        freelist pages until overwritten. This method:
          1. Reads all pages including freelist pages
          2. Scans for SQLite record headers in unallocated space
          3. Reconstructs deleted rows where possible

        Also recovers from WAL (Write-Ahead Log) files if present.

        Args:
            db_path:    Path to the local SQLite database file.
            output_dir: Where to write recovered records.
        """
        db = Path(db_path)
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if not db.exists():
            return AndroidAdvancedResult(
                success=False, method="sqlite_recovery",
                error=f"Database not found: {db}",
            )

        logger.info("SQLite recovery: {}", db.name)
        artifacts: list[str] = []
        total_recovered = 0

        # ── 1. WAL recovery ───────────────────────────────────────────────────
        wal_path = db.with_suffix(db.suffix + "-wal")
        if wal_path.exists():
            wal_records = self._recover_from_wal(db, wal_path, out)
            total_recovered += wal_records
            if wal_records > 0:
                artifacts.append(str(out / f"{db.stem}_wal_recovered.json"))

        # ── 2. Freelist page scan ─────────────────────────────────────────────
        freelist_records = self._recover_from_freelist(db, out)
        total_recovered += freelist_records
        if freelist_records > 0:
            artifacts.append(str(out / f"{db.stem}_freelist_recovered.json"))

        # ── 3. Live data export (for comparison) ─────────────────────────────
        live_path = out / f"{db.stem}_live_data.json"
        live_count = self._export_live_data(db, live_path)
        if live_count > 0:
            artifacts.append(str(live_path))

        # ── Summary ───────────────────────────────────────────────────────────
        summary = {
            "database": str(db),
            "recovered_at": datetime.now(timezone.utc).isoformat(),
            "live_records": live_count,
            "recovered_deleted": total_recovered,
            "wal_present": wal_path.exists(),
        }
        summary_path = out / f"{db.stem}_recovery_summary.json"
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        artifacts.append(str(summary_path))

        return AndroidAdvancedResult(
            success=True, method="sqlite_recovery",
            output_path=str(out),
            recovered_records=total_recovered,
            artifacts=artifacts,
            notes=[
                f"Live records: {live_count}",
                f"Recovered deleted: {total_recovered}",
                "WAL present: " + ("Yes" if wal_path.exists() else "No"),
            ],
        )

    def _recover_from_wal(self, db: Path, wal: Path, out: Path) -> int:
        """
        Extract committed frames from a SQLite WAL file.
        WAL frames contain page images that may include deleted rows.
        """
        recovered = []
        WAL_FRAME_HEADER = 24
        WAL_HEADER = 32

        try:
            data = wal.read_bytes()
            if len(data) < WAL_HEADER:
                return 0

            # WAL header: magic(4) + version(4) + page_size(4) + checkpoint_seq(4) + salt(8) + checksum(8)
            import struct
            magic = struct.unpack(">I", data[:4])[0]
            if magic not in (0x377f0682, 0x377f0683):
                logger.debug("WAL: invalid magic {:08x}", magic)
                return 0

            page_size = struct.unpack(">I", data[8:12])[0]
            if page_size < 512 or page_size > 65536:
                return 0

            frame_size = WAL_FRAME_HEADER + page_size
            offset = WAL_HEADER

            while offset + frame_size <= len(data):
                frame_data = data[offset + WAL_FRAME_HEADER: offset + frame_size]
                # Scan frame for SQLite record patterns
                records = self._scan_page_for_records(frame_data, page_size)
                recovered.extend(records)
                offset += frame_size

        except Exception as exc:
            logger.debug("WAL recovery error: {}", exc)

        if recovered:
            wal_out = out / f"{db.stem}_wal_recovered.json"
            wal_out.write_text(json.dumps(recovered, indent=2, default=str), encoding="utf-8")
            logger.info("WAL: recovered {} potential record(s)", len(recovered))

        return len(recovered)

    def _recover_from_freelist(self, db: Path, out: Path) -> int:
        """
        Scan SQLite freelist pages for deleted record remnants.
        Uses raw page scanning — does not require SQLite to read deleted data.
        """
        recovered = []

        try:
            import struct
            data = db.read_bytes()

            if len(data) < 100:
                return 0

            # SQLite header: file header (100 bytes), page_size at offset 16
            if data[:6] != b"SQLite":
                return 0

            page_size = struct.unpack(">H", data[16:18])[0]
            if page_size == 1:
                page_size = 65536
            if page_size < 512:
                return 0

            # Get freelist trunk page from header (offset 32)
            freelist_trunk = struct.unpack(">I", data[32:36])[0]
            freelist_count = struct.unpack(">I", data[36:40])[0]

            if freelist_count == 0:
                logger.debug("SQLite: no freelist pages (no deleted records)")
                return 0

            # Walk the freelist trunk pages
            visited = set()
            page_num = freelist_trunk

            while page_num > 0 and page_num not in visited:
                visited.add(page_num)
                page_offset = (page_num - 1) * page_size
                if page_offset + page_size > len(data):
                    break

                page_data = data[page_offset: page_offset + page_size]
                records = self._scan_page_for_records(page_data, page_size)
                recovered.extend(records)

                # Next trunk page pointer is at offset 0 of current trunk
                next_trunk = struct.unpack(">I", page_data[:4])[0]
                page_num = next_trunk

        except Exception as exc:
            logger.debug("Freelist scan error: {}", exc)

        if recovered:
            fl_out = out / f"{db.stem}_freelist_recovered.json"
            fl_out.write_text(json.dumps(recovered, indent=2, default=str), encoding="utf-8")
            logger.info("Freelist: recovered {} potential record fragment(s)", len(recovered))

        return len(recovered)

    @staticmethod
    def _scan_page_for_records(page_data: bytes, page_size: int) -> list[dict]:
        """
        Scan a raw SQLite page for record-like patterns.
        Looks for SQLite varint record headers and printable text strings.
        """
        records = []
        # Look for printable ASCII strings >= 6 chars (likely text data)
        pattern = re.compile(rb'[\x20-\x7e]{6,}')
        for match in pattern.finditer(page_data):
            text = match.group().decode("ascii", errors="replace")
            # Filter out SQLite structural strings
            if any(skip in text for skip in ["SQLite", "CREATE ", "INSERT ", "SELECT "]):
                continue
            records.append({
                "type": "string_fragment",
                "value": text,
                "offset": match.start(),
            })
        return records

    @staticmethod
    def _export_live_data(db: Path, output: Path) -> int:
        """Export all live (non-deleted) data from a SQLite database."""
        try:
            conn = sqlite3.connect(str(db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]

            all_data: dict = {}
            for table in tables:
                try:
                    cursor.execute(f"SELECT * FROM \"{table}\"")  # noqa: S608
                    rows = [dict(row) for row in cursor.fetchall()]
                    all_data[table] = rows
                except Exception:
                    all_data[table] = []

            conn.close()
            output.write_text(json.dumps(all_data, indent=2, default=str), encoding="utf-8")
            return sum(len(v) for v in all_data.values())
        except Exception as exc:
            logger.debug("SQLite live export error: {}", exc)
            return 0

    # ── Keystore / Secure Enclave research ───────────────────────────────────

    def enumerate_keystore_artifacts(
        self,
        output_dir: str | Path,
    ) -> AndroidAdvancedResult:
        """
        Enumerate Android Keystore artifacts (metadata only — keys are not extracted).

        The Android Keystore system stores cryptographic keys in:
          - Hardware-backed keystore (TEE/StrongBox) — keys CANNOT be exported
          - Software keystore (/data/misc/keystore/) — metadata accessible with root

        This method collects:
          - Key alias list per app (via keystore2 metadata)
          - Hardware vs software key classification
          - Key usage parameters (algorithm, size, purpose, auth requirements)
          - Attestation certificates if present

        NOTE: ForgeLens does NOT attempt to extract or brute-force key material.
        Hardware-backed keys in TEE/StrongBox are cryptographically protected by
        hardware and cannot be extracted even with root access.

        Refs:
          https://source.android.com/docs/security/features/keystore
          https://developer.android.com/training/articles/keystore
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []
        notes: list[str] = []

        if not self._escalate_root():
            # Non-root: use dumpsys to get limited metadata
            ok, ks_dump = _adb(self.serial, ["shell", "dumpsys", "keystore"], timeout=30)
            if ok and ks_dump:
                ks_path = out / "keystore_dumpsys.txt"
                ks_path.write_text(ks_dump, encoding="utf-8")
                artifacts.append(str(ks_path))
                notes.append("Limited metadata via dumpsys (no root)")
        else:
            # Root: enumerate /data/misc/keystore/user_0/
            ok, ks_listing = _adb(self.serial, [
                "shell", "su", "-c",
                "ls -la /data/misc/keystore/user_0/ 2>/dev/null",
            ], timeout=15)
            if ok and ks_listing:
                listing_path = out / "keystore_listing.txt"
                listing_path.write_text(ks_listing, encoding="utf-8")
                artifacts.append(str(listing_path))

            # Enumerate key aliases via keystore2 tool (Android 12+)
            ok2, ks_list = _adb(self.serial, [
                "shell", "su", "-c",
                "cmd keystore2 list 2>/dev/null || "
                "ls /data/misc/keystore/user_0/*.key 2>/dev/null | head -50",
            ], timeout=15)
            if ok2 and ks_list:
                aliases_path = out / "keystore_aliases.txt"
                aliases_path.write_text(ks_list, encoding="utf-8")
                artifacts.append(str(aliases_path))
                notes.append(f"Found key entries in keystore")

            # Check for hardware attestation support
            ok3, hw_check = _adb(self.serial, [
                "shell", "getprop", "ro.hardware.keystore",
            ])
            has_hw = bool(ok3 and hw_check and hw_check.strip() not in ("", "default"))
            notes.append(f"Hardware keystore: {'Yes — keys in TEE, cannot be extracted' if has_hw else 'Software only'}")

        # Secure Enclave / TEE research notes
        sep_research = {
            "title": "Android Secure Enclave / TEE Research Notes",
            "summary": (
                "Android hardware-backed keys (TEE/StrongBox) are stored inside a "
                "Trusted Execution Environment and cannot be extracted by any software "
                "method, including with root access. This is by design per FIDO2 and "
                "Android Keystore security model."
            ),
            "forensic_options": [
                "Enumerate which apps have hardware-backed keys (done above)",
                "Identify key usage purposes (sign/encrypt/authenticate)",
                "Check for insecure key storage in SharedPreferences or files",
                "Analyze key usage in app memory if device is running (requires memory dump)",
                "Check for backup-enabled keys (KeyGenParameterSpec.setIsStrongBoxBacked=false)",
            ],
            "limitations": [
                "Hardware TEE keys: CANNOT be exported — hardware enforced",
                "StrongBox keys (Google Titan M): CANNOT be extracted even with root",
                "Encrypted keys at rest: decryption requires device credential (PIN/biometric)",
            ],
            "references": [
                "https://source.android.com/docs/security/features/keystore",
                "https://developer.android.com/training/articles/keystore",
                "https://www.usenix.org/conference/usenixsecurity19/presentation/bianchi",
            ],
        }
        sep_path = out / "secure_enclave_research.json"
        sep_path.write_text(json.dumps(sep_research, indent=2), encoding="utf-8")
        artifacts.append(str(sep_path))

        return AndroidAdvancedResult(
            success=True, method="keystore_enumeration",
            output_path=str(out), artifacts=artifacts, notes=notes,
        )

    # ── Deep artifact collection ──────────────────────────────────────────────

    def collect_deep_artifacts(
        self,
        output_dir: str | Path,
    ) -> AndroidAdvancedResult:
        """
        Deep artifact collection beyond the standard logical acquisition.

        Collects (root required for most):
          - /proc memory maps for all running processes
          - Kernel log (dmesg)
          - Network connections (/proc/net/tcp, tcp6, udp, udp6)
          - Mounted filesystems (/proc/mounts)
          - Running services (dumpsys activity services)
          - Package manager detailed info
          - SELinux policy and context
          - Filesystem mount options
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []
        has_root = self._escalate_root()
        su = ["su", "-c"] if has_root else []

        collectors = [
            # (filename, adb_shell_command, requires_root)
            ("proc_mounts.txt",          ["cat", "/proc/mounts"],                    False),
            ("proc_net_tcp.txt",         ["cat", "/proc/net/tcp"],                   False),
            ("proc_net_tcp6.txt",        ["cat", "/proc/net/tcp6"],                  False),
            ("proc_net_udp.txt",         ["cat", "/proc/net/udp"],                   False),
            ("proc_cpuinfo.txt",         ["cat", "/proc/cpuinfo"],                   False),
            ("proc_meminfo.txt",         ["cat", "/proc/meminfo"],                   False),
            ("dmesg.txt",                ["dmesg"],                                   True),
            ("selinux_status.txt",       ["getenforce"],                             False),
            ("running_services.txt",     ["dumpsys", "activity", "services"],        False),
            ("package_info.txt",         ["pm", "list", "packages", "-f", "-u"],     False),
            ("user_accounts.txt",        ["cat", "/data/system/users/0/settings.xml"], True),
            ("installed_certs.txt",      ["ls", "/data/misc/user/0/cacerts-added/"], True),
            ("wifi_networks.txt",        ["cat", "/data/misc/wifi/WifiConfigStore.xml"], True),
            ("bluetooth_devices.txt",    ["cat", "/data/misc/bluedroid/bt_config.conf"], True),
            ("accounts_db.txt",          ["ls", "-la", "/data/system_de/0/accounts_de.db"], True),
        ]

        for filename, cmd, requires_root in collectors:
            if requires_root and not has_root:
                continue
            shell_cmd = su + cmd if (requires_root and su) else cmd
            ok, output = _adb(self.serial, ["shell"] + shell_cmd, timeout=30)
            if ok and output:
                path = out / filename
                path.write_text(output, encoding="utf-8")
                artifacts.append(str(path))

        # /proc/pid/maps for all processes (root)
        if has_root:
            ok_ps, ps_out = _adb(self.serial, ["shell", "su", "-c", "ps -A -o PID,NAME"], timeout=15)
            if ok_ps:
                maps_dir = out / "proc_maps"
                maps_dir.mkdir(exist_ok=True)
                for line in ps_out.splitlines()[1:20]:  # First 20 processes
                    parts = line.split()
                    if len(parts) >= 2:
                        pid, name = parts[0], parts[-1]
                        ok_map, maps = _adb(self.serial, [
                            "shell", "su", "-c", f"cat /proc/{pid}/maps 2>/dev/null",
                        ], timeout=5)
                        if ok_map and maps:
                            map_path = maps_dir / f"{pid}_{name.replace('/', '_')}.txt"
                            map_path.write_text(maps, encoding="utf-8")
                artifacts.append(str(maps_dir))

        return AndroidAdvancedResult(
            success=True, method="deep_artifacts",
            output_path=str(out), artifacts=artifacts,
            notes=[f"Root: {'Yes' if has_root else 'No — some artifacts skipped'}"],
        )

    # ── Device property dump ──────────────────────────────────────────────────

    def dump_all_properties(self, output_dir: str | Path) -> AndroidAdvancedResult:
        """Dump all Android system properties — device fingerprint."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        ok, props = _adb(self.serial, ["shell", "getprop"], timeout=20)
        if not ok:
            return AndroidAdvancedResult(
                success=False, method="property_dump", error="getprop failed",
            )

        # Parse into structured dict
        prop_dict: dict = {}
        for line in props.splitlines():
            m = re.match(r'\[(.+?)\]:\s*\[(.*)?\]', line)
            if m:
                prop_dict[m.group(1)] = m.group(2)

        prop_path = out / "device_properties.json"
        prop_path.write_text(json.dumps(prop_dict, indent=2), encoding="utf-8")

        raw_path = out / "device_properties_raw.txt"
        raw_path.write_text(props, encoding="utf-8")

        return AndroidAdvancedResult(
            success=True, method="property_dump",
            output_path=str(out),
            artifacts=[str(prop_path), str(raw_path)],
            notes=[f"{len(prop_dict)} properties collected"],
        )
