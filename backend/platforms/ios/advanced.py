"""
iOS Advanced Forensics (v2.2)
==============================
Advanced filesystem extraction, keybag research, SEP documentation,
and deep artifact collection for iOS devices.

Access levels and methods:

  No jailbreak required (paired device):
    - Full encrypted iTunes backup (idevicebackup2)
    - AFC media partition access
    - Device metadata, crash logs, syslog
    - Paired device filesystem via pymobiledevice3

  Jailbreak required:
    - Full filesystem extraction via AFC2 or SSH/tar
    - Keychain database access
    - Deleted file recovery from HFS+/APFS unallocated space
    - Live process memory maps

  Research documentation (no exploitation):
    - SEP (Secure Enclave Processor) architecture
    - Keybag structure and key class hierarchy
    - APFS encryption and EffaceableStorage
    - GrayKey / Cellebrite attack surface (defensive awareness)

Usage:
    from platforms.ios.advanced import IOSAdvanced

    adv = IOSAdvanced(udid="00008110-001234567890ABCD")
    result = adv.extract_full_filesystem(output_dir="evidence/ios")
    result = adv.extract_keychain(output_dir="evidence/ios")
    adv.document_sep_research(output_dir="evidence/ios")
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class IOSAdvancedResult:
    success: bool
    method: str
    output_path: str = ""
    size_bytes: int = 0
    artifacts: list[str] = field(default_factory=list)
    error: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def size_mb(self) -> float:
        return round(self.size_bytes / (1024 ** 2), 2)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _idevice(args: list[str], udid: str | None = None, timeout: int = 60) -> tuple[bool, str]:
    cmd = args[:]
    if udid:
        cmd = [cmd[0], "-u", udid] + cmd[1:]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except FileNotFoundError:
        return False, f"Tool not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {timeout}s"
    except Exception as exc:
        return False, str(exc)


def _pymobile(args: list[str], timeout: int = 60) -> tuple[bool, str]:
    """Run a pymobiledevice3 command."""
    try:
        result = subprocess.run(
            ["python", "-m", "pymobiledevice3"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode == 0, result.stdout.strip()
    except Exception as exc:
        return False, str(exc)


class IOSAdvanced:
    """
    Advanced iOS forensic acquisition.
    Adapts to available tools and device access level.
    """

    def __init__(self, udid: str) -> None:
        self.udid = udid
        self._libimobile = self._check_libimobile()
        self._pymobile = self._check_pymobile()
        self._is_jailbroken = self._check_jailbreak()
        logger.info(
            "IOSAdvanced | udid={} | libimobiledevice={} | pymobiledevice3={} | jailbroken={}",
            udid[:16], self._libimobile, self._pymobile, self._is_jailbroken,
        )

    def _check_libimobile(self) -> bool:
        ok, _ = _idevice(["ideviceinfo", "--version"])
        return ok

    def _check_pymobile(self) -> bool:
        ok, _ = _pymobile(["--version"])
        return ok

    def _check_jailbreak(self) -> bool:
        """Detect jailbreak via Cydia/Sileo app presence or common jailbreak paths."""
        if self._libimobile:
            ok, apps = _idevice(["ideviceinstaller", "-l"], udid=self.udid, timeout=20)
            if ok and any(jb in apps.lower() for jb in ["cydia", "sileo", "zebra"]):
                return True
        # Try AFC2 access (only available on jailbroken devices)
        ok2, _ = _idevice(["idevicecrashreport", "-l", "-d", "/var/root"], udid=self.udid, timeout=10)
        return ok2

    # ── Full filesystem extraction ────────────────────────────────────────────

    def extract_full_filesystem(
        self,
        output_dir: str | Path,
        method: str = "auto",
    ) -> IOSAdvancedResult:
        """
        Extract the full iOS filesystem.

        Methods:
          auto          — selects best available method
          itunes_backup — encrypted/unencrypted iTunes backup (no jailbreak)
          afc2          — jailbreak AFC2 full filesystem mount
          ssh_tar       — SSH + tar over jailbroken device
          pymobile_fs   — pymobiledevice3 filesystem service (paired, no jailbreak)
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if method == "auto":
            if self._is_jailbroken:
                return self._extract_afc2(out)
            elif self._pymobile:
                return self._extract_pymobile_fs(out)
            else:
                return self._extract_itunes_backup(out)

        dispatch = {
            "itunes_backup": lambda: self._extract_itunes_backup(out),
            "afc2":          lambda: self._extract_afc2(out),
            "ssh_tar":       lambda: self._extract_ssh_tar(out),
            "pymobile_fs":   lambda: self._extract_pymobile_fs(out),
        }
        fn = dispatch.get(method)
        if not fn:
            return IOSAdvancedResult(
                success=False, method=method,
                error=f"Unknown method. Use: auto|itunes_backup|afc2|ssh_tar|pymobile_fs",
            )
        return fn()

    def _extract_itunes_backup(self, out: Path) -> IOSAdvancedResult:
        """Full iTunes backup — works without jailbreak."""
        backup_dir = out / "itunes_backup"
        backup_dir.mkdir(exist_ok=True)

        if self._libimobile:
            ok, err = _idevice(
                ["idevicebackup2", "backup", "--full", str(backup_dir)],
                udid=self.udid, timeout=7200,
            )
        elif self._pymobile:
            ok, err = _pymobile([
                "backup2", "backup", "--full",
                "-u", self.udid, str(backup_dir),
            ], timeout=7200)
        else:
            return IOSAdvancedResult(
                success=False, method="itunes_backup",
                error="Neither libimobiledevice nor pymobiledevice3 is installed.",
            )

        if backup_dir.exists():
            size = sum(f.stat().st_size for f in backup_dir.rglob("*") if f.is_file())
            if size > 0:
                return IOSAdvancedResult(
                    success=True, method="itunes_backup",
                    output_path=str(backup_dir), size_bytes=size,
                    artifacts=[str(backup_dir)],
                    notes=[
                        f"iTunes backup: {size/(1024**2):.1f} MB",
                        "Encrypted backup preserves keychain data",
                        "Decrypt with: python forgelens.py mobile ios-decrypt",
                    ],
                )

        return IOSAdvancedResult(
            success=False, method="itunes_backup",
            error=f"Backup failed: {err[:200]}",
        )

    def _extract_afc2(self, out: Path) -> IOSAdvancedResult:
        """
        AFC2 full filesystem access — requires jailbreak.
        AFC2 service exposes / (root filesystem), unlike AFC which only exposes /var/mobile/Media.
        """
        if not self._is_jailbroken:
            return IOSAdvancedResult(
                success=False, method="afc2",
                error="AFC2 requires a jailbroken device.",
            )

        afc_dir = out / "filesystem_afc2"
        afc_dir.mkdir(exist_ok=True)

        # Try ifuse with AFC2
        mount_point = Path(tempfile.mkdtemp())
        try:
            # ifuse --afc2 mounts the full filesystem
            mount_result = subprocess.run(
                ["ifuse", "--udid", self.udid, "--afc2", str(mount_point)],
                capture_output=True, text=True, timeout=30,
            )

            if mount_result.returncode == 0:
                import shutil
                shutil.copytree(str(mount_point), str(afc_dir), dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("proc", "sys", "dev"))
                subprocess.run(["fusermount", "-u", str(mount_point)],
                                capture_output=True, timeout=10)
                size = sum(f.stat().st_size for f in afc_dir.rglob("*") if f.is_file())
                return IOSAdvancedResult(
                    success=True, method="afc2",
                    output_path=str(afc_dir), size_bytes=size,
                    artifacts=[str(afc_dir)],
                    notes=["Full filesystem via AFC2 (jailbreak)"],
                )
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.debug("AFC2 error: {}", exc)
        finally:
            import contextlib
            with contextlib.suppress(Exception):
                mount_point.rmdir()

        # Fallback: pymobiledevice3 filesystem service
        if self._pymobile:
            return self._extract_pymobile_fs(out, afc2=True)

        return IOSAdvancedResult(
            success=False, method="afc2",
            error="AFC2 extraction failed — ifuse not installed or device not responding",
        )

    def _extract_ssh_tar(self, out: Path) -> IOSAdvancedResult:
        """
        SSH + tar extraction from jailbroken device.
        Device must have OpenSSH installed (via Cydia/Sileo).
        Default jailbreak SSH credentials: root/alpine (CHANGE THESE).
        """
        if not self._is_jailbroken:
            return IOSAdvancedResult(
                success=False, method="ssh_tar",
                error="SSH extraction requires a jailbroken device with OpenSSH installed.",
            )

        # Get device IP from WiFi
        ok, ip = _idevice(["ideviceinfo", "-k", "WiFiAddress"], udid=self.udid)
        if not ok or not ip:
            return IOSAdvancedResult(
                success=False, method="ssh_tar",
                error="Could not get device WiFi IP. Ensure device is on same network as host.",
            )

        tar_path = out / "ios_filesystem.tar.gz"
        logger.info("iOS SSH tar: connecting to {}", ip)

        cmd = [
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            f"root@{ip}",
            "tar czf - --exclude=/proc --exclude=/sys --exclude=/dev /",
        ]
        try:
            with open(tar_path, "wb") as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=7200)

            if tar_path.exists() and tar_path.stat().st_size > 0:
                size = tar_path.stat().st_size
                return IOSAdvancedResult(
                    success=True, method="ssh_tar",
                    output_path=str(tar_path), size_bytes=size,
                    artifacts=[str(tar_path)],
                    notes=[
                        f"Full filesystem tar: {size/(1024**3):.2f} GB",
                        "Default SSH password is 'alpine' — change after forensic work",
                    ],
                )
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            return IOSAdvancedResult(
                success=False, method="ssh_tar",
                error="ssh not found — install OpenSSH client",
            )

        return IOSAdvancedResult(
            success=False, method="ssh_tar",
            error="SSH tar extraction failed",
        )

    def _extract_pymobile_fs(self, out: Path, afc2: bool = False) -> IOSAdvancedResult:
        """
        Filesystem extraction via pymobiledevice3 (no jailbreak for /var/mobile/Media).
        With jailbreak: can access full filesystem via developer disk image.
        """
        if not self._pymobile:
            return IOSAdvancedResult(
                success=False, method="pymobile_fs",
                error="pymobiledevice3 not installed — run: pip install pymobiledevice3",
            )

        fs_dir = out / "pymobile_filesystem"
        fs_dir.mkdir(exist_ok=True)

        # pymobiledevice3 afc pull / fs pull
        if afc2:
            ok, err = _pymobile([
                "afc", "pull", "-u", self.udid, "/", str(fs_dir),
            ], timeout=7200)
        else:
            ok, err = _pymobile([
                "afc", "pull", "-u", self.udid, "/var/mobile/Media", str(fs_dir),
            ], timeout=3600)

        if fs_dir.exists():
            size = sum(f.stat().st_size for f in fs_dir.rglob("*") if f.is_file())
            if size > 0:
                return IOSAdvancedResult(
                    success=True, method="pymobile_fs",
                    output_path=str(fs_dir), size_bytes=size,
                    artifacts=[str(fs_dir)],
                    notes=[
                        f"pymobiledevice3 pull: {size/(1024**2):.1f} MB",
                        "Coverage: /var/mobile/Media (no jailbreak)" if not afc2 else "Full filesystem (jailbreak)",
                    ],
                )

        return IOSAdvancedResult(
            success=False, method="pymobile_fs",
            error=f"pymobiledevice3 filesystem extraction failed: {err[:200]}",
        )

    # ── Keychain extraction ───────────────────────────────────────────────────

    def extract_keychain(self, output_dir: str | Path) -> IOSAdvancedResult:
        """
        Extract iOS keychain data.

        Access levels:
          Jailbroken:    Full keychain dump via keychain-dumper or Frida
          Non-jailbreak: Keychain items backed up in encrypted iTunes backup only

        The iOS keychain is encrypted with device-specific keys derived from
        the device passcode and hardware UID. Items have a 'kSecAttrAccessible'
        class that determines when they're accessible.

        Keychain data classes:
          WhenUnlocked           — accessible only when device is unlocked
          AfterFirstUnlock       — accessible after first unlock post-boot
          Always                 — accessible always (deprecated, insecure)
          WhenPasscodeSetThisDeviceOnly — requires passcode, not backed up
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        if not self._is_jailbroken:
            notes = [
                "Keychain extraction requires a jailbroken device OR an encrypted iTunes backup.",
                "For encrypted backup: enable encryption in iTunes/Finder, backup, then decrypt.",
                "Keychain items with kSecAttrSynchronizable=true sync to iCloud.",
            ]
            # Document what would be found in encrypted backup
            doc = {
                "method": "backup_keychain",
                "note": "Keychain is included in encrypted iTunes backup as Keychain-backup.plist",
                "decrypt_tool": "iphone-backup-decrypt (pip install iphone-backup-decrypt)",
                "accessible_without_jailbreak": [
                    "kSecAttrAccessible: WhenUnlocked (if device is unlocked during backup)",
                    "kSecAttrAccessible: AfterFirstUnlock",
                    "iCloud-synced items (kSecAttrSynchronizable=true)",
                ],
                "not_accessible": [
                    "kSecAttrAccessible: WhenPasscodeSetThisDeviceOnly",
                    "Hardware-bound keys (kSecAttrTokenIDSecureEnclave)",
                ],
            }
            doc_path = out / "keychain_access_info.json"
            doc_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            artifacts.append(str(doc_path))

            return IOSAdvancedResult(
                success=True, method="keychain_info",
                output_path=str(out), artifacts=artifacts, notes=notes,
            )

        # Jailbroken: try keychain-dumper
        ok, kc_dump = _idevice(["idevicedebug", "run", "com.ptoomey3.Keychain-Dumper"],
                                 udid=self.udid, timeout=30)

        # Try via pymobiledevice3
        if not ok and self._pymobile:
            ok, kc_dump = _pymobile([
                "developer", "shell", "-u", self.udid,
                "cat", "/var/Keychains/keychain-2.db",
            ], timeout=30)

        # Try direct AFC pull of keychain DB
        kc_paths = [
            "/var/Keychains/keychain-2.db",
            "/private/var/Keychains/keychain-2.db",
        ]
        for kc_path in kc_paths:
            ok2, _ = _idevice(
                ["ifuse", "--udid", self.udid, "--afc2"],
                timeout=10,
            )
            local_kc = out / "keychain-2.db"
            ok3, pull_out = _idevice(
                ["idevicecrashreport", kc_path, str(local_kc)],
                udid=self.udid, timeout=30,
            )
            if local_kc.exists() and local_kc.stat().st_size > 0:
                artifacts.append(str(local_kc))
                break

        return IOSAdvancedResult(
            success=len(artifacts) > 0, method="keychain_extraction",
            output_path=str(out), artifacts=artifacts,
            notes=["Jailbreak keychain extraction — review keychain-2.db with SQLite"],
        )

    # ── SEP Research Documentation ────────────────────────────────────────────

    def document_sep_research(self, output_dir: str | Path) -> IOSAdvancedResult:
        """
        Document Secure Enclave Processor (SEP) architecture and forensic implications.

        This method produces a structured research document covering:
          - SEP architecture and isolation model
          - Keybag structure and key class hierarchy
          - APFS volume encryption
          - EffaceableStorage and cryptographic erase
          - Known attack surfaces and their current status
          - Forensic acquisition strategies by scenario

        NOTE: ForgeLens does NOT implement SEP exploitation.
        This documentation supports forensic practitioners in understanding
        what data is and is not recoverable from iOS devices.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        sep_doc = {
            "title": "iOS Secure Enclave Processor (SEP) — Forensic Research Notes",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "version": "ForgeLens v2.2",

            "sep_architecture": {
                "description": (
                    "The SEP is a dedicated security processor embedded in Apple SoCs (A7+). "
                    "It runs its own sepOS firmware, has isolated memory, and communicates with "
                    "the Application Processor only via a mailbox mechanism. The AP cannot read "
                    "SEP memory or execute SEP code."
                ),
                "key_functions": [
                    "Touch ID / Face ID biometric template storage and matching",
                    "Device encryption key derivation (UID key)",
                    "Passcode verification and throttling (10-attempt limit)",
                    "Secure boot chain validation",
                    "Apple Pay Secure Element interface",
                    "Cryptographic operations (ECDH, AES) on behalf of AP",
                ],
                "isolation": (
                    "Even with a fully compromised iOS kernel, the SEP cannot be accessed. "
                    "The UID (Unique ID) key is burned into hardware and never leaves the SEP."
                ),
            },

            "keybag_structure": {
                "description": (
                    "iOS uses a keybag system to manage file encryption keys. "
                    "Each file has a per-file key wrapped with a class key. "
                    "Class keys are wrapped with the device passcode-derived key."
                ),
                "key_classes": {
                    "NSFileProtectionComplete (A)": {
                        "accessible_when": "Device is unlocked",
                        "class_key_derivation": "Passcode + UID key",
                        "forensic_note": "Keys discarded from memory when device locks",
                    },
                    "NSFileProtectionCompleteUnlessOpen (B)": {
                        "accessible_when": "File open or device unlocked",
                        "forensic_note": "Public key allows new files to be created when locked",
                    },
                    "NSFileProtectionCompleteUntilFirstUserAuthentication (C)": {
                        "accessible_when": "After first unlock post-boot (most app data)",
                        "forensic_note": "Most device data — accessible in BFU (Before First Unlock) attacks only after unlock",
                    },
                    "NSFileProtectionNone (D)": {
                        "accessible_when": "Always (including when locked)",
                        "forensic_note": "Not common, used for accessibility/emergency data",
                    },
                },
                "keybag_types": [
                    "System keybag — device keys, stored in EffaceableStorage",
                    "Backup keybag — wrapped backup keys (iTunes backup encryption)",
                    "Escrow keybag — used by iTunes for trusted pairing",
                    "iCloud backup keybag — wrapped with iCloud account key",
                ],
            },

            "apfs_encryption": {
                "description": (
                    "APFS volumes on iOS are encrypted with AES-XTS using volume keys "
                    "derived from the class key hierarchy. Each APFS volume has its own "
                    "encryption key stored in the keybag."
                ),
                "effaceable_storage": (
                    "Apple devices include EffaceableStorage — a dedicated NAND region "
                    "that can be cryptographically erased in milliseconds. Wiping the keybag "
                    "from EffaceableStorage renders all encrypted data irrecoverable, even with "
                    "chip-off NAND extraction. This is the mechanism behind 'Erase All Content'."
                ),
                "forensic_implications": [
                    "Chip-off of NAND without keybag = unrecoverable ciphertext",
                    "Full disk decryption requires either passcode or exploiting SEP",
                    "BFU (Before First Unlock) state: only class D files readable",
                    "AFU (After First Unlock) state: class C, D files readable by tools like Cellebrite/GrayKey",
                ],
            },

            "acquisition_strategies": {
                "no_passcode_known": {
                    "description": "Device locked, passcode unknown",
                    "accessible": [
                        "Device metadata (serial, IMEI, model) via ideviceinfo",
                        "Emergency call functionality only",
                        "Class D (NSFileProtectionNone) files",
                    ],
                    "not_accessible": [
                        "All user data (class A, B, C)",
                        "Keychain items",
                        "iTunes backup (passcode required for encrypted, or backup password)",
                    ],
                    "tools": ["ideviceinfo for metadata only"],
                },
                "passcode_known_unlocked": {
                    "description": "Device unlocked / passcode known",
                    "accessible": [
                        "All user data via iTunes backup",
                        "AFC media partition",
                        "Syslog and crash logs",
                        "Full filesystem on jailbroken device",
                    ],
                    "tools": ["idevicebackup2", "ifuse", "pymobiledevice3"],
                },
                "jailbroken_unlocked": {
                    "description": "Jailbroken device, unlocked",
                    "accessible": [
                        "Full filesystem via AFC2",
                        "Keychain database (keychain-2.db)",
                        "SSH access for live forensics",
                        "Memory dumps via Frida or MemDump",
                        "All class A, B, C, D files",
                    ],
                    "tools": ["ifuse --afc2", "keychain-dumper", "Frida", "iphone-backup-decrypt"],
                },
            },

            "known_attack_surfaces": {
                "disclaimer": (
                    "The following documents known research for forensic awareness. "
                    "ForgeLens does not implement these attacks."
                ),
                "graykey_cellebrite": {
                    "description": "Commercial tools using undisclosed iOS exploits",
                    "current_status": "Effective against older iOS versions; Apple patches continuously",
                    "bfu_capability": "Can sometimes access class C data in BFU state on older devices",
                },
                "checkm8_exploit": {
                    "description": "Unpatchable bootrom exploit for A5-A11 chips (iPhone X and older)",
                    "tool": "checkra1n jailbreak",
                    "forensic_use": "Enables full filesystem extraction on supported devices",
                    "limitations": "Does not bypass passcode — requires passcode or known AFU state",
                },
                "sep_throttling": {
                    "description": "SEP enforces 10-attempt limit with increasing delays",
                    "bypass_status": "No known general bypass post-iOS 9",
                    "note": "checkm8 devices: USB Restricted Mode bypass possible with Ramdisk",
                },
            },

            "keybag_handling_workflow": {
                "description": "How to work with keybag data in a forensic context",
                "steps": [
                    "1. Acquire encrypted iTunes backup with known password",
                    "2. Extract BackupKeyBag from Manifest.plist",
                    "3. Derive backup key from backup password via PBKDF2",
                    "4. Unwrap class keys from keybag",
                    "5. Decrypt individual file keys and then files",
                    "6. Parse decrypted databases (SQLite) and property lists",
                ],
                "python_tools": [
                    "iphone-backup-decrypt: pip install iphone-backup-decrypt",
                    "iOSbackup: pip install iOSbackup",
                    "pymobiledevice3: pip install pymobiledevice3",
                ],
                "example": (
                    "from iphone_backup_decrypt import EncryptedBackup, RelativePath\n"
                    "backup = EncryptedBackup(backup_directory=backup_dir, passphrase='password')\n"
                    "backup.extract_file(RelativePath.SMS_DB, output_filename='sms.db')"
                ),
            },
        }

        doc_path = out / "sep_keybag_research.json"
        doc_path.write_text(json.dumps(sep_doc, indent=2), encoding="utf-8")

        return IOSAdvancedResult(
            success=True, method="sep_research",
            output_path=str(doc_path),
            artifacts=[str(doc_path)],
            notes=["SEP/keybag research document generated"],
        )

    # ── Backup decryption ─────────────────────────────────────────────────────

    def decrypt_backup(
        self,
        backup_dir: str | Path,
        password: str,
        output_dir: str | Path,
    ) -> IOSAdvancedResult:
        """
        Decrypt an encrypted iTunes backup.
        Requires: pip install iphone-backup-decrypt
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        bk = Path(backup_dir)

        try:
            from iphone_backup_decrypt import EncryptedBackup
        except ImportError:
            return IOSAdvancedResult(
                success=False, method="backup_decrypt",
                error=(
                    "iphone-backup-decrypt not installed.\n"
                    "Run: pip install iphone-backup-decrypt"
                ),
            )

        try:
            logger.info("Decrypting iOS backup | dir={}", bk)
            backup = EncryptedBackup(backup_directory=str(bk), passphrase=password)
            backup.extract_all(output_folder=str(out))

            size = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
            artifacts = [str(p) for p in out.iterdir() if p.is_file()][:20]

            return IOSAdvancedResult(
                success=True, method="backup_decrypt",
                output_path=str(out), size_bytes=size,
                artifacts=artifacts,
                notes=[
                    f"Decrypted {size/(1024**2):.1f} MB",
                    "Keychain items included if backup was encrypted",
                ],
            )
        except Exception as exc:
            return IOSAdvancedResult(
                success=False, method="backup_decrypt",
                error=f"Decryption failed: {exc} — wrong password or corrupted backup?",
            )

    # ── Crash logs and diagnostics ────────────────────────────────────────────

    def collect_crash_logs(self, output_dir: str | Path) -> IOSAdvancedResult:
        """Collect crash reports and diagnostic data from the device."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        if self._libimobile:
            ok, _ = _idevice(
                ["idevicecrashreport", "-e", str(out)],
                udid=self.udid, timeout=120,
            )
            if ok:
                crash_files = list(out.glob("**/*.crash")) + list(out.glob("**/*.ips"))
                artifacts = [str(f) for f in crash_files]

        return IOSAdvancedResult(
            success=True, method="crash_logs",
            output_path=str(out),
            artifacts=artifacts,
            notes=[f"{len(artifacts)} crash report(s) collected"],
        )

    # ── Live process info ─────────────────────────────────────────────────────

    def collect_live_process_info(self, output_dir: str | Path) -> IOSAdvancedResult:
        """
        Collect live process information via pymobiledevice3 diagnostic relay.
        Requires: paired device + pymobiledevice3.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        if not self._pymobile:
            return IOSAdvancedResult(
                success=False, method="live_process_info",
                error="pymobiledevice3 required — pip install pymobiledevice3",
            )

        # Process list via diagnostics relay
        ok, proc_list = _pymobile([
            "diagnostics", "restart", "--json",
            "-u", self.udid,
        ], timeout=30)

        # Battery / power info
        ok2, diag = _pymobile([
            "diagnostics", "info", "-u", self.udid, "--json",
        ], timeout=30)
        if ok2 and diag:
            diag_path = out / "diagnostics.json"
            diag_path.write_text(diag, encoding="utf-8")
            artifacts.append(str(diag_path))

        # App list via installation proxy
        ok3, apps = _pymobile([
            "apps", "list", "-u", self.udid, "--json",
        ], timeout=30)
        if ok3 and apps:
            apps_path = out / "installed_apps.json"
            apps_path.write_text(apps, encoding="utf-8")
            artifacts.append(str(apps_path))

        return IOSAdvancedResult(
            success=len(artifacts) > 0, method="live_process_info",
            output_path=str(out), artifacts=artifacts,
        )
