"""
Android Acquisition
====================
ADB-based logical and physical acquisition for Android devices.
Supports rooted and non-rooted devices.

Requires: adb on PATH or in tools/
"""

from __future__ import annotations

from collections.abc import Callable
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass
class AndroidDevice:
    serial: str
    model: str = ""
    manufacturer: str = ""
    android_version: str = ""
    sdk_version: str = ""
    build_id: str = ""
    is_rooted: bool = False
    bootloader_state: str = ""
    encryption_state: str = ""
    screen_locked: bool = True


@dataclass
class AndroidArtifact:
    artifact_type: str
    source_path: str
    local_path: str = ""
    size_bytes: int = 0
    error: str = ""


def _adb(serial: str, args: list[str], timeout: int = 30) -> str | None:
    """Run an adb command against a specific device."""
    try:
        result = subprocess.run(
            ["adb", "-s", serial] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except FileNotFoundError:
        logger.error("ADB not found — install Android Platform Tools")
        return None
    except Exception as exc:
        logger.error("ADB error: {}", exc)
        return None


def _prop(serial: str, prop: str) -> str:
    """Get an Android system property."""
    return _adb(serial, ["shell", "getprop", prop]) or ""


def detect_devices() -> list[AndroidDevice]:
    """Detect all connected Android devices via ADB."""
    devices: list[AndroidDevice] = []
    try:
        result = subprocess.run(
            ["adb", "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines()[1:]:
            line = line.strip()
            if not line or "offline" in line or "unauthorized" in line:
                continue
            parts = line.split()
            if len(parts) < 2 or parts[1] != "device":
                continue
            serial = parts[0]
            dev = _get_device_info(serial)
            devices.append(dev)
    except FileNotFoundError:
        logger.warning("ADB not found")
    except Exception as exc:
        logger.error("Device detection error: {}", exc)
    logger.info("Android: detected {} device(s)", len(devices))
    return devices


def _get_device_info(serial: str) -> AndroidDevice:
    """Collect detailed info about a connected Android device."""
    model = _prop(serial, "ro.product.model")
    manufacturer = _prop(serial, "ro.product.manufacturer")
    android_version = _prop(serial, "ro.build.version.release")
    sdk = _prop(serial, "ro.build.version.sdk")
    build_id = _prop(serial, "ro.build.id")
    bootloader = _prop(serial, "ro.boot.verifiedbootstate")
    encryption = _prop(serial, "ro.crypto.state")

    # Root check — try `id` command
    id_out = _adb(serial, ["shell", "id"])
    is_rooted = bool(id_out and "uid=0" in id_out)

    return AndroidDevice(
        serial=serial,
        model=model,
        manufacturer=manufacturer,
        android_version=android_version,
        sdk_version=sdk,
        build_id=build_id,
        is_rooted=is_rooted,
        bootloader_state=bootloader,
        encryption_state=encryption,
    )


# ── Logical acquisition ───────────────────────────────────────────────────────


def _pull_with_su(serial: str, remote_path: str, local_path: Path) -> bool:
    """Try to copy a file using su to /data/local/tmp and then pull it."""
    su_check = _adb(serial, ["shell", "which", "su"])
    if not su_check or "su" not in su_check:
        return False

    import uuid
    temp_name = f"tmp_{uuid.uuid4().hex}"
    temp_path = f"/data/local/tmp/{temp_name}"

    try:
        # Copy to temp using su
        _adb(serial, ["shell", "su", "-c", f"cp {remote_path} {temp_path}"])
        # Change permissions so we can pull it
        _adb(serial, ["shell", "su", "-c", f"chmod 666 {temp_path}"])
        # Pull it
        out = _adb(serial, ["pull", temp_path, str(local_path)], timeout=30)
        # Clean up temp file
        _adb(serial, ["shell", "rm", "-f", temp_path])
        return out is not None and local_path.exists()
    except Exception:
        # Clean up in case of failure
        _adb(serial, ["shell", "rm", "-f", temp_path])
        return False


# ── Logical acquisition ───────────────────────────────────────────────────────


def extract_sms(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract SMS database via ADB backup or direct pull (rooted) or content query."""
    output_dir.mkdir(parents=True, exist_ok=True)
    sms_paths = [
        "/data/data/com.android.providers.telephony/databases/mmssms.db",
        "/data/user/0/com.android.providers.telephony/databases/mmssms.db",
    ]
    for sms_path in sms_paths:
        local = output_dir / "mmssms.db"
        # 1. Try standard pull
        out = _adb(serial, ["pull", sms_path, str(local)], timeout=30)
        if out and local.exists():
            return AndroidArtifact(
                artifact_type="sms",
                source_path=sms_path,
                local_path=str(local),
                size_bytes=local.stat().st_size,
            )
        # 2. Try pull with su
        if _pull_with_su(serial, sms_path, local):
            return AndroidArtifact(
                artifact_type="sms",
                source_path=sms_path,
                local_path=str(local),
                size_bytes=local.stat().st_size,
            )

    # 3. Fallback: Query content provider
    local_fallback = output_dir / "sms_query.txt"
    out = _adb(serial, ["shell", "content", "query", "--uri", "content://sms"], timeout=30)
    if out and "Error" not in out and "Permission Denial" not in out:
        local_fallback.write_text(out, encoding="utf-8")
        return AndroidArtifact(
            artifact_type="sms",
            source_path="content://sms",
            local_path=str(local_fallback),
            size_bytes=local_fallback.stat().st_size,
        )

    return AndroidArtifact(
        artifact_type="sms",
        source_path="",
        error="SMS database not accessible (device may not be rooted and content query failed)",
    )


def extract_contacts(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract contacts database."""
    output_dir.mkdir(parents=True, exist_ok=True)
    contacts_paths = [
        "/data/data/com.android.providers.contacts/databases/contacts2.db",
        "/data/user/0/com.android.providers.contacts/databases/contacts2.db",
    ]
    for path in contacts_paths:
        local = output_dir / "contacts2.db"
        # 1. Try standard pull
        out = _adb(serial, ["pull", path, str(local)], timeout=30)
        if out and local.exists():
            return AndroidArtifact(
                artifact_type="contacts",
                source_path=path,
                local_path=str(local),
                size_bytes=local.stat().st_size,
            )
        # 2. Try pull with su
        if _pull_with_su(serial, path, local):
            return AndroidArtifact(
                artifact_type="contacts",
                source_path=path,
                local_path=str(local),
                size_bytes=local.stat().st_size,
            )

    # 3. Fallback: Query content provider
    local_fallback = output_dir / "contacts_query.txt"
    out = _adb(serial, ["shell", "content", "query", "--uri", "content://contacts/phones"], timeout=30)
    if out and "Error" not in out and "Permission Denial" not in out:
        local_fallback.write_text(out, encoding="utf-8")
        return AndroidArtifact(
            artifact_type="contacts",
            source_path="content://contacts/phones",
            local_path=str(local_fallback),
            size_bytes=local_fallback.stat().st_size,
        )

    return AndroidArtifact(
        artifact_type="contacts",
        source_path="",
        error="Contacts database not accessible",
    )


def extract_call_log(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract call log database."""
    output_dir.mkdir(parents=True, exist_ok=True)
    call_paths = [
        "/data/data/com.android.providers.contacts/databases/calllog.db",
        "/data/user/0/com.android.providers.contacts/databases/calllog.db",
    ]
    for path in call_paths:
        local = output_dir / "calllog.db"
        # 1. Try standard pull
        out = _adb(serial, ["pull", path, str(local)], timeout=30)
        if out and local.exists():
            return AndroidArtifact(
                artifact_type="call_log",
                source_path=path,
                local_path=str(local),
                size_bytes=local.stat().st_size,
            )
        # 2. Try pull with su
        if _pull_with_su(serial, path, local):
            return AndroidArtifact(
                artifact_type="call_log",
                source_path=path,
                local_path=str(local),
                size_bytes=local.stat().st_size,
            )

    # 3. Fallback: Query content provider
    local_fallback = output_dir / "call_log_query.txt"
    out = _adb(serial, ["shell", "content", "query", "--uri", "content://call_log/calls"], timeout=30)
    if out and "Error" not in out and "Permission Denial" not in out:
        local_fallback.write_text(out, encoding="utf-8")
        return AndroidArtifact(
            artifact_type="call_log",
            source_path="content://call_log/calls",
            local_path=str(local_fallback),
            size_bytes=local_fallback.stat().st_size,
        )

    return AndroidArtifact(
        artifact_type="call_log",
        source_path="",
        error="Call log not accessible",
    )


def extract_installed_apps(serial: str) -> list[dict]:
    """List all installed packages."""
    out = _adb(serial, ["shell", "pm", "list", "packages", "-f"])
    if not out:
        return []
    apps = []
    for line in out.splitlines():
        if line.startswith("package:"):
            parts = line[8:].rsplit("=", 1)
            apps.append(
                {
                    "apk_path": parts[0] if len(parts) > 1 else "",
                    "package": parts[1] if len(parts) > 1 else parts[0],
                }
            )
    logger.info("Android: {} installed app(s)", len(apps))
    return apps


def extract_media(serial: str, output_dir: Path, max_files: int = 100) -> list[AndroidArtifact]:
    """Pull media files from /sdcard/DCIM and /sdcard/Pictures."""
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[AndroidArtifact] = []
    media_dirs = ["/sdcard/DCIM", "/sdcard/Pictures", "/sdcard/Downloads"]

    for media_dir in media_dirs:
        local_dir = output_dir / Path(media_dir).name
        out = _adb(serial, ["pull", media_dir, str(local_dir)], timeout=120)
        if out:
            artifacts.append(
                AndroidArtifact(
                    artifact_type="media",
                    source_path=media_dir,
                    local_path=str(local_dir),
                    size_bytes=sum(f.stat().st_size for f in local_dir.rglob("*") if f.is_file())
                    if local_dir.exists()
                    else 0,
                )
            )

    return artifacts


def extract_apks(serial: str, output_dir: Path) -> list[AndroidArtifact]:
    """Extract APK files for all user-installed apps."""
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[AndroidArtifact] = []
    apps = extract_installed_apps(serial)

    for app in apps[:50]:  # Limit to 50 APKs
        apk_path = app.get("apk_path", "")
        pkg = app.get("package", "unknown")
        if not apk_path:
            continue
        local = output_dir / f"{pkg}.apk"
        out = _adb(serial, ["pull", apk_path, str(local)], timeout=60)
        if out and local.exists():
            artifacts.append(
                AndroidArtifact(
                    artifact_type="apk",
                    source_path=apk_path,
                    local_path=str(local),
                    size_bytes=local.stat().st_size,
                )
            )

    logger.info("Android: extracted {} APK(s)", len(artifacts))
    return artifacts


def _extract_app_databases_dir(
    serial: str,
    output_dir: Path,
    package_name: str,
    local_subdir_name: str,
    artifact_type: str,
) -> AndroidArtifact:
    """Extract all databases from an application's database folder."""
    local_dir = output_dir / local_subdir_name
    local_dir.mkdir(parents=True, exist_ok=True)
    
    remote_dirs = [
        f"/data/data/{package_name}/databases",
        f"/data/user/0/{package_name}/databases",
    ]

    for remote_dir in remote_dirs:
        # 1. Try standard pull of the directory
        out = _adb(serial, ["pull", remote_dir, str(output_dir)], timeout=120)
        # adb pull remote_dir local_parent creates local_parent/databases
        extracted_path = output_dir / "databases"
        if extracted_path.exists() and any(extracted_path.iterdir()):
            if extracted_path != local_dir:
                if local_dir.exists():
                    import shutil
                    shutil.rmtree(local_dir)
                extracted_path.rename(local_dir)
            return AndroidArtifact(
                artifact_type=artifact_type,
                source_path=remote_dir,
                local_path=str(local_dir),
                size_bytes=sum(f.stat().st_size for f in local_dir.rglob("*") if f.is_file()),
            )

        # 2. Try pull with su (for rooted devices)
        su_check = _adb(serial, ["shell", "which", "su"])
        if su_check and "su" in su_check:
            import uuid
            temp_name = f"tmp_{uuid.uuid4().hex}"
            temp_path = f"/data/local/tmp/{temp_name}"
            try:
                # Copy databases folder to temp using su
                _adb(serial, ["shell", "su", "-c", f"cp -r {remote_dir} {temp_path}"])
                # Change permissions
                _adb(serial, ["shell", "su", "-c", f"chmod -R 777 {temp_path}"])
                # Pull it
                _adb(serial, ["pull", temp_path, str(local_dir)], timeout=120)
                # Clean up
                _adb(serial, ["shell", "rm", "-rf", temp_path])
                
                pulled_subdir = local_dir / temp_name
                if pulled_subdir.exists():
                    for f in pulled_subdir.iterdir():
                        dest = local_dir / f.name
                        if dest.exists():
                            if dest.is_dir():
                                import shutil
                                shutil.rmtree(dest)
                            else:
                                dest.unlink()
                        f.rename(dest)
                    pulled_subdir.rmdir()
                    return AndroidArtifact(
                        artifact_type=artifact_type,
                        source_path=remote_dir,
                        local_path=str(local_dir),
                        size_bytes=sum(f.stat().st_size for f in local_dir.rglob("*") if f.is_file()),
                    )
            except Exception as exc:
                logger.error("Failed to copy app databases via su: {}", exc)
                _adb(serial, ["shell", "rm", "-rf", temp_path])

    # 3. Fallback for non-rooted devices: Try to pull shared cache/files/media from SD card
    sd_data_dirs = [
        f"/sdcard/Android/data/{package_name}",
        f"/sdcard/Android/media/{package_name}",
    ]
    if package_name == "org.telegram.messenger":
        sd_data_dirs.append("/sdcard/Telegram")
    elif package_name == "org.thoughtcrime.securesms":
        sd_data_dirs.append("/sdcard/Signal")
    elif package_name == "com.whatsapp":
        sd_data_dirs.append("/sdcard/WhatsApp")

    local_cache_dir = output_dir / f"{local_subdir_name}_shared"
    pulled_any = False

    for sd_dir in sd_data_dirs:
        ls_out = _adb(serial, ["shell", "ls", sd_dir])
        if ls_out and "No such file" not in ls_out and "Permission denied" not in ls_out:
            local_cache_dir.mkdir(parents=True, exist_ok=True)
            out = _adb(serial, ["pull", sd_dir, str(local_cache_dir)], timeout=120)
            if out and local_cache_dir.exists() and any(local_cache_dir.iterdir()):
                pulled_any = True

    if pulled_any:
        return AndroidArtifact(
            artifact_type=artifact_type,
            source_path=f"shared_storage://{package_name}",
            local_path=str(local_cache_dir),
            size_bytes=sum(f.stat().st_size for f in local_cache_dir.rglob("*") if f.is_file()),
        )

    return AndroidArtifact(
        artifact_type=artifact_type,
        source_path=f"/data/data/{package_name}/databases",
        error=f"{artifact_type.capitalize()} databases not accessible (requires root)",
    )


def extract_whatsapp(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract WhatsApp database folder (decrypted via root/su, or fallback encrypted backups from shared storage)."""
    # 1. Try to pull decrypted databases (requires root/su)
    art = _extract_app_databases_dir(
        serial, output_dir, "com.whatsapp", "whatsapp", "whatsapp"
    )
    if not art.error:
        return art

    # 2. Fallback for non-rooted devices: Pull local backups (.crypt14, .crypt15, etc.) from SD card
    sd_backup_dirs = [
        "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
        "/sdcard/WhatsApp/Databases",
    ]
    local_backup_dir = output_dir / "whatsapp_backups"

    for backup_dir in sd_backup_dirs:
        ls_out = _adb(serial, ["shell", "ls", backup_dir])
        if ls_out and "No such file" not in ls_out and "Permission denied" not in ls_out:
            # Create local folder
            local_backup_dir.mkdir(parents=True, exist_ok=True)
            # Pull the entire folder
            out = _adb(serial, ["pull", backup_dir, str(output_dir)], timeout=120)
            extracted_db_dir = output_dir / "Databases"
            if extracted_db_dir.exists() and any(extracted_db_dir.iterdir()):
                import shutil
                if local_backup_dir.exists():
                    try:
                        shutil.rmtree(local_backup_dir)
                    except Exception:
                        pass
                extracted_db_dir.rename(local_backup_dir)
                return AndroidArtifact(
                    artifact_type="whatsapp",
                    source_path=backup_dir,
                    local_path=str(local_backup_dir),
                    size_bytes=sum(f.stat().st_size for f in local_backup_dir.rglob("*") if f.is_file()),
                )

    return art


def extract_telegram(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract Telegram database folder."""
    return _extract_app_databases_dir(
        serial, output_dir, "org.telegram.messenger", "telegram", "telegram"
    )


def extract_gmail(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract Gmail database folder."""
    return _extract_app_databases_dir(
        serial, output_dir, "com.google.android.gm", "gmail", "gmail"
    )


def extract_googledrive(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract Google Drive database folder."""
    return _extract_app_databases_dir(
        serial, output_dir, "com.google.android.apps.docs", "googledrive", "googledrive"
    )


def extract_googlephotos(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract Google Photos database folder."""
    return _extract_app_databases_dir(
        serial, output_dir, "com.google.android.apps.photos", "googlephotos", "googlephotos"
    )


def extract_signal(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract Signal database folder (decrypted via root/su, or fallback encrypted backups from shared storage)."""
    # 1. Try to pull decrypted databases (requires root/su)
    art = _extract_app_databases_dir(
        serial, output_dir, "org.thoughtcrime.securesms", "signal", "signal"
    )
    if not art.error:
        return art

    # 2. Fallback for non-rooted devices: Pull local backups (.backup files) from SD card
    sd_backup_dirs = [
        "/sdcard/Android/media/org.thoughtcrime.securesms/Signal/Backups",
        "/sdcard/Signal/Backups",
    ]
    local_backup_dir = output_dir / "signal_backups"

    for backup_dir in sd_backup_dirs:
        ls_out = _adb(serial, ["shell", "ls", backup_dir])
        if ls_out and "No such file" not in ls_out and "Permission denied" not in ls_out:
            # Create local folder
            local_backup_dir.mkdir(parents=True, exist_ok=True)
            # Pull the entire folder
            out = _adb(serial, ["pull", backup_dir, str(output_dir)], timeout=120)
            extracted_db_dir = output_dir / "Backups"
            if extracted_db_dir.exists() and any(extracted_db_dir.iterdir()):
                import shutil
                if local_backup_dir.exists():
                    try:
                        shutil.rmtree(local_backup_dir)
                    except Exception:
                        pass
                extracted_db_dir.rename(local_backup_dir)
                return AndroidArtifact(
                    artifact_type="signal",
                    source_path=backup_dir,
                    local_path=str(local_backup_dir),
                    size_bytes=sum(f.stat().st_size for f in local_backup_dir.rglob("*") if f.is_file()),
                )

    if art.error:
        art.error = (
            "Signal database not accessible. On non-rooted devices, you must manually "
            "enable Chat Backups in Signal settings (Settings -> Chats -> Chat backups) "
            "to generate a local backup on the SD card before running acquisition."
        )
    return art


def extract_facebook(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract Facebook database folder."""
    return _extract_app_databases_dir(
        serial, output_dir, "com.facebook.katana", "facebook", "facebook"
    )


def extract_messenger(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract Facebook Messenger database folder."""
    return _extract_app_databases_dir(
        serial, output_dir, "com.facebook.orca", "messenger", "messenger"
    )


def extract_instagram(serial: str, output_dir: Path) -> AndroidArtifact:
    """Extract Instagram database folder."""
    return _extract_app_databases_dir(
        serial, output_dir, "com.instagram.android", "instagram", "instagram"
    )


def collect_all(
    serial: str,
    output_dir: str | Path,
    progress_callback: Callable[[str, float], None] | None = None,
) -> dict:
    """Run all Android logical acquisition collectors."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    logger.info("Starting Android acquisition | serial={}", serial)
    if progress_callback:
        progress_callback("Getting device info", 5.0)
    device = _get_device_info(serial)

    if progress_callback:
        progress_callback("Extracting installed apps", 15.0)
    installed_apps = extract_installed_apps(serial)

    if progress_callback:
        progress_callback("Extracting SMS database", 25.0)
    sms = extract_sms(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting contacts database", 35.0)
    contacts = extract_contacts(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting call logs", 45.0)
    call_log = extract_call_log(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting media files", 60.0)
    media = extract_media(serial, out / "media")

    if progress_callback:
        progress_callback("Extracting WhatsApp database", 70.0)
    whatsapp = extract_whatsapp(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting Telegram database", 75.0)
    telegram = extract_telegram(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting Gmail database", 80.0)
    gmail = extract_gmail(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting Google Drive database", 82.0)
    googledrive = extract_googledrive(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting Google Photos database", 85.0)
    googlephotos = extract_googlephotos(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting Signal database", 88.0)
    signal = extract_signal(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting Facebook database", 91.0)
    facebook = extract_facebook(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting Facebook Messenger database", 94.0)
    messenger = extract_messenger(serial, out / "databases")

    if progress_callback:
        progress_callback("Extracting Instagram database", 97.0)
    instagram = extract_instagram(serial, out / "databases")

    results = {
        "device_info": vars(device),
        "installed_apps": installed_apps,
        "sms": vars(sms),
        "contacts": vars(contacts),
        "call_log": vars(call_log),
        "media": [vars(a) for a in media],
        "whatsapp": vars(whatsapp),
        "telegram": vars(telegram),
        "gmail": vars(gmail),
        "googledrive": vars(googledrive),
        "googlephotos": vars(googlephotos),
        "signal": vars(signal),
        "facebook": vars(facebook),
        "messenger": vars(messenger),
        "instagram": vars(instagram),
    }

    summary_path = out / "android_acquisition_summary.json"
    summary_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    logger.info("Android acquisition complete | output={}", out)
    if progress_callback:
        progress_callback("Acquisition complete", 100.0)
    return results
