"""
USB & External Storage Detector
=================================
Cross-platform detection of USB devices, SD cards, external drives.
Supports hotplug monitoring, serial number extraction, and metadata logging.
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger

import platform


class MediaType(str, Enum):
    USB_HDD = "usb_hdd"
    USB_SSD = "usb_ssd"
    USB_FLASH = "usb_flash"
    SD_CARD = "sd_card"
    NVME = "nvme"
    SATA = "sata"
    OPTICAL = "optical"
    UNKNOWN = "unknown"


@dataclass
class USBDevice:
    device_id: str
    label: str = ""
    vendor: str = ""
    product: str = ""
    serial: str = ""
    media_type: MediaType = MediaType.UNKNOWN
    size_bytes: int = 0
    filesystem: str = ""
    mount_point: str = ""
    bus: str = ""
    is_removable: bool = True
    connected_at: str = ""
    raw: dict = field(default_factory=dict)

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)

    def __str__(self) -> str:
        return (
            f"[{self.media_type.value}] {self.device_id} | "
            f"{self.vendor} {self.product} | {self.size_gb} GB | "
            f"serial={self.serial or 'N/A'}"
        )


def _run(cmd: list[str], timeout: int = 10) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else None
    except FileNotFoundError:
        return None
    except Exception as exc:
        logger.error("USB detector command error: {}", exc)
        return None


def detect_usb_devices() -> list[USBDevice]:
    """Detect all connected USB and removable storage devices."""
    os_name = platform.system()
    if os_name == "Windows":
        return _detect_windows_usb()
    elif os_name == "Linux":
        return _detect_linux_usb()
    elif os_name == "Darwin":
        return _detect_macos_usb()
    return []


def _detect_windows_usb() -> list[USBDevice]:
    """Detect USB devices on Windows via WMI."""
    devices: list[USBDevice] = []
    out = _run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-WmiObject Win32_DiskDrive | "
            "Where-Object {$_.InterfaceType -eq 'USB' -or $_.MediaType -like '*Removable*'} | "
            "Select-Object DeviceID,Model,SerialNumber,Size,InterfaceType,MediaType | "
            "ConvertTo-Json -Depth 2",
        ]
    )
    if not out:
        return devices
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        for d in raw:
            size = int(d.get("Size") or 0)
            media = (d.get("MediaType") or "").lower()
            mtype = MediaType.USB_FLASH if size < 64 * (1024**3) else MediaType.USB_HDD
            if "sd" in media or "card" in media:
                mtype = MediaType.SD_CARD
            devices.append(
                USBDevice(
                    device_id=d.get("DeviceID", ""),
                    label=d.get("Model", ""),
                    serial=(d.get("SerialNumber") or "").strip(),
                    media_type=mtype,
                    size_bytes=size,
                    bus="USB",
                    raw=d,
                )
            )
    except Exception as exc:
        logger.error("Windows USB parse error: {}", exc)
    logger.info("Windows USB: detected {} device(s)", len(devices))
    return devices


def _detect_linux_usb() -> list[USBDevice]:
    """Detect USB devices on Linux via lsblk + udevadm."""
    devices: list[USBDevice] = []
    out = _run(
        [
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,TRAN,RM,VENDOR,MODEL,SERIAL",
        ]
    )
    if not out:
        return devices
    try:
        data = json.loads(out)
        for blk in data.get("blockdevices", []):
            tran = (blk.get("tran") or "").lower()
            is_removable = str(blk.get("rm", "0")) == "1"
            if tran not in ("usb", "sd") and not is_removable:
                continue
            mtype = MediaType.SD_CARD if tran == "sd" else MediaType.USB_HDD
            size = int(blk.get("size") or 0)
            if size < 64 * (1024**3) and tran == "usb":
                mtype = MediaType.USB_FLASH
            devices.append(
                USBDevice(
                    device_id=f"/dev/{blk.get('name', '')}",
                    label=blk.get("model") or blk.get("name", ""),
                    vendor=blk.get("vendor") or "",
                    product=blk.get("model") or "",
                    serial=blk.get("serial") or "",
                    media_type=mtype,
                    size_bytes=size,
                    filesystem=blk.get("fstype") or "",
                    mount_point=blk.get("mountpoint") or "",
                    bus=tran.upper(),
                    is_removable=is_removable,
                    raw=blk,
                )
            )
    except Exception as exc:
        logger.error("Linux USB parse error: {}", exc)
    logger.info("Linux USB: detected {} device(s)", len(devices))
    return devices


def _detect_macos_usb() -> list[USBDevice]:
    """Detect USB devices on macOS via system_profiler."""
    import plistlib

    devices: list[USBDevice] = []
    try:
        result = subprocess.run(
            ["system_profiler", "SPUSBDataType", "-xml"],
            capture_output=True,
            timeout=15,
        )
        if result.returncode != 0:
            return devices
        plist = plistlib.loads(result.stdout)

        def _walk(items: list) -> None:
            for item in items:
                if isinstance(item, dict):
                    name = item.get("_name", "")
                    if name and "hub" not in name.lower():
                        size = int(item.get("bcd_device", 0) or 0)
                        devices.append(
                            USBDevice(
                                device_id=item.get("location_id", name),
                                label=name,
                                vendor=item.get("manufacturer", ""),
                                product=name,
                                serial=item.get("serial_num", ""),
                                media_type=MediaType.USB_FLASH,
                                size_bytes=size,
                                bus="USB",
                                raw=item,
                            )
                        )
                    sub = item.get("_items", [])
                    if sub:
                        _walk(sub)

        for top in plist:
            _walk(top.get("_items", []))
    except Exception as exc:
        logger.error("macOS USB parse error: {}", exc)
    logger.info("macOS USB: detected {} device(s)", len(devices))
    return devices


# ── Hotplug monitor ───────────────────────────────────────────────────────────


class USBHotplugMonitor:
    """
    Monitors USB device connect/disconnect events.
    Calls on_connect(device) and on_disconnect(device_id) callbacks.
    """

    def __init__(
        self,
        on_connect: Callable[[USBDevice], None] | None = None,
        on_disconnect: Callable[[str], None] | None = None,
        poll_interval: float = 2.0,
    ) -> None:
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._poll_interval = poll_interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._known: dict[str, USBDevice] = {}

    def start(self) -> None:
        """Start monitoring in a background thread."""
        self._running = True
        self._known = {d.device_id: d for d in detect_usb_devices()}
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()
        logger.info("USB hotplug monitor started | {} device(s) known", len(self._known))

    def stop(self) -> None:
        """Stop the monitor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("USB hotplug monitor stopped")

    def _poll_loop(self) -> None:
        while self._running:
            time.sleep(self._poll_interval)
            try:
                current = {d.device_id: d for d in detect_usb_devices()}

                # New devices
                for dev_id, dev in current.items():
                    if dev_id not in self._known:
                        logger.info("USB connected: {}", dev)
                        if self._on_connect:
                            self._on_connect(dev)

                # Removed devices
                for dev_id in list(self._known):
                    if dev_id not in current:
                        logger.info("USB disconnected: {}", dev_id)
                        if self._on_disconnect:
                            self._on_disconnect(dev_id)

                self._known = current
            except Exception as exc:
                logger.error("Hotplug poll error: {}", exc)
