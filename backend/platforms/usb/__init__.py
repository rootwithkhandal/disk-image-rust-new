"""USB & External Storage platform module."""

from platforms.usb.detector import (
    MediaType,
    USBDevice,
    USBHotplugMonitor,
    detect_usb_devices,
)

__all__ = ["detect_usb_devices", "USBDevice", "MediaType", "USBHotplugMonitor"]
