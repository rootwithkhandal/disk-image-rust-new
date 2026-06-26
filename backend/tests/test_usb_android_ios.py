"""Tests for USB detector, Android, and iOS acquisition modules."""

import tempfile
from pathlib import Path


class TestUSBDetector:
    def test_detect_usb_devices_returns_list(self):
        from platforms.usb.detector import detect_usb_devices

        result = detect_usb_devices()
        assert isinstance(result, list)

    def test_usb_device_dataclass(self):
        from platforms.usb.detector import MediaType, USBDevice

        dev = USBDevice(
            device_id="/dev/sdb",
            label="Test Drive",
            serial="ABC123",
            media_type=MediaType.USB_HDD,
            size_bytes=1024**3,
        )
        assert dev.size_gb == 1.0
        assert "usb_hdd" in str(dev)

    def test_hotplug_monitor_start_stop(self):
        from platforms.usb.detector import USBHotplugMonitor

        monitor = USBHotplugMonitor(poll_interval=0.1)
        monitor.start()
        import time

        time.sleep(0.3)
        monitor.stop()
        # Just verify it doesn't crash

    def test_usb_module_imports(self):
        from platforms.usb import detect_usb_devices

        assert detect_usb_devices is not None


class TestAndroidAcquisition:
    def test_detect_devices_returns_list(self):
        from platforms.android.acquisition import detect_devices

        result = detect_devices()
        assert isinstance(result, list)
        # No device connected in CI — just verify no crash

    def test_android_device_dataclass(self):
        from platforms.android.acquisition import AndroidDevice

        dev = AndroidDevice(
            serial="emulator-5554",
            model="Pixel 6",
            android_version="13",
            is_rooted=False,
        )
        assert dev.serial == "emulator-5554"
        assert dev.is_rooted is False

    def test_android_artifact_dataclass(self):
        from platforms.android.acquisition import AndroidArtifact

        art = AndroidArtifact(
            artifact_type="sms",
            source_path="/data/data/com.android.providers.telephony/databases/mmssms.db",
            error="not accessible",
        )
        assert art.artifact_type == "sms"
        assert art.error != ""

    def test_extract_installed_apps_no_device(self):
        """Without a device, should return empty list gracefully."""
        from platforms.android.acquisition import extract_installed_apps

        result = extract_installed_apps("nonexistent-serial")
        assert isinstance(result, list)

    def test_android_module_imports(self):
        from platforms.android import (
            detect_devices,
        )

        assert detect_devices is not None


class TestIOSAcquisition:
    def test_detect_devices_returns_list(self):
        from platforms.ios.acquisition import detect_devices

        result = detect_devices()
        assert isinstance(result, list)

    def test_ios_device_dataclass(self):
        from platforms.ios.acquisition import IOSDevice

        dev = IOSDevice(
            udid="abc123def456",
            name="iPhone 14",
            ios_version="16.5",
            is_jailbroken=False,
        )
        assert dev.udid == "abc123def456"
        assert dev.is_jailbroken is False

    def test_ios_artifact_dataclass(self):
        from platforms.ios.acquisition import IOSArtifact

        art = IOSArtifact(
            artifact_type="itunes_backup",
            source_path="device:abc123",
            error="idevicebackup2 not found",
        )
        assert art.artifact_type == "itunes_backup"
        assert art.error != ""

    def test_extract_itunes_backup_no_device(self):
        """Without a device, should return failure gracefully."""
        from platforms.ios.acquisition import extract_itunes_backup

        tmp = Path(tempfile.mkdtemp())
        result = extract_itunes_backup("nonexistent-udid", tmp)
        assert result.artifact_type == "itunes_backup"
        # Either succeeds (unlikely) or has an error message
        assert result.error != "" or result.local_path != ""

    def test_ios_module_imports(self):
        from platforms.ios import (
            detect_devices,
        )

        assert detect_devices is not None
