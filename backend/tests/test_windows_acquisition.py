"""
Tests for Windows acquisition modules.
These tests run on all platforms — Windows-specific collectors
return empty results gracefully on non-Windows systems.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import platform

IS_WINDOWS = platform.system() == "Windows"


class TestWindowsEnumeration:
    def test_get_windows_version_returns_object(self):
        from platforms.windows.enumeration import get_windows_version

        info = get_windows_version()
        # On non-Windows returns empty object — just check it doesn't crash
        assert info is not None
        assert hasattr(info, "os_name")

    def test_enumerate_physical_drives_returns_list(self):
        from platforms.windows.enumeration import enumerate_physical_drives

        drives = enumerate_physical_drives()
        assert isinstance(drives, list)
        if IS_WINDOWS:
            assert len(drives) >= 1

    def test_enumerate_mounted_partitions_returns_list(self):
        from platforms.windows.enumeration import enumerate_mounted_partitions

        partitions = enumerate_mounted_partitions()
        assert isinstance(partitions, list)

    def test_get_bitlocker_status_returns_list(self):
        from platforms.windows.enumeration import get_bitlocker_status

        status = get_bitlocker_status()
        assert isinstance(status, list)

    def test_enumerate_shadow_copies_returns_list(self):
        from platforms.windows.enumeration import enumerate_shadow_copies

        copies = enumerate_shadow_copies()
        assert isinstance(copies, list)


class TestWindowsRegistry:
    def test_collect_run_keys_returns_list(self):
        from platforms.windows.registry import collect_run_keys

        result = collect_run_keys()
        assert isinstance(result, list)

    def test_collect_usb_history_returns_list(self):
        from platforms.windows.registry import collect_usb_history

        result = collect_usb_history()
        assert isinstance(result, list)

    def test_collect_userassist_returns_list(self):
        from platforms.windows.registry import collect_userassist

        result = collect_userassist()
        assert isinstance(result, list)

    def test_collect_all_registry_artifacts_structure(self):
        from platforms.windows.registry import collect_all_registry_artifacts

        result = collect_all_registry_artifacts()
        assert isinstance(result, dict)
        assert "run_keys" in result
        assert "usb_history" in result
        assert "userassist" in result
        assert "recent_docs" in result


class TestWindowsEventLogs:
    def test_collect_login_activity_returns_list(self):
        from platforms.windows.event_logs import collect_login_activity

        result = collect_login_activity(max_events=10)
        assert isinstance(result, list)

    def test_collect_all_event_logs_structure(self):
        from platforms.windows.event_logs import collect_all_event_logs

        result = collect_all_event_logs(max_events=10)
        assert isinstance(result, dict)
        assert "login_activity" in result
        assert "powershell_activity" in result
        assert "process_creation" in result
        assert "service_installs" in result
        assert "rdp_activity" in result


class TestWindowsArtifacts:
    def test_collect_prefetch_returns_list(self):
        from platforms.windows.artifacts import collect_prefetch

        result = collect_prefetch()
        assert isinstance(result, list)
        if IS_WINDOWS:
            # Prefetch entries should have expected fields
            for entry in result:
                assert hasattr(entry, "filename")
                assert hasattr(entry, "path")

    def test_collect_user_profiles_returns_list(self):
        from platforms.windows.artifacts import collect_user_profiles

        result = collect_user_profiles()
        assert isinstance(result, list)

    def test_collect_jump_lists_returns_list(self):
        from platforms.windows.artifacts import collect_jump_lists

        result = collect_jump_lists()
        assert isinstance(result, list)

    def test_collect_browser_history_structure(self):
        from platforms.windows.artifacts import collect_browser_history

        result = collect_browser_history()
        assert isinstance(result, dict)
        assert "chrome" in result
        assert "edge" in result
        assert "firefox" in result

    def test_collect_all_artifacts_structure(self):
        from platforms.windows.artifacts import collect_all_artifacts

        result = collect_all_artifacts()
        assert isinstance(result, dict)
        assert "prefetch" in result
        assert "browser_history" in result
        assert "user_profiles" in result


class TestWindowsLiveResponse:
    def test_enumerate_processes_returns_list(self):
        from platforms.windows.live_response import enumerate_processes

        result = enumerate_processes()
        assert isinstance(result, list)
        if IS_WINDOWS:
            assert len(result) > 0
            assert result[0].name != ""

    def test_capture_network_connections_returns_list(self):
        from platforms.windows.live_response import capture_network_connections

        result = capture_network_connections()
        assert isinstance(result, list)

    def test_capture_arp_table_returns_list(self):
        from platforms.windows.live_response import capture_arp_table

        result = capture_arp_table()
        assert isinstance(result, list)

    def test_capture_dns_cache_returns_list(self):
        from platforms.windows.live_response import capture_dns_cache

        result = capture_dns_cache()
        assert isinstance(result, list)

    def test_collect_scheduled_tasks_returns_list(self):
        from platforms.windows.live_response import collect_scheduled_tasks

        result = collect_scheduled_tasks()
        assert isinstance(result, list)

    def test_collect_all_live_response_structure(self):
        from platforms.windows.live_response import collect_all_live_response

        result = collect_all_live_response()
        assert isinstance(result, dict)
        assert "processes" in result
        assert "network_connections" in result
        assert "arp_table" in result
        assert "dns_cache" in result
        assert "scheduled_tasks" in result


class TestWindowsMemory:
    def test_get_ram_info_returns_dict(self):
        from platforms.windows.memory import get_ram_info

        info = get_ram_info()
        assert isinstance(info, dict)
        if info:
            assert "total_gb" in info
            assert info["total_gb"] > 0

    def test_acquire_ram_no_winpmem_fails_gracefully(self):
        """Without WinPMEM installed, should return failure gracefully."""
        from platforms.windows.memory import acquire_ram

        tmp = Path(tempfile.mkdtemp()) / "test_ram.raw"
        # Only run if WinPMEM is NOT present (safe test)
        from platforms.windows.memory import _find_winpmem

        if _find_winpmem() is None:
            result = acquire_ram(tmp)
            assert result.success is False
            assert result.error != ""


class TestWindowsAcquisitionOrchestrator:
    def test_collect_all_writes_output_files(self):
        from platforms.windows import WindowsAcquisition

        tmp = Path(tempfile.mkdtemp())
        summary = WindowsAcquisition.collect_all(
            output_dir=tmp,
            include_live_response=True,
            include_registry=True,
            include_event_logs=True,
            include_artifacts=True,
            include_ram=False,
        )

        assert isinstance(summary, dict)
        assert "files" in summary
        assert "counts" in summary
        assert (tmp / "collection_summary.json").exists()
        assert (tmp / "system_info.json").exists()
