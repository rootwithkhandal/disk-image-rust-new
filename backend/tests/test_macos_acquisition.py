"""Tests for macOS acquisition modules. Graceful on non-macOS."""

import tempfile
from pathlib import Path

import platform

IS_MACOS = platform.system() == "Darwin"


class TestMacOSEnumeration:
    def test_get_macos_system_info_returns_object(self):
        from platforms.macos.enumeration import get_macos_system_info

        info = get_macos_system_info()
        assert info is not None
        assert hasattr(info, "os_version")
        assert hasattr(info, "sip_status")

    def test_detect_apfs_containers_returns_list(self):
        from platforms.macos.enumeration import detect_apfs_containers

        result = detect_apfs_containers()
        assert isinstance(result, list)

    def test_enumerate_disks_returns_list(self):
        from platforms.macos.enumeration import enumerate_disks

        result = enumerate_disks()
        assert isinstance(result, list)

    def test_get_filevault_status_returns_string(self):
        from platforms.macos.enumeration import get_filevault_status

        result = get_filevault_status()
        assert isinstance(result, str)

    def test_get_sip_status_returns_string(self):
        from platforms.macos.enumeration import get_sip_status

        result = get_sip_status()
        assert isinstance(result, str)


class TestMacOSArtifacts:
    def test_collect_unified_logs_returns_list(self):
        from platforms.macos.artifacts import collect_unified_logs

        result = collect_unified_logs(last_minutes=1, max_entries=5)
        assert isinstance(result, list)

    def test_collect_safari_history_returns_list(self):
        from platforms.macos.artifacts import collect_safari_history

        result = collect_safari_history()
        assert isinstance(result, list)

    def test_collect_keychain_metadata_returns_list(self):
        from platforms.macos.artifacts import collect_keychain_metadata

        result = collect_keychain_metadata()
        assert isinstance(result, list)

    def test_collect_launch_entries_returns_list(self):
        from platforms.macos.artifacts import collect_launch_entries

        result = collect_launch_entries()
        assert isinstance(result, list)

    def test_collect_apfs_snapshots_returns_list(self):
        from platforms.macos.artifacts import collect_apfs_snapshots

        result = collect_apfs_snapshots()
        assert isinstance(result, list)

    def test_collect_all_artifacts_structure(self):
        from platforms.macos.artifacts import collect_all_artifacts

        result = collect_all_artifacts()
        assert isinstance(result, dict)
        assert "unified_logs" in result
        assert "safari_history" in result
        assert "launch_entries" in result
        assert "apfs_snapshots" in result


class TestMacOSOrchestrator:
    def test_collect_all_writes_output_files(self):
        from platforms.macos import MacOSAcquisition

        tmp = Path(tempfile.mkdtemp())
        summary = MacOSAcquisition.collect_all(
            output_dir=tmp,
            include_artifacts=True,
        )
        assert isinstance(summary, dict)
        assert (tmp / "collection_summary.json").exists()
        assert (tmp / "system_info.json").exists()
