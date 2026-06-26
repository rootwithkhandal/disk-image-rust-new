"""
Tests for Linux acquisition modules.
Collectors return empty results gracefully on non-Linux systems.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import platform

IS_LINUX = platform.system() == "Linux"


class TestLinuxEnumeration:
    def test_detect_block_devices_returns_list(self):
        from platforms.linux.enumeration import detect_block_devices

        result = detect_block_devices()
        assert isinstance(result, list)
        if IS_LINUX:
            assert len(result) >= 1

    def test_detect_lvm_volumes_returns_list(self):
        from platforms.linux.enumeration import detect_lvm_volumes

        result = detect_lvm_volumes()
        assert isinstance(result, list)

    def test_detect_raid_arrays_returns_list(self):
        from platforms.linux.enumeration import detect_raid_arrays

        result = detect_raid_arrays()
        assert isinstance(result, list)

    def test_detect_encrypted_partitions_returns_list(self):
        from platforms.linux.enumeration import detect_encrypted_partitions

        result = detect_encrypted_partitions()
        assert isinstance(result, list)

    def test_detect_filesystem_types_returns_dict(self):
        from platforms.linux.enumeration import detect_filesystem_types

        result = detect_filesystem_types()
        assert isinstance(result, dict)


class TestLinuxArtifacts:
    def test_collect_bash_history_returns_list(self):
        from platforms.linux.artifacts import collect_bash_history

        result = collect_bash_history()
        assert isinstance(result, list)

    def test_collect_ssh_artifacts_returns_list(self):
        from platforms.linux.artifacts import collect_ssh_artifacts

        result = collect_ssh_artifacts()
        assert isinstance(result, list)

    def test_collect_crontabs_returns_list(self):
        from platforms.linux.artifacts import collect_crontabs

        result = collect_crontabs()
        assert isinstance(result, list)

    def test_collect_syslog_returns_list(self):
        from platforms.linux.artifacts import collect_syslog

        result = collect_syslog(max_lines=10)
        assert isinstance(result, list)

    def test_collect_auth_log_returns_list(self):
        from platforms.linux.artifacts import collect_auth_log

        result = collect_auth_log(max_lines=10)
        assert isinstance(result, list)

    def test_collect_journalctl_returns_list(self):
        from platforms.linux.artifacts import collect_journalctl

        result = collect_journalctl(max_lines=10)
        assert isinstance(result, list)

    def test_collect_docker_artifacts_returns_dict(self):
        from platforms.linux.artifacts import collect_docker_artifacts

        result = collect_docker_artifacts()
        assert isinstance(result, dict)
        assert "containers" in result
        assert "images" in result

    def test_collect_all_artifacts_structure(self):
        from platforms.linux.artifacts import collect_all_artifacts

        result = collect_all_artifacts()
        assert isinstance(result, dict)
        assert "bash_history" in result
        assert "ssh_artifacts" in result
        assert "crontabs" in result
        assert "syslog" in result
        assert "auth_log" in result
        assert "docker" in result


class TestLinuxMemory:
    def test_get_ram_info_returns_dict(self):
        from platforms.linux.memory import get_ram_info

        result = get_ram_info()
        assert isinstance(result, dict)
        if IS_LINUX and result:
            assert "total_gb" in result
            assert result["total_gb"] > 0

    def test_acquire_ram_no_tool_fails_gracefully(self):
        from platforms.linux.memory import _find_tool, acquire_ram

        tmp = Path(tempfile.mkdtemp()) / "test_ram.lime"
        # Only test graceful failure when no tool is present
        if not _find_tool(["avml", "avml-memory"]) and not _find_tool(["lime.ko"]):
            result = acquire_ram(tmp)
            assert result.success is False
            assert result.error != ""


class TestLinuxAcquisitionOrchestrator:
    def test_collect_all_writes_output_files(self):
        from platforms.linux import LinuxAcquisition

        tmp = Path(tempfile.mkdtemp())
        summary = LinuxAcquisition.collect_all(
            output_dir=tmp,
            include_artifacts=True,
            include_ram=False,
        )
        assert isinstance(summary, dict)
        assert "files" in summary
        assert "counts" in summary
        assert (tmp / "collection_summary.json").exists()
        assert (tmp / "system_info.json").exists()
        assert (tmp / "artifacts.json").exists()
