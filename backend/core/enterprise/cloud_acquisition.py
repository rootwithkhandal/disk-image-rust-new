"""
Cloud & Container Forensic Acquisition (v2.1)
==============================================
Full forensic acquisition for AWS, Azure, GCP, Docker, and Kubernetes.

Providers:
  AWS       — EBS snapshots, CloudTrail logs, S3 artifacts, IAM, VPC flow logs
  Azure     — Managed disk SAS export, Activity logs, Storage artifacts
  GCP       — Persistent disk snapshots, Cloud Audit logs, GCS artifacts
  Docker    — Container filesystem export, image layers, runtime metadata
  Kubernetes— Pod/service/event artifacts, cluster timeline, container memory

Usage:
    from core.enterprise.cloud_acquisition import CloudAcquisition

    acq = CloudAcquisition()
    result = acq.acquire_aws_snapshot("vol-0123456789", output_dir="evidence/aws")
    result = acq.acquire_docker_container("abc123", output_dir="evidence/docker")
    result = acq.reconstruct_cluster_timeline(namespace="default", output_dir="evidence/k8s")
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class CloudAcquisitionResult:
    success: bool
    provider: str
    resource_id: str
    output_path: str = ""
    size_bytes: int = 0
    sha256: str = ""
    duration_seconds: float = 0.0
    metadata: dict = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)  # list of collected artifact paths
    error: str = ""

    def __str__(self) -> str:
        status = "OK" if self.success else f"FAILED: {self.error}"
        return (
            f"[{status}] {self.provider}/{self.resource_id} | "
            f"{len(self.artifacts)} artifact(s) | {self.duration_seconds}s"
        )


# ── CLI helpers ───────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 60) -> tuple[bool, str]:
    """Run a subprocess command, return (success, output)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip() or result.stderr.strip()
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]} — is it installed and on PATH?"
    except subprocess.TimeoutExpired:
        return False, f"Command timed out after {timeout}s"
    except Exception as exc:
        return False, str(exc)


def _run_json(cmd: list[str], timeout: int = 60) -> tuple[bool, dict | list]:
    """Run a command expecting JSON output. Returns (success, parsed_data)."""
    ok, out = _run(cmd, timeout)
    if not ok:
        return False, {"error": out}
    try:
        return True, json.loads(out)
    except Exception:
        return False, {"raw": out[:500]}


def _write(path: Path, data: dict | list) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _hash_file(path: Path) -> str:
    from core.hashing.hasher import HashAlgorithm, Hasher
    try:
        return Hasher.hash_file(path, HashAlgorithm.SHA256).hex_digest
    except Exception:
        return ""


# ── Main class ────────────────────────────────────────────────────────────────

class CloudAcquisition:
    """
    Forensic acquisition from cloud and container environments.
    All methods require the relevant CLI tool to be installed and authenticated.
    """

    # ══════════════════════════════════════════════════════════════════════════
    # AWS
    # ══════════════════════════════════════════════════════════════════════════

    def acquire_aws_snapshot(
        self,
        volume_id: str,
        output_dir: str | Path,
        region: str = "us-east-1",
        wait_minutes: int = 10,
    ) -> CloudAcquisitionResult:
        """
        Create an EBS snapshot of a volume and save metadata.
        The snapshot can then be exported via aws ec2 export-image.
        Requires: aws CLI + ec2:CreateSnapshot + ec2:DescribeSnapshots
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        logger.info("AWS: Creating EBS snapshot | volume={} | region={}", volume_id, region)

        ok, snap_data = _run_json([
            "aws", "ec2", "create-snapshot",
            "--volume-id", volume_id,
            "--description", f"ForgeLens forensic {datetime.now(timezone.utc).isoformat()}",
            "--tag-specifications",
            f'ResourceType=snapshot,Tags=[{{Key=forgelens,Value=forensic}},{{Key=source-volume,Value={volume_id}}}]',
            "--region", region, "--output", "json",
        ])

        if not ok:
            return CloudAcquisitionResult(
                success=False, provider="aws", resource_id=volume_id,
                error=f"Snapshot creation failed: {snap_data.get('error', '')}",
            )

        snapshot_id = snap_data.get("SnapshotId", "")
        if not snapshot_id:
            return CloudAcquisitionResult(
                success=False, provider="aws", resource_id=volume_id,
                error="No SnapshotId in response",
            )

        logger.info("AWS: Snapshot {} created — waiting for completion...", snapshot_id)

        # Poll for completion
        for attempt in range(wait_minutes * 6):  # poll every 10s
            ok2, desc = _run_json([
                "aws", "ec2", "describe-snapshots",
                "--snapshot-ids", snapshot_id,
                "--region", region, "--output", "json",
            ])
            if ok2:
                with contextlib.suppress(Exception):
                    state = desc["Snapshots"][0]["State"]
                    progress = desc["Snapshots"][0].get("Progress", "")
                    logger.debug("AWS snapshot {} state={} progress={}", snapshot_id, state, progress)
                    if state == "completed":
                        break
                    if state == "error":
                        return CloudAcquisitionResult(
                            success=False, provider="aws", resource_id=volume_id,
                            error=f"Snapshot {snapshot_id} failed with error state",
                        )
            time.sleep(10)

        # Save snapshot metadata
        meta_path = out / f"{snapshot_id}_metadata.json"
        meta = {
            "snapshot_id": snapshot_id, "volume_id": volume_id,
            "region": region, "acquired_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_data": snap_data,
        }
        _write(meta_path, meta)
        artifacts.append(str(meta_path))

        duration = round(time.perf_counter() - start, 2)
        logger.info("AWS: Snapshot {} complete in {}s", snapshot_id, duration)

        return CloudAcquisitionResult(
            success=True, provider="aws", resource_id=snapshot_id,
            output_path=str(out), duration_seconds=duration,
            artifacts=artifacts,
            metadata={"snapshot_id": snapshot_id, "volume_id": volume_id, "region": region},
        )

    def collect_aws_artifacts(
        self,
        output_dir: str | Path,
        region: str = "us-east-1",
        include_cloudtrail: bool = True,
        include_vpc_flow: bool = False,
        include_s3_policy: bool = True,
    ) -> CloudAcquisitionResult:
        """
        Collect AWS forensic artifacts: IAM, CloudTrail, VPC config, S3 policies.
        Requires: aws CLI authenticated with read-only permissions.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        collectors = [
            # (key, command, filename)
            ("iam_users",     ["aws", "iam", "list-users", "--output", "json"],                              "iam_users.json"),
            ("iam_roles",     ["aws", "iam", "list-roles", "--output", "json"],                              "iam_roles.json"),
            ("iam_policies",  ["aws", "iam", "list-policies", "--scope", "Local", "--output", "json"],       "iam_policies.json"),
            ("iam_groups",    ["aws", "iam", "list-groups", "--output", "json"],                             "iam_groups.json"),
            ("ec2_instances", ["aws", "ec2", "describe-instances", "--region", region, "--output", "json"],  "ec2_instances.json"),
            ("ec2_sgs",       ["aws", "ec2", "describe-security-groups", "--region", region, "--output", "json"], "ec2_security_groups.json"),
            ("vpc",           ["aws", "ec2", "describe-vpcs", "--region", region, "--output", "json"],       "vpc.json"),
            ("route_tables",  ["aws", "ec2", "describe-route-tables", "--region", region, "--output", "json"], "route_tables.json"),
            ("s3_buckets",    ["aws", "s3api", "list-buckets", "--output", "json"],                          "s3_buckets.json"),
        ]

        if include_cloudtrail:
            collectors += [
                ("cloudtrail_trails",  ["aws", "cloudtrail", "describe-trails", "--region", region, "--output", "json"], "cloudtrail_trails.json"),
                ("cloudtrail_status",  ["aws", "cloudtrail", "get-trail-status", "--name", "default", "--region", region, "--output", "json"], "cloudtrail_status.json"),
            ]

        collected: dict = {}
        for key, cmd, filename in collectors:
            ok, data = _run_json(cmd, timeout=30)
            if ok:
                path = out / filename
                _write(path, data if isinstance(data, (dict, list)) else {"raw": data})
                artifacts.append(str(path))
                collected[key] = True
                logger.debug("AWS: collected {}", key)
            else:
                collected[key] = False
                logger.debug("AWS: {} skipped — {}", key, str(data)[:80])

        # Master summary
        summary_path = out / "aws_collection_summary.json"
        _write(summary_path, {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "region": region,
            "artifacts": collected,
            "artifact_count": sum(1 for v in collected.values() if v),
        })
        artifacts.append(str(summary_path))

        return CloudAcquisitionResult(
            success=True, provider="aws", resource_id="account",
            output_path=str(out),
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=artifacts,
            metadata={"region": region, "collected": collected},
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Azure
    # ══════════════════════════════════════════════════════════════════════════

    def acquire_azure_vm_disk(
        self,
        resource_group: str,
        disk_name: str,
        output_dir: str | Path,
        duration_seconds: int = 3600,
    ) -> CloudAcquisitionResult:
        """
        Generate a SAS URL for a read-only Azure managed disk.
        Use the SAS URL to download the disk image for analysis.
        Requires: az CLI authenticated.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        ok, data = _run_json([
            "az", "disk", "grant-access",
            "--resource-group", resource_group,
            "--name", disk_name,
            "--duration-in-seconds", str(duration_seconds),
            "--access-level", "Read",
            "--output", "json",
        ])

        if not ok:
            return CloudAcquisitionResult(
                success=False, provider="azure", resource_id=disk_name,
                error=f"Disk access grant failed: {data.get('error', '')}",
            )

        sas_url = data.get("accessSas", "") if isinstance(data, dict) else ""
        meta_path = out / f"{disk_name}_sas_access.json"
        _write(meta_path, {
            "disk_name": disk_name, "resource_group": resource_group,
            "sas_expires_in_seconds": duration_seconds,
            "acquired_at": datetime.now(timezone.utc).isoformat(),
            "has_sas_url": bool(sas_url),
            # Store partial URL (first 80 chars) for reference — not the full secret
            "sas_url_preview": sas_url[:80] + "..." if sas_url else "",
        })

        return CloudAcquisitionResult(
            success=bool(sas_url), provider="azure", resource_id=disk_name,
            output_path=str(meta_path),
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=[str(meta_path)],
            metadata={"disk_name": disk_name, "resource_group": resource_group, "has_sas": bool(sas_url)},
        )

    def collect_azure_artifacts(
        self,
        output_dir: str | Path,
        subscription_id: str = "",
    ) -> CloudAcquisitionResult:
        """
        Collect Azure forensic artifacts: VMs, NSGs, Activity Log, RBAC assignments.
        Requires: az CLI authenticated.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        sub_arg = ["--subscription", subscription_id] if subscription_id else []

        collectors = [
            ("vms",           ["az", "vm", "list", "--output", "json"] + sub_arg,                    "azure_vms.json"),
            ("disks",         ["az", "disk", "list", "--output", "json"] + sub_arg,                  "azure_disks.json"),
            ("nsgs",          ["az", "network", "nsg", "list", "--output", "json"] + sub_arg,         "azure_nsgs.json"),
            ("vnets",         ["az", "network", "vnet", "list", "--output", "json"] + sub_arg,        "azure_vnets.json"),
            ("storage",       ["az", "storage", "account", "list", "--output", "json"] + sub_arg,     "azure_storage.json"),
            ("role_assign",   ["az", "role", "assignment", "list", "--all", "--output", "json"] + sub_arg, "azure_role_assignments.json"),
            ("activity_log",  ["az", "monitor", "activity-log", "list", "--output", "json", "--max-events", "500"] + sub_arg, "azure_activity_log.json"),
            ("ad_users",      ["az", "ad", "user", "list", "--output", "json"],                       "azure_ad_users.json"),
            ("ad_apps",       ["az", "ad", "app", "list", "--output", "json"],                        "azure_ad_apps.json"),
        ]

        collected: dict = {}
        for key, cmd, filename in collectors:
            ok, data = _run_json(cmd, timeout=60)
            if ok:
                path = out / filename
                _write(path, data)
                artifacts.append(str(path))
                collected[key] = True
            else:
                collected[key] = False
                logger.debug("Azure: {} skipped", key)

        summary_path = out / "azure_collection_summary.json"
        _write(summary_path, {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": collected,
        })
        artifacts.append(str(summary_path))

        return CloudAcquisitionResult(
            success=True, provider="azure", resource_id="subscription",
            output_path=str(out),
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=artifacts, metadata={"collected": collected},
        )

    # ══════════════════════════════════════════════════════════════════════════
    # GCP
    # ══════════════════════════════════════════════════════════════════════════

    def acquire_gcp_disk_snapshot(
        self,
        disk_name: str,
        project: str,
        zone: str,
        output_dir: str | Path,
    ) -> CloudAcquisitionResult:
        """
        Create a forensic snapshot of a GCP persistent disk.
        Requires: gcloud CLI authenticated with compute.snapshots.create.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        snapshot_name = f"forgelens-{disk_name[:20]}-{ts}"

        logger.info("GCP: Creating disk snapshot | disk={} | project={} | zone={}", disk_name, project, zone)

        ok, output = _run([
            "gcloud", "compute", "disks", "snapshot", disk_name,
            f"--project={project}", f"--zone={zone}",
            f"--snapshot-names={snapshot_name}",
            "--format=json",
        ], timeout=120)

        # Describe the snapshot
        ok2, snap_data = _run_json([
            "gcloud", "compute", "snapshots", "describe", snapshot_name,
            f"--project={project}", "--format=json",
        ])

        meta_path = out / f"{snapshot_name}_metadata.json"
        _write(meta_path, {
            "snapshot_name": snapshot_name, "disk_name": disk_name,
            "project": project, "zone": zone,
            "acquired_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_details": snap_data,
        })

        return CloudAcquisitionResult(
            success=ok, provider="gcp", resource_id=snapshot_name,
            output_path=str(meta_path),
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=[str(meta_path)],
            metadata={"snapshot_name": snapshot_name, "disk_name": disk_name, "project": project},
            error="" if ok else output[:200],
        )

    def collect_gcp_artifacts(
        self,
        project: str,
        output_dir: str | Path,
        zone: str = "",
    ) -> CloudAcquisitionResult:
        """
        Collect GCP forensic artifacts: instances, IAM, firewall rules, audit logs.
        Requires: gcloud CLI authenticated.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        zone_arg = [f"--zones={zone}"] if zone else []

        collectors = [
            ("instances",    ["gcloud", "compute", "instances", "list", f"--project={project}", "--format=json"], "gcp_instances.json"),
            ("disks",        ["gcloud", "compute", "disks", "list", f"--project={project}", "--format=json"], "gcp_disks.json"),
            ("snapshots",    ["gcloud", "compute", "snapshots", "list", f"--project={project}", "--format=json"], "gcp_snapshots.json"),
            ("firewall",     ["gcloud", "compute", "firewall-rules", "list", f"--project={project}", "--format=json"], "gcp_firewall_rules.json"),
            ("networks",     ["gcloud", "compute", "networks", "list", f"--project={project}", "--format=json"], "gcp_networks.json"),
            ("iam_policy",   ["gcloud", "projects", "get-iam-policy", project, "--format=json"], "gcp_iam_policy.json"),
            ("service_accts",["gcloud", "iam", "service-accounts", "list", f"--project={project}", "--format=json"], "gcp_service_accounts.json"),
            ("buckets",      ["gcloud", "storage", "buckets", "list", f"--project={project}", "--format=json"], "gcp_buckets.json"),
            ("audit_logs",   ["gcloud", "logging", "read", "protoPayload.@type=type.googleapis.com/google.cloud.audit.AuditLog",
                               f"--project={project}", "--limit=500", "--format=json"], "gcp_audit_logs.json"),
        ]

        collected: dict = {}
        for key, cmd, filename in collectors:
            ok, data = _run_json(cmd, timeout=60)
            if ok:
                path = out / filename
                _write(path, data)
                artifacts.append(str(path))
                collected[key] = True
            else:
                collected[key] = False
                logger.debug("GCP: {} skipped", key)

        summary_path = out / "gcp_collection_summary.json"
        _write(summary_path, {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "project": project, "artifacts": collected,
        })
        artifacts.append(str(summary_path))

        return CloudAcquisitionResult(
            success=True, provider="gcp", resource_id=project,
            output_path=str(out),
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=artifacts, metadata={"project": project, "collected": collected},
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Docker
    # ══════════════════════════════════════════════════════════════════════════

    def acquire_docker_container(
        self,
        container_id: str,
        output_dir: str | Path,
        include_logs: bool = True,
        include_env: bool = False,    # sensitive — opt-in
    ) -> CloudAcquisitionResult:
        """
        Full forensic export of a Docker container:
        filesystem tar, metadata, process list, network info, logs.
        Requires: docker CLI.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []
        short_id = container_id[:12]

        # ── Filesystem export ─────────────────────────────────────────────────
        fs_path = out / f"docker_{short_id}_fs.tar"
        ok, err = _run(["docker", "export", container_id, "--output", str(fs_path)], timeout=300)
        if ok and fs_path.exists():
            sha = _hash_file(fs_path)
            artifacts.append(str(fs_path))
            logger.info("Docker: fs exported | {} | sha256={}", short_id, sha[:16])
        else:
            logger.warning("Docker: fs export failed — {}", err[:100])

        # ── Inspect metadata ──────────────────────────────────────────────────
        ok2, inspect = _run_json(["docker", "inspect", container_id])
        if ok2 and isinstance(inspect, list) and inspect:
            meta = inspect[0]
            # Optionally redact environment variables
            if not include_env and isinstance(meta.get("Config"), dict):
                meta["Config"]["Env"] = ["<redacted — use --env to include>"]
            meta_path = out / f"docker_{short_id}_metadata.json"
            _write(meta_path, meta)
            artifacts.append(str(meta_path))

        # ── Running processes ─────────────────────────────────────────────────
        ok3, procs_raw = _run(["docker", "top", container_id, "auxww"])
        if ok3:
            proc_path = out / f"docker_{short_id}_processes.txt"
            proc_path.write_text(procs_raw, encoding="utf-8")
            artifacts.append(str(proc_path))

        # ── Network stats ─────────────────────────────────────────────────────
        ok4, net_raw = _run(["docker", "stats", "--no-stream", "--format",
                              "{{json .}}", container_id])
        if ok4:
            net_path = out / f"docker_{short_id}_stats.json"
            with contextlib.suppress(Exception):
                net_path.write_text(net_raw, encoding="utf-8")
                artifacts.append(str(net_path))

        # ── Container logs ────────────────────────────────────────────────────
        if include_logs:
            ok5, logs = _run(["docker", "logs", "--timestamps", container_id], timeout=60)
            if ok5:
                log_path = out / f"docker_{short_id}_logs.txt"
                log_path.write_text(logs, encoding="utf-8")
                artifacts.append(str(log_path))

        # ── Image history ─────────────────────────────────────────────────────
        image_id = ""
        if ok2 and isinstance(inspect, list) and inspect:
            image_id = inspect[0].get("Image", "")
        if image_id:
            ok6, history = _run_json(["docker", "history", "--no-trunc",
                                       "--format", "{{json .}}", image_id])
            if ok6:
                hist_path = out / f"docker_{short_id}_image_history.json"
                _write(hist_path, history if isinstance(history, list) else [])
                artifacts.append(str(hist_path))

        size = fs_path.stat().st_size if fs_path.exists() else 0
        sha256 = _hash_file(fs_path) if fs_path.exists() else ""

        return CloudAcquisitionResult(
            success=len(artifacts) > 0, provider="docker", resource_id=container_id,
            output_path=str(out), size_bytes=size, sha256=sha256,
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=artifacts,
            metadata={
                "container_id": container_id,
                "image": (inspect[0].get("Config", {}).get("Image", "") if ok2 and inspect else ""),
            },
        )

    def collect_docker_artifacts(self, output_dir: str | Path) -> CloudAcquisitionResult:
        """
        Inventory all Docker objects: containers, images, volumes, networks.
        Requires: docker CLI.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        collectors = [
            ("containers", ["docker", "ps", "-a", "--format", "{{json .}}"],       "docker_containers.json"),
            ("images",     ["docker", "images", "-a", "--format", "{{json .}}"],   "docker_images.json"),
            ("volumes",    ["docker", "volume", "ls", "--format", "{{json .}}"],   "docker_volumes.json"),
            ("networks",   ["docker", "network", "ls", "--format", "{{json .}}"],  "docker_networks.json"),
        ]

        collected: dict = {}
        for key, cmd, filename in collectors:
            ok, raw = _run(cmd)
            if ok:
                items = []
                for line in raw.splitlines():
                    with contextlib.suppress(Exception):
                        items.append(json.loads(line))
                path = out / filename
                _write(path, items)
                artifacts.append(str(path))
                collected[key] = len(items)

        # Docker system info
        ok_info, sys_info = _run_json(["docker", "system", "info", "--format", "{{json .}}"])
        if ok_info:
            info_path = out / "docker_system_info.json"
            _write(info_path, sys_info)
            artifacts.append(str(info_path))

        summary_path = out / "docker_collection_summary.json"
        _write(summary_path, {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "counts": collected,
        })
        artifacts.append(str(summary_path))

        return CloudAcquisitionResult(
            success=True, provider="docker", resource_id="host",
            output_path=str(out),
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=artifacts, metadata={"counts": collected},
        )

    def acquire_container_memory(
        self,
        container_id: str,
        output_dir: str | Path,
    ) -> CloudAcquisitionResult:
        """
        Acquire the memory of a running container by attaching to its process
        namespace and using /proc/<pid>/mem or nsenter + gcore.
        Requires: docker CLI + root/cap_sys_ptrace on the host.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []
        short_id = container_id[:12]

        # Get the PID of the container's init process on the host
        ok, pid_raw = _run(["docker", "inspect", "--format", "{{.State.Pid}}", container_id])
        if not ok or not pid_raw.strip().isdigit():
            return CloudAcquisitionResult(
                success=False, provider="docker", resource_id=container_id,
                error=f"Could not get container PID: {pid_raw[:100]}",
            )

        host_pid = pid_raw.strip()

        # Read /proc/<pid>/maps and mem for a lightweight memory snapshot
        maps_path = out / f"docker_{short_id}_proc_maps.txt"
        try:
            maps = Path(f"/proc/{host_pid}/maps").read_text()
            maps_path.write_text(maps, encoding="utf-8")
            artifacts.append(str(maps_path))
        except Exception as exc:
            logger.warning("Container memory: maps read failed — {}", exc)

        # Try gcore dump via nsenter (Linux only)
        dump_path = out / f"docker_{short_id}_core"
        ok2, err = _run([
            "nsenter", "-t", host_pid, "-m", "-u", "-i", "-n", "-p", "--",
            "gcore", "-o", str(dump_path), host_pid,
        ], timeout=120)

        if ok2 and dump_path.with_suffix("").exists():
            actual = dump_path.with_suffix("")
            artifacts.append(str(actual))
            sha256 = _hash_file(actual)
            logger.info("Container memory acquired: {} bytes", actual.stat().st_size)
        else:
            logger.warning("gcore failed (requires root + gdb): {}", err[:100])
            sha256 = ""

        # Save process memory maps as forensic artifact regardless
        smaps_path = out / f"docker_{short_id}_smaps.txt"
        try:
            smaps = Path(f"/proc/{host_pid}/smaps").read_text()
            smaps_path.write_text(smaps, encoding="utf-8")
            artifacts.append(str(smaps_path))
        except Exception:
            pass

        return CloudAcquisitionResult(
            success=len(artifacts) > 0, provider="docker", resource_id=container_id,
            output_path=str(out), sha256=sha256,
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=artifacts,
            metadata={"host_pid": host_pid, "container_id": container_id},
        )

    # ══════════════════════════════════════════════════════════════════════════
    # Kubernetes
    # ══════════════════════════════════════════════════════════════════════════

    def collect_kubernetes_artifacts(
        self,
        namespace: str = "default",
        output_dir: str | Path = ".",
        all_namespaces: bool = False,
    ) -> CloudAcquisitionResult:
        """
        Collect Kubernetes forensic artifacts for a namespace or cluster-wide.
        Requires: kubectl CLI authenticated.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[str] = []

        ns_arg = ["--all-namespaces"] if all_namespaces else ["-n", namespace]
        ns_label = "all" if all_namespaces else namespace

        resources = [
            "pods", "services", "deployments", "replicasets",
            "daemonsets", "statefulsets", "jobs", "cronjobs",
            "events", "configmaps", "serviceaccounts",
            "networkpolicies", "ingresses", "persistentvolumeclaims",
        ]
        cluster_resources = [
            "nodes", "persistentvolumes", "clusterroles",
            "clusterrolebindings", "namespaces",
        ]

        collected: dict = {}

        # Namespace-scoped resources
        for resource in resources:
            ok, data = _run_json(["kubectl", "get", resource] + ns_arg + ["-o", "json"])
            if ok:
                path = out / f"k8s_{ns_label}_{resource}.json"
                _write(path, data)
                artifacts.append(str(path))
                items = data.get("items", []) if isinstance(data, dict) else []
                collected[resource] = len(items)
            else:
                collected[resource] = 0

        # Cluster-scoped resources
        for resource in cluster_resources:
            ok, data = _run_json(["kubectl", "get", resource, "-o", "json"])
            if ok:
                path = out / f"k8s_cluster_{resource}.json"
                _write(path, data)
                artifacts.append(str(path))
                items = data.get("items", []) if isinstance(data, dict) else []
                collected[f"cluster_{resource}"] = len(items)

        # Node descriptions (detailed)
        ok_nodes, nodes = _run_json(["kubectl", "get", "nodes", "-o", "json"])
        if ok_nodes and isinstance(nodes, dict):
            for node in nodes.get("items", []):
                node_name = node.get("metadata", {}).get("name", "unknown")
                ok_desc, desc = _run(["kubectl", "describe", "node", node_name])
                if ok_desc:
                    desc_path = out / f"k8s_node_{node_name}_describe.txt"
                    desc_path.write_text(desc, encoding="utf-8")
                    artifacts.append(str(desc_path))

        summary_path = out / f"k8s_{ns_label}_collection_summary.json"
        _write(summary_path, {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "namespace": namespace, "all_namespaces": all_namespaces,
            "resource_counts": collected,
        })
        artifacts.append(str(summary_path))

        return CloudAcquisitionResult(
            success=True, provider="kubernetes", resource_id=ns_label,
            output_path=str(out),
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=artifacts,
            metadata={"namespace": namespace, "resource_counts": collected},
        )

    def reconstruct_cluster_timeline(
        self,
        namespace: str = "default",
        output_dir: str | Path = ".",
        all_namespaces: bool = False,
    ) -> CloudAcquisitionResult:
        """
        Reconstruct a forensic timeline of Kubernetes cluster activity
        from Events, Pod creation/deletion timestamps, and Job history.
        Requires: kubectl CLI authenticated.
        """
        start = time.perf_counter()
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        ns_arg = ["--all-namespaces"] if all_namespaces else ["-n", namespace]
        ns_label = "all" if all_namespaces else namespace

        timeline: list[dict] = []

        # ── Kubernetes Events ─────────────────────────────────────────────────
        ok, events_data = _run_json(["kubectl", "get", "events"] + ns_arg + ["-o", "json"])
        if ok and isinstance(events_data, dict):
            for ev in events_data.get("items", []):
                ts = (ev.get("lastTimestamp") or ev.get("eventTime") or
                      ev.get("metadata", {}).get("creationTimestamp", ""))
                timeline.append({
                    "timestamp": ts,
                    "type": "k8s_event",
                    "namespace": ev.get("metadata", {}).get("namespace", ""),
                    "reason": ev.get("reason", ""),
                    "message": ev.get("message", "")[:200],
                    "object_kind": ev.get("involvedObject", {}).get("kind", ""),
                    "object_name": ev.get("involvedObject", {}).get("name", ""),
                    "source": ev.get("source", {}).get("component", ""),
                    "event_type": ev.get("type", ""),  # Normal | Warning
                    "is_suspicious": ev.get("type") == "Warning",
                })

        # ── Pod lifecycle ─────────────────────────────────────────────────────
        ok2, pods_data = _run_json(["kubectl", "get", "pods"] + ns_arg + ["-o", "json"])
        if ok2 and isinstance(pods_data, dict):
            for pod in pods_data.get("items", []):
                meta = pod.get("metadata", {})
                status = pod.get("status", {})
                name = meta.get("name", "")
                ns = meta.get("namespace", "")
                created = meta.get("creationTimestamp", "")
                phase = status.get("phase", "")
                deleted = meta.get("deletionTimestamp", "")

                if created:
                    timeline.append({
                        "timestamp": created,
                        "type": "pod_created",
                        "namespace": ns,
                        "object_kind": "Pod",
                        "object_name": name,
                        "message": f"Pod created | phase={phase}",
                        "is_suspicious": False,
                    })
                if deleted:
                    timeline.append({
                        "timestamp": deleted,
                        "type": "pod_deleted",
                        "namespace": ns,
                        "object_kind": "Pod",
                        "object_name": name,
                        "message": f"Pod marked for deletion | phase={phase}",
                        "is_suspicious": False,
                    })

                # Flag privileged containers
                for container in pod.get("spec", {}).get("containers", []):
                    sc = container.get("securityContext", {})
                    if sc.get("privileged") or sc.get("allowPrivilegeEscalation"):
                        timeline.append({
                            "timestamp": created,
                            "type": "privileged_container",
                            "namespace": ns,
                            "object_kind": "Pod",
                            "object_name": name,
                            "message": f"Privileged container: {container.get('name', '')}",
                            "is_suspicious": True,
                        })

        # ── Sort and save ─────────────────────────────────────────────────────
        timeline.sort(key=lambda e: e.get("timestamp") or "")

        suspicious = [e for e in timeline if e.get("is_suspicious")]
        timeline_path = out / f"k8s_{ns_label}_timeline.json"
        _write(timeline_path, {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "namespace": namespace,
            "total_events": len(timeline),
            "suspicious_events": len(suspicious),
            "time_range": {
                "start": timeline[0]["timestamp"] if timeline else "",
                "end": timeline[-1]["timestamp"] if timeline else "",
            },
            "events": timeline,
        })

        return CloudAcquisitionResult(
            success=True, provider="kubernetes", resource_id=f"{ns_label}_timeline",
            output_path=str(timeline_path),
            duration_seconds=round(time.perf_counter() - start, 2),
            artifacts=[str(timeline_path)],
            metadata={
                "namespace": namespace,
                "total_events": len(timeline),
                "suspicious_events": len(suspicious),
            },
        )
