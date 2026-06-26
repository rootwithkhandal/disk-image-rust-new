# ForgeLens CLI Usage Guide

Full reference for the ForgeLens command-line interface.

```bash
python forgelens.py [COMMAND] [OPTIONS]
```

---

## Global Options

| Flag | Description |
|---|---|
| `--verbose` / `-v` | Enable debug logging |
| `--log-dir PATH` | Override log directory |
| `--help` | Show help for any command |

---

## 1. Dependency Setup

### Check all dependencies
```bash
python forgelens.py setup check
python forgelens.py setup check --all   # include non-current-OS tools
```

### Auto-install missing tools
```bash
python forgelens.py setup install
python forgelens.py setup install --optional   # also optional tools
python forgelens.py setup install --dry-run    # preview only
```

### Download WinPmem (Windows RAM acquisition)
```bash
python forgelens.py memory setup
python forgelens.py memory setup --arch x86    # 32-bit systems
```

### Download disk mount tools
```bash
python forgelens.py setup mounter              # ImDisk (default)
python forgelens.py setup mounter --tool aim   # Arsenal Image Mounter instructions
python forgelens.py setup mounter --tool all
```

### Full tool reference
```bash
python forgelens.py setup info
```

---

## 2. Device Detection

```bash
# List all physical disks
python forgelens.py devices

# Include Android devices (ADB)
python forgelens.py devices --android

# Detect everything — disks + Android + iOS
python forgelens.py acquire detect

# Show partition layout for a device
python forgelens.py enumerate "\\.\PhysicalDrive0"   # Windows
python forgelens.py enumerate /dev/sda               # Linux/macOS
```

---

## 3. Platform Acquisition

### Windows (live system)

Collects processes, network connections, ARP/DNS cache, scheduled tasks,
registry run keys, BitLocker status. Optionally acquires RAM.

```bash
# Artifacts only
python forgelens.py acquire windows \
  --case CASE-2026-001 --examiner "Jane Smith" --output evidence\windows

# Artifacts + RAM (run as Administrator)
python forgelens.py acquire windows \
  --case CASE-2026-001 --examiner "Jane Smith" --output evidence\windows \
  --memory
```

### Linux (live system)

Collects block devices, LVM volumes, RAID arrays, bash history, SSH keys,
crontabs, syslog, auth.log. Optionally acquires RAM via AVML or LiME.

```bash
python forgelens.py acquire linux \
  --case CASE-2026-001 --examiner "Jane Smith" --output /evidence/linux

python forgelens.py acquire linux \
  --case CASE-2026-001 --examiner "Jane Smith" --output /evidence/linux \
  --memory
```

### macOS (live system)

Collects APFS containers, FileVault status, SIP, unified logs,
Safari history, LaunchAgents/Daemons.

```bash
python forgelens.py acquire macos \
  --case CASE-2026-001 --examiner "Jane Smith" --output /evidence/macos
```

### Android (connected device via ADB)

Requires USB debugging enabled on the device.

```bash
# Auto-detect device
python forgelens.py acquire android \
  --case CASE-2026-001 --examiner "Jane Smith" --output evidence\android

# Specific device
python forgelens.py acquire android \
  --case CASE-2026-001 --examiner "Jane Smith" --output evidence\android \
  --serial R58M12345XY
```

### iOS (connected device)

Requires device unlocked and trusted. Uses libimobiledevice or pymobiledevice3.

```bash
# Auto-detect device
python forgelens.py acquire ios \
  --case CASE-2026-001 --examiner "Jane Smith" --output evidence\ios

# By UDID
python forgelens.py acquire ios \
  --case CASE-2026-001 --examiner "Jane Smith" --output evidence\ios \
  --udid 00008110-001234567890ABCD
```

### MS-DOS / Legacy FAT

```bash
python forgelens.py acquire msdos \
  --source "\\.\PhysicalDrive2" \
  --case CASE-2026-001 --examiner "Jane Smith" \
  --output evidence\msdos --format dd
```

---

## 4. Disk Imaging (DD / E01)

```bash
# Windows
python forgelens.py image acquire \
  --source "\\.\PhysicalDrive0" \
  --output evidence --case CASE-2026-001 --examiner "Jane Smith" \
  --format dd

# Linux / macOS
python forgelens.py image acquire \
  --source /dev/sda \
  --output /evidence --case CASE-2026-001 --examiner "Jane Smith" \
  --format e01

# Options
#   --format dd|e01       image format (default: dd)
#   --block-size N        read block size in bytes (default: 65536)
#   --verify/--no-verify  post-acquisition verification (default: verify)
```

### Mount an image read-only

```bash
# Windows — requires ImDisk or Arsenal Image Mounter in tools/
python forgelens.py image mount evidence\image.dd --drive Z \
  --case CASE-2026-001 --evidence EV-XXXXXXXX

# Linux/macOS — uses kernel loopback (no extra tools)
python forgelens.py image mount /evidence/image.dd \
  --case CASE-2026-001 --evidence EV-XXXXXXXX

# List active mounts
python forgelens.py image mounts

# Unmount
python forgelens.py image unmount A1B2C3D4
python forgelens.py image unmount ALL
```

---

## 5. Hashing & Verification

```bash
# Hash a file
python forgelens.py hash file evidence/image.dd --algo sha256

# Hash with all algorithms in one pass
python forgelens.py hash file evidence/image.dd --multi

# Hash a physical drive (Windows, run as Administrator)
python forgelens.py hash file "\\.\PhysicalDrive0" --algo sha256

# Verify against a known hash
python forgelens.py hash verify evidence/image.dd <HASH> --algo sha256
```

Supported algorithms: `sha256` `md5` `sha1` `blake3`

---

## 6. Memory Forensics

### Acquire RAM

**Windows** (Administrator required):
```bash
python forgelens.py memory setup        # download WinPmem (once)
python forgelens.py memory acquire \
  --output evidence\memory.raw \
  --case CASE-2026-001 --examiner "Jane Smith"
```

**Linux** (root required, AVML or LiME):
```bash
python forgelens.py acquire linux --memory \
  --case CASE-2026-001 --examiner "Jane Smith" --output /evidence/linux
```

### Analyse a memory dump

```bash
# List all processes
python forgelens.py memory processes dump.raw

# Suspicious processes only
python forgelens.py memory processes dump.raw --suspicious

# List loaded DLLs
python forgelens.py memory dlls dump.raw
python forgelens.py memory dlls dump.raw --pid 1234

# Network connections
python forgelens.py memory connections dump.raw

# Injected code / process hollowing
python forgelens.py memory malfind dump.raw

# NTLM password hashes
python forgelens.py memory hashes dump.raw

# Memory timeline
python forgelens.py memory timeline dump.raw
python forgelens.py memory timeline dump.raw --output timeline.json --suspicious

# Export all processes + connections to JSON (for YARA/VirusTotal)
python forgelens.py memory export dump.raw --output evidence\memory_export.json
python forgelens.py memory export dump.raw --virustotal --vt-key YOUR_KEY
python forgelens.py memory export dump.raw --yara-rules plugins\yara_rules
```

---

## 7. Case Management

```bash
# Create a case
python forgelens.py case create CASE-2026-001 \
  --examiner "Jane Smith" --title "Ransomware Investigation" \
  --tags "windows,ransomware" --priority high

# List cases
python forgelens.py cases
python forgelens.py case list --status active

# Update a case
python forgelens.py case update CASE-2026-001 --status closed

# Search
python forgelens.py case search "ransomware"

# Full audit trail
python forgelens.py case audit CASE-2026-001
```

Case statuses: `open` `active` `closed` `archived`  
Priorities: `low` `medium` `high` `critical`

---

## 8. Evidence Vault

```bash
# Tag evidence
python forgelens.py vault tag --case CASE-2026-001 --evidence EV-XXXXXXXX "malware,urgent"

# Search evidence
python forgelens.py vault search --tag malware
python forgelens.py vault search --case CASE-2026-001

# Rebuild search index
python forgelens.py vault index

# Repair missing metadata.json for all evidence
python forgelens.py vault repair
python forgelens.py vault repair --case CASE-2026-001   # specific case
python forgelens.py vault repair --dry-run              # preview only

# Encrypt an evidence file (AES-256-GCM)
python forgelens.py vault encrypt evidence/image.dd
python forgelens.py vault decrypt evidence/image.dd.enc --key evidence/image.key

# Verify HMAC-signed metadata
python forgelens.py vault verify-sig \
  --case CASE-2026-001 --evidence EV-XXXXXXXX --key metadata.key
```

---

## 9. Reports & Chain of Custody

```bash
# Generate reports
python forgelens.py export report \
  --case CASE-2026-001 --evidence EV-XXXXXXXX \
  --formats "json,html,text"

# Print chain of custody
python forgelens.py export custody \
  --case CASE-2026-001 --evidence EV-XXXXXXXX
```

---

## 10. Offensive DFIR (v2.3)

### Persistence hunting (live Windows)
```bash
python forgelens.py dfir persist --output evidence\dfir
```
Checks: Run keys, scheduled tasks, services, WMI subscriptions, IFEO hijacks, startup folders.

### Beacon detection
```bash
# From memory dump
python forgelens.py dfir beacons --dump dump.raw --output evidence\dfir

# From JSON files
python forgelens.py dfir beacons \
  --connections connections.json --processes processes.json
```
Detects: LOLBin HTTP/S connections, classic C2 ports (4444/31337), DNS C2, statistical interval analysis vs Cobalt Strike/Sliver/Empire defaults.

### Credential theft detection
```bash
python forgelens.py dfir creds --dump dump.raw --output evidence\dfir
python forgelens.py dfir creds --processes procs.json --events events.json
```
Detects: Mimikatz/WCE/procdump, Kerberoasting (4769 RC4), Pass-the-Hash (4624 type 3), DCSync (4662), WDigest enabled, comsvcs MiniDump.

### Ransomware triage
```bash
python forgelens.py dfir ransomware C:\Users --output evidence\dfir
python forgelens.py dfir ransomware C:\ --max-files 100000
```
Detects: Ransom notes, 100+ known encrypted extensions, VSS deletion, blast radius estimate.

### Lateral movement mapping
```bash
python forgelens.py dfir lateral --events security_log.json --output evidence\dfir
python forgelens.py dfir lateral --dump dump.raw --events events.json
```
Detects: Logon paths (4624), admin share access (5140), remote service install (7045), PsExec/WMI/WinRM/RDP.

### Full triage (all modules)
```bash
python forgelens.py dfir full-triage C:\ \
  --dump dump.raw \
  --events security_log.json \
  --output evidence\dfir
```

---

## 11. Advanced Mobile Forensics (v2.2)

### Android
```bash
# Full filesystem (auto-selects method based on root access)
python forgelens.py mobile android-filesystem --output evidence\android
python forgelens.py mobile android-filesystem --method tar_root --partition /data
python forgelens.py mobile android-filesystem --method adb_backup

# SQLite deleted record recovery (WAL + freelist scan)
python forgelens.py mobile android-recover mmssms.db --output evidence\recovery
# Pull from device first, then recover:
python forgelens.py mobile android-recover mmssms.db --output evidence\recovery \
  --serial R58M12345 \
  --remote /data/data/com.android.providers.telephony/databases/mmssms.db

# Keystore / TEE enumeration + research doc
python forgelens.py mobile android-keystore --output evidence\keystore

# Deep artifacts (/proc, dmesg, WiFi, Bluetooth, accounts)
python forgelens.py mobile android-deep --output evidence\android-deep
```

### iOS
```bash
# Full filesystem
python forgelens.py mobile ios-filesystem --output evidence\ios
python forgelens.py mobile ios-filesystem --method itunes_backup
python forgelens.py mobile ios-filesystem --method afc2       # jailbreak
python forgelens.py mobile ios-filesystem --method ssh_tar    # jailbreak + SSH

# Keychain
python forgelens.py mobile ios-keychain --output evidence\ios

# SEP/keybag architecture research document
python forgelens.py mobile ios-sep --output evidence\ios

# Decrypt encrypted iTunes backup
python forgelens.py mobile ios-decrypt path\to\backup \
  --output evidence\ios-decrypted

# Collect crash logs
python forgelens.py mobile ios-crashes --output evidence\ios-crashes
```

---

## 12. Cloud & Container Forensics (v2.1)

### AWS
```bash
python forgelens.py cloud aws-snapshot vol-0123456789abcdef0 \
  --output evidence\aws --region us-east-1

python forgelens.py cloud aws-collect --output evidence\aws
```

### Azure
```bash
python forgelens.py cloud azure-disk my-rg my-disk --output evidence\azure
python forgelens.py cloud azure-collect --output evidence\azure
```

### GCP
```bash
python forgelens.py cloud gcp-snapshot my-disk \
  --project my-project --zone us-central1-a --output evidence\gcp

python forgelens.py cloud gcp-collect my-project --output evidence\gcp
```

### Docker
```bash
python forgelens.py cloud docker-collect --output evidence\docker
python forgelens.py cloud docker-acquire abc123def456 --output evidence\docker
python forgelens.py cloud docker-memory abc123def456 --output evidence\docker
```

### Kubernetes
```bash
python forgelens.py cloud k8s-collect --output evidence\k8s --namespace production
python forgelens.py cloud k8s-collect --output evidence\k8s --all-namespaces
python forgelens.py cloud k8s-timeline --output evidence\k8s --all-namespaces
```

---

## 13. Battlefield Edition — V3.0

### Distributed acquisition

```bash
# Register remote agents
python forgelens.py v3 agent-add http://192.168.1.10:8765 --token secret1 --label DC-01
python forgelens.py v3 agent-add http://192.168.1.11:8765 --token secret2 --label WS-01

# Ping all agents
python forgelens.py v3 ping

# List agents + status
python forgelens.py v3 agents

# Acquire from all online agents simultaneously
python forgelens.py v3 acquire-all \
  --case CASE-2026-001 --examiner "Jane Smith" \
  --task live_response

# Non-blocking (fire and forget)
python forgelens.py v3 acquire-all --case CASE-001 --examiner Alice --async
```

### Immutable evidence ledger

```bash
# Migrate existing chain-of-custody events into the ledger
python forgelens.py v3 ledger CASE-2026-001 --migrate

# View ledger entries
python forgelens.py v3 ledger CASE-2026-001
python forgelens.py v3 ledger CASE-2026-001 --evidence EV-XXXXXXXX

# Verify hash-chain integrity
python forgelens.py v3 ledger CASE-2026-001 --verify

# Export to JSON
python forgelens.py v3 ledger CASE-2026-001 --export ledger.json
```

### AI threat graph

```bash
python forgelens.py v3 graph CASE-2026-001 \
  --output evidence\graph \
  --processes evidence\...\EV-XXXXXXXX.processes.json

# Also export STIX 2.1 bundle for threat intel sharing
python forgelens.py v3 graph CASE-2026-001 \
  --output evidence\graph --stix

# Render the DOT graph (requires Graphviz)
dot -Tpng evidence\graph\CASE-2026-001_threat_graph.dot -o graph.png
```

### Cross-device timeline fusion

```bash
# Fuse multiple device timelines
python forgelens.py v3 timeline-fuse CASE-2026-001 \
  --output evidence\timeline.json \
  --source "DC-01:memory:dc_processes.json" \
  --source "WS-01:events:ws_events.json" \
  --source "AWS:cloud:cloudtrail.json"

# Auto-load from evidence vault
python forgelens.py v3 timeline-fuse CASE-2026-001 --output evidence\timeline.json

# Suspicious events only
python forgelens.py v3 timeline-fuse CASE-2026-001 \
  --output evidence\timeline.json --suspicious
```

### Multi-investigator collaboration

```bash
# Dashboard
python forgelens.py v3 collab CASE-2026-001

# Add a note
python forgelens.py v3 note --case CASE-2026-001 --author alice \
  "Mimikatz found in PID 4432, DLL injection confirmed"

# Add note tied to specific evidence
python forgelens.py v3 note --case CASE-2026-001 --author alice \
  --evidence EV-XXXXXXXX "High entropy section at offset 0x4000"

# Assign a task
python forgelens.py v3 task --case CASE-2026-001 \
  --from alice --to bob "Analyze memory dump EV-XXXXXXXX" \
  --priority high

# Case handoff
python forgelens.py v3 handoff --case CASE-2026-001 \
  --from alice --to bob \
  "IR phase complete. 3 open tasks remain. Pass to legal."
```

---

## 14. API Server

```bash
# Start the REST + SSE server
uvicorn backend.api.server:app --reload --port 8000

# Connect to real-time event stream (SSE)
curl -N http://localhost:8000/api/v3/stream/CASE-2026-001

# Health check
curl http://localhost:8000/api/health
```

---

## 15. Typical Workflows

### Windows incident response
```bash
python forgelens.py case create CASE-2026-001 --examiner "Jane Smith" --title "IR - Workstation"
python forgelens.py acquire windows --case CASE-2026-001 --examiner "Jane Smith" --output evidence\win --memory
python forgelens.py dfir full-triage C:\ --dump evidence\...\EV-XXXXXXXX.raw --output evidence\dfir
python forgelens.py v3 graph CASE-2026-001 --output evidence\graph --stix
python forgelens.py export report --case CASE-2026-001 --evidence EV-XXXXXXXX --formats "html,json"
```

### Android phone investigation
```bash
python forgelens.py case create CASE-2026-002 --examiner "Jane Smith" --title "Mobile - Android"
python forgelens.py acquire detect
python forgelens.py acquire android --case CASE-2026-002 --examiner "Jane Smith" --output evidence\android
python forgelens.py mobile android-recover \
  --case CASE-2026-002 --output evidence\recovery \
  --remote /data/data/com.android.providers.telephony/databases/mmssms.db
```

### Multi-endpoint IR (distributed)
```bash
python forgelens.py case create CASE-2026-003 --examiner "Alice" --title "Enterprise IR"
python forgelens.py v3 agent-add http://192.168.1.10:8765 --token t1 --label DC-01
python forgelens.py v3 agent-add http://192.168.1.11:8765 --token t2 --label DC-02
python forgelens.py v3 agent-add http://192.168.1.12:8765 --token t3 --label FS-01
python forgelens.py v3 ping
python forgelens.py v3 acquire-all --case CASE-2026-003 --examiner Alice --task live_response
python forgelens.py v3 timeline-fuse CASE-2026-003 --output evidence\timeline.json
python forgelens.py v3 ledger CASE-2026-003 --verify
```

### Ransomware response
```bash
python forgelens.py case create CASE-2026-004 --examiner "Bob" --title "Ransomware IR" --priority critical
python forgelens.py dfir ransomware C:\ --output evidence\dfir --max-files 100000
python forgelens.py dfir persist --output evidence\dfir
python forgelens.py dfir creds --dump evidence\...\EV-XXXXXXXX.raw --output evidence\dfir
python forgelens.py v3 ledger CASE-2026-004 --migrate
python forgelens.py v3 ledger CASE-2026-004 --verify
```

---

## 16. Prerequisites by Platform

| Platform | Required | Install |
|---|---|---|
| Windows live | PowerShell (built-in) | — |
| Windows RAM | WinPmem | `python forgelens.py memory setup` |
| Linux live | lsblk, ps (built-in) | — |
| Linux RAM | AVML | `python forgelens.py setup mounter` |
| macOS live | diskutil, system_profiler (built-in) | — |
| Android | ADB | Android Platform Tools |
| iOS | libimobiledevice | `pip install pymobiledevice3` |
| Memory analysis | Volatility3 | `pip install volatility3` (auto) |
| YARA scanning | yara-python | `pip install yara-python` (needs C compiler) |
| E01 imaging | pyewf | `pip install pyewf` (needs libewf-dev) |
| DD mounting (Windows) | ImDisk or AIM | `python forgelens.py setup mounter` |
| Cloud — AWS | aws CLI | `winget install Amazon.AWSCLI` |
| Cloud — Azure | az CLI | `winget install Microsoft.AzureCLI` |
| Cloud — GCP | gcloud CLI | https://cloud.google.com/sdk |
| Containers | docker, kubectl | https://docs.docker.com/get-docker/ |
| Threat graph viz | Graphviz | `winget install Graphviz.Graphviz` |
| STIX sharing | (built-in) | — |
