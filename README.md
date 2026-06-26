# ForgeLens — Universal Forensic Acquisition Toolkit

> Professional-grade, open-source DFIR platform. Acquire, verify, analyze, and report on digital evidence across every major platform — Windows, Linux, macOS, Android, iOS, MS-DOS, cloud, and containers.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![Volatility3](https://img.shields.io/badge/memory-Volatility3-orange)](https://github.com/volatilityfoundation/volatility3)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What is ForgeLens?

ForgeLens is a full-spectrum DFIR toolkit built to compete with Cellebrite, Magnet AXIOM, EnCase, and FTK — completely open source. It covers the complete forensic pipeline:

```
Acquire → Hash → Verify → Analyze → Report → Collaborate
```

From imaging a single hard drive to coordinating distributed IR across a hundred endpoints.

---

## Feature Matrix

| Capability | Status |
|---|---|
| Disk imaging (DD/E01) | ✅ |
| Multi-algorithm hashing (SHA256/MD5/SHA1/BLAKE3) | ✅ |
| Windows live acquisition + artifacts | ✅ |
| Linux acquisition + RAM (AVML/LiME) | ✅ |
| macOS acquisition (APFS, FileVault) | ✅ |
| Android logical + full filesystem | ✅ |
| iOS backup extraction + jailbreak | ✅ |
| MS-DOS/FAT legacy disk imaging | ✅ |
| Memory forensics (Volatility3) | ✅ |
| Chain of custody + tamper-evident vault | ✅ |
| AES-256-GCM evidence encryption | ✅ |
| YARA scanning | ✅ |
| IOC detection + VirusTotal integration | ✅ |
| Persistence hunting | ✅ |
| Beacon detection | ✅ |
| Credential theft detection | ✅ |
| Ransomware triage | ✅ |
| Lateral movement mapping | ✅ |
| AWS/Azure/GCP cloud acquisition | ✅ |
| Docker/Kubernetes container forensics | ✅ |
| Distributed multi-agent acquisition | ✅ |
| Immutable hash-chain evidence ledger | ✅ |
| AI threat graph (JSON/DOT/STIX 2.1) | ✅ |
| Cross-device timeline fusion | ✅ |
| Real-time SSE streaming API | ✅ |
| Multi-investigator collaboration | ✅ |
| SIEM integration (Splunk/Elastic/syslog) | ✅ |
| MITRE ATT&CK mapping throughout | ✅ |
| Password-protected CLI (auth gate) | ✅ |
| Role-based access control (admin/examiner/analyst/viewer) | ✅ |

---

## Quick Start

### 1. Clone and set up the environment

```bash
git clone https://github.com/your-org/forgelens.git
cd forgelens
python -m venv .pyenv
.pyenv\Scripts\activate          # Windows
# source .pyenv/bin/activate     # Linux/macOS
pip install -r backend/requirements.txt
```

### 2. Check dependencies

```
python forgelens.py setup check
```

### 3. Run your first acquisition

```bash
# List connected devices
python forgelens.py devices

# Acquire a disk image
python forgelens.py image acquire --source "\\.\PhysicalDrive0" \
  --output evidence --case CASE-2026-001 --examiner "Your Name"

# Acquire RAM (Windows, run as Administrator)
python forgelens.py memory setup   # download WinPmem once
python forgelens.py memory acquire --output evidence\memory.raw \
  --case CASE-2026-001 --examiner "Your Name"
```

### 4. (Optional) Enable authentication

Auth is off by default. Enable it when multiple people share the system:

```bash
# Enable — prompts to create an admin account
python forgelens.py auth enable

# Log in (required after enable)
python forgelens.py auth login

# Add more users
python forgelens.py auth user-add bob --role examiner
```

### 5. (Optional) Customizing Active Features

You can hide specific tabs and command groups (e.g. `v3`, `cloud`, `dfir`, `memory`) by customizing `backend/configs/settings.yaml`. Under the `features` block:

```yaml
features:
  disabled:
    - v3
    - cloud
    - dfir
```

This will automatically omit the corresponding commands from the CLI help menus (`python forgelens.py --help`) and remove their navigation panels and related quick actions from the Desktop GUI.

---

## Project Structure

```
forensic-toolkit/
├── backend/
│   ├── api/                  FastAPI REST + SSE server
│   ├── cli/                  Typer CLI (main.py)
│   ├── configs/              settings.yaml + .env.example
│   └── core/
│       ├── acquisition/      Device detection, metadata
│       ├── ai/               Anomaly detection, IOC scoring, timeline narration
│       ├── artifacts/        YARA, IOC matching, entropy, persistence
│       ├── chain_of_custody/ Evidence vault, crypto, case management
│       ├── dfir/             Offensive DFIR — persistence, beacons, ransomware, lateral
│       ├── enterprise/       SIEM, threat intel, cloud acquisition, orchestration
│       ├── hashing/          SHA256/MD5/SHA1/BLAKE3
│       ├── imaging/          DD/E01 imager, disk mounter
│       ├── logging/          Loguru structured logging
│       ├── memory/           Volatility3 integration + timeline
│       ├── remote/           Agent, agent client, RBAC, sync
│       ├── reporting/        JSON/HTML/Text/PDF reports
│       ├── setup/            Dependency checker + installer
│       └── v3/               Battlefield Edition modules
│           ├── distributed.py   Multi-agent acquisition coordinator
│           ├── ledger.py        Immutable hash-chain ledger
│           ├── threat_graph.py  AI threat graph (JSON/DOT/STIX)
│           ├── timeline_fusion.py Cross-device timeline fusion
│           ├── streaming.py     Real-time SSE broker
│           └── collaboration.py Multi-investigator workspace
├── platforms/
│   ├── windows/              Registry, event logs, live response, memory
│   ├── linux/                Block devices, artifacts, AVML/LiME
│   ├── macos/                APFS, FileVault, unified logs
│   ├── android/              ADB acquisition + advanced filesystem
│   ├── ios/                  libimobiledevice + jailbreak workflows
│   └── usb/                  USB/removable device detection
├── plugins/
│   └── yara_rules/           Place .yar files here
├── tools/                    Third-party binaries (WinPmem, etc.)
├── evidence/                 Runtime evidence vault (gitignored)
└── docs/                     Documentation
```

---

## CLI Command Tree

```
python forgelens.py
├── devices                   List all physical storage devices
├── enumerate <device>        Show partition layout
│
├── setup
│   ├── check                 Check all dependencies
│   ├── install               Auto-install missing dependencies
│   ├── mounter               Download disk mount tools
│   └── info                  Full tool reference
│
├── acquire                   Platform-specific acquisition
│   ├── windows               Live Windows system artifacts + RAM
│   ├── linux                 Live Linux system artifacts + RAM
│   ├── macos                 macOS APFS + artifacts
│   ├── android               Android via ADB
│   ├── ios                   iOS via libimobiledevice
│   ├── msdos                 MS-DOS/FAT legacy disk
│   └── detect                Detect all connected devices
│
├── image
│   ├── acquire               Sector-by-sector disk imaging (DD/E01)
│   ├── mount                 Mount image read-only for analysis
│   ├── unmount               Unmount an image
│   └── mounts                List active mounts
│
├── hash
│   ├── file                  Hash a file (sha256/md5/sha1/blake3)
│   └── verify                Verify against a known hash
│
├── memory
│   ├── setup                 Download WinPmem
│   ├── acquire               Acquire live RAM (Windows)
│   ├── processes             List processes from dump
│   ├── dlls                  List DLLs from dump
│   ├── connections           Network connections from dump
│   ├── malfind               Detect injected code
│   ├── hashes                Extract NTLM hashes
│   ├── timeline              Build memory timeline
│   └── export                Export processes/connections to JSON
│
├── case
│   ├── create                Create a new case
│   ├── list                  List cases
│   ├── update                Update case status
│   ├── search                Search cases
│   └── audit                 Full case audit trail
│
├── vault
│   ├── tag                   Tag evidence items
│   ├── search                Search evidence index
│   ├── index                 Rebuild search index
│   ├── repair                Reconstruct missing metadata.json
│   ├── encrypt               AES-256-GCM file encryption
│   ├── decrypt               Decrypt evidence file
│   └── verify-sig            Verify HMAC-signed metadata
│
├── export
│   ├── report                Generate HTML/JSON/Text reports
│   └── custody               Print chain of custody
│
├── dfir                      Offensive DFIR (v2.3)
│   ├── persist               Hunt persistence mechanisms
│   ├── beacons               Detect C2 beaconing
│   ├── creds                 Detect credential theft
│   ├── ransomware            Ransomware triage
│   ├── lateral               Map lateral movement
│   └── full-triage           Run all DFIR modules
│
├── mobile                    Advanced mobile forensics (v2.2)
│   ├── android-filesystem    Full Android filesystem extraction
│   ├── android-recover       SQLite deleted record recovery
│   ├── android-keystore      Keystore/TEE enumeration
│   ├── android-deep          Deep artifact collection
│   ├── ios-filesystem        Full iOS filesystem extraction
│   ├── ios-keychain          iOS keychain extraction
│   ├── ios-sep               SEP/keybag research document
│   ├── ios-decrypt           Decrypt encrypted iTunes backup
│   └── ios-crashes           Collect crash logs
│
├── cloud                     Cloud & container forensics (v2.1)
│   ├── aws-snapshot          EBS volume snapshot
│   ├── aws-collect           AWS IAM/EC2/VPC/CloudTrail artifacts
│   ├── azure-disk            Azure managed disk SAS access
│   ├── azure-collect         Azure VM/NSG/Activity Log artifacts
│   ├── gcp-snapshot          GCP persistent disk snapshot
│   ├── gcp-collect           GCP instances/IAM/audit logs
│   ├── docker-collect        Docker host inventory
│   ├── docker-acquire        Container filesystem + logs
│   ├── docker-memory         Container memory (Linux)
│   ├── k8s-collect           Kubernetes artifacts
│   └── k8s-timeline          Kubernetes cluster timeline
│
└── v3                        Battlefield Edition (v3.0)
    ├── agents                List distributed agents
    ├── agent-add             Register a remote agent
    ├── ping                  Ping all agents
    ├── acquire-all           Distribute acquisition across agents
    ├── ledger                View/verify immutable evidence ledger
    ├── graph                 Build AI threat graph
    ├── timeline-fuse         Cross-device timeline fusion
    ├── collab                Collaboration dashboard
    ├── note                  Add investigator note
    ├── task                  Assign task to investigator
    └── handoff               Formal case handoff
```

---

## API

Start the REST + SSE server:

```bash
uvicorn backend.api.server:app --reload --port 8000
```

Key endpoints:

| Endpoint | Description |
|---|---|
| `GET /api/health` | Server health + version |
| `GET /api/devices` | List connected devices |
| `GET /api/v3/stream/{case_id}` | SSE real-time event stream |
| `GET /api/v3/cases` | List all cases |
| `POST /api/v3/cases` | Create case |
| `GET /api/v3/cases/{id}/evidence` | List evidence |
| `GET /api/v3/cases/{id}/ledger` | Immutable ledger |
| `POST /api/v3/cases/{id}/ledger/verify` | Verify chain integrity |
| `GET /api/v3/cases/{id}/graph` | Threat graph JSON |
| `GET /api/v3/cases/{id}/graph.dot` | Threat graph (Graphviz) |
| `GET /api/v3/cases/{id}/graph.stix` | STIX 2.1 bundle |
| `GET /api/v3/cases/{id}/timeline` | Fused timeline |
| `GET /api/v3/cases/{id}/collab` | Collaboration dashboard |
| `POST /api/v3/agents/acquire` | Distributed acquisition |

---

## Documentation

| File | Description |
|---|---|
| [docs/showcase_guide.md](docs/showcase_guide.md) | Non-technical showcase guide with screenshots |
| [docs/how-to-use.md](docs/how-to-use.md) | Step-by-step user guide for non-technical users |
| [docs/install.md](docs/install.md) | Full tool installation guide |
| [docs/cli-usage.md](docs/cli-usage.md) | Complete CLI reference |
| [docs/features.md](docs/features.md) | Annotated feature list |
| [docs/dev-phases.md](docs/dev-phases.md) | Development phase history |
| [docs/tech-stack.md](docs/tech-stack.md) | Technology decisions |
| [docs/walkthrough.md](docs/walkthrough.md) | Architecture walkthrough |
| [docs/final-documentation.md](docs/final-documentation.md) | Complete technical reference |
| [docs/todo](docs/todo) | Version task tracker |

---

## License

MIT — see [LICENSE](LICENSE).

---

> "Acquire → Hash → Verify → Export → Analyze. That pipeline is the spine of the entire platform."
