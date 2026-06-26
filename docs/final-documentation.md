# ForgeLens — Complete Technical Reference

> Full documentation for the Universal Forensic Acquisition Toolkit — v3.0 Battlefield Edition.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Tech Stack](#2-tech-stack)
3. [Architecture](#3-architecture)
4. [Authentication & Access Control](#4-authentication--access-control)
5. [Feature Reference](#5-feature-reference)
6. [CLI Reference](#6-cli-reference)
7. [API Reference](#7-api-reference)
8. [Evidence Vault & Chain of Custody](#8-evidence-vault--chain-of-custody)
9. [Development Phases & Version History](#9-development-phases--version-history)
10. [Installation & Environment Setup](#10-installation--environment-setup)
11. [Configuration](#11-configuration)
12. [Strategic Notes](#12-strategic-notes)

---

## 1. Project Overview

ForgeLens is a professional-grade, open-source Digital Forensics and Incident Response (DFIR) platform. It handles the complete forensic pipeline across every major OS and device type, from a single investigator's workstation to a distributed multi-agent enterprise deployment.

**Competes with:** Cellebrite, Magnet AXIOM, EnCase, FTK, Velociraptor

**Core pipeline:**
```
Acquire → Hash → Verify → Analyze → Report → Collaborate
```

**Supported platforms:** Windows, Linux, macOS, Android, iOS, MS-DOS/FAT, AWS, Azure, GCP, Docker, Kubernetes

**Current version:** v3.0 — Battlefield Edition

**User Documentation:**
- [How-To-Use Guide (Non-Technical)](how-to-use.md) — Step-by-step guide for running investigations, creating cases, and collecting evidence.
- [Showcase Guide (Non-Technical)](showcase_guide.md) — Visual tour of all core modules with screenshots and non-technical explanations.

---

## 2. Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Backend | Python | 3.10+ |
| CLI | Typer + Rich | 0.25.1 / 15.0.0 |
| API | FastAPI + Uvicorn | 0.109.2 / 0.27.1 |
| Config | Pydantic v2 + PyYAML | 2.13.4 / 6.0.3 |
| Logging | Loguru | 0.7.3 |
| Filesystem parsing | pytsk3 | ≥20260418 |
| Memory forensics | Volatility3 | 2.28.0 |
| Encryption | cryptography | ≥44.0.0 |
| Hashing | hashlib + blake3 | stdlib + optional |
| Mobile | adb-shell + pymobiledevice3 | 0.4.4 / optional |
| YARA | yara-python | 4.5.1 (optional) |
| Desktop UI | React + TypeScript + Tauri v2 | 18.3.1 / 5.5.3 / 2.0.0 |
| Linting | Ruff | 0.15.14 |
| Testing | pytest | 8.3.5 |

---

## 3. Architecture

### Module Map

```
backend/core/
├── acquisition/        Device detection, disk enumeration, metadata collector
├── ai/                 Anomaly detector, IOC prioritizer, summarizer, explainer, timeline narrator
├── artifacts/          YARA, IOC matching, entropy, browser/registry/SQLite parsers
├── auth/               CLI authentication gate, session management, brute-force protection
├── chain_of_custody/   Evidence manager, vault crypto, case manager, evidence index
├── dfir/               Offensive DFIR — persistence, beacons, creds, ransomware, lateral
├── enterprise/         SIEM, threat intel, cloud acquisition, case orchestrator
├── hashing/            Multi-algorithm hash engine
├── imaging/            DiskImager (DD/E01), ImageMounter
├── logging/            Loguru structured logging
├── memory/             VolatilityEngine, MemoryTimeline
├── remote/             RemoteAgent, AgentClient, RBACManager, EvidenceSync
├── reporting/          JSON/HTML/Text/PDF reports
├── setup/              Dependency checker and auto-installer
└── v3/                 Battlefield Edition — distributed, ledger, streaming, graph, fusion, collab

platforms/
├── windows/            Registry, event logs, live response, WinPmem memory, enumeration
├── linux/              Block devices, artifacts, AVML/LiME, enumeration
├── macos/              APFS, FileVault, SIP, unified logs, enumeration
├── android/            ADB acquisition, advanced filesystem, SQLite recovery
├── ios/                libimobiledevice, jailbreak workflows, SEP research
└── usb/                USB/removable device detection
```

### Key Design Principles

- **Read-only sources** — source devices never opened for writing
- **Evidence-first** — CoC entry created before any collection begins; failures recorded too
- **Graceful degradation** — optional deps fail silently with clear install hints
- **MITRE ATT&CK throughout** — every detection maps to technique + tactic
- **Offline-first** — no internet required for core functionality

---

## 4. Authentication & Access Control

### Overview

Auth is **disabled by default** — existing workflows are unaffected. Enable explicitly when multi-user or shared-system security is required.

### Roles and Permissions

| Role | Permissions |
|---|---|
| `admin` | All — acquire, image, analyze, report, export, manage cases, manage users, delete evidence, encrypt, memory, remote agents |
| `examiner` | acquire, image, analyze, report, export, manage cases, encrypt, memory, remote agents |
| `analyst` | analyze, report, export (read-only on evidence) |
| `viewer` | view only |

### Security Model

- Passwords: PBKDF2-HMAC-SHA256, 600,000 iterations, per-user random salt
- Session token: `secrets.token_urlsafe(32)` — 256-bit, stored in `evidence/.session`
- Session file: chmod 600, owner-only read
- Session TTL: 8 hours
- Brute-force: 3 failed attempts → 30-second lockout (persisted across process restarts)
- Exempt commands: `auth`, `setup`, `--help`, `version`

### Auth Commands

```bash
python forgelens.py auth enable           # Enable auth (creates admin on first run)
python forgelens.py auth disable          # Disable (confirm required)
python forgelens.py auth login            # Log in, create 8-hour session
python forgelens.py auth logout           # Invalidate session
python forgelens.py auth whoami           # Show current session
python forgelens.py auth status           # Full status + user table
python forgelens.py auth user-add <name> --role examiner
python forgelens.py auth user-remove <name>
python forgelens.py auth user-role <name> admin
python forgelens.py auth passwd <name>
```

---

## 5. Feature Reference

See [features.md](features.md) for the complete annotated feature list.

Summary of major areas:

| Area | Key Capabilities |
|---|---|
| Disk imaging | DD/E01, pause/resume, dual-hash, verification |
| Memory | WinPmem/AVML, Volatility3, 8 plugins |
| Windows | Processes, network, registry, artifacts, RAM |
| Linux | Block devices, LVM, RAID, LUKS, bash history |
| macOS | APFS, FileVault, SIP, unified logs |
| Android | ADB + full filesystem + SQLite recovery |
| iOS | Backup, AFC, jailbreak, SEP research |
| Cloud | AWS/Azure/GCP/Docker/Kubernetes |
| DFIR | Persistence, beacons, creds, ransomware, lateral |
| AI | Anomaly detection, IOC scoring, threat graph |
| V3.0 | Distributed agents, ledger, timeline fusion, SSE, collab |
| Auth | Password gate, RBAC, sessions, brute-force protection |

---

## 6. CLI Reference

See [cli-usage.md](cli-usage.md) for the complete command reference.

### Top-level commands

```
python forgelens.py
├── auth          Authentication (enable/disable/login/logout/users)
├── setup         Dependency check + install
├── acquire       Platform acquisition (windows/linux/macos/android/ios/msdos)
├── devices       List connected devices
├── enumerate     Show partition layout
├── image         Disk imaging (acquire/mount/unmount/mounts)
├── hash          File hashing and verification
├── memory        RAM acquisition + Volatility3 analysis
├── case          Case management (create/list/update/search/audit)
├── vault         Evidence vault (tag/search/index/repair/encrypt/decrypt)
├── export        Reports and chain of custody
├── dfir          Offensive DFIR (persist/beacons/creds/ransomware/lateral/full-triage)
├── mobile        Advanced mobile (android-*/ios-*)
├── cloud         Cloud/container forensics (aws/azure/gcp/docker/k8s)
├── v3            Battlefield Edition (agents/ledger/graph/timeline-fuse/collab)
└── version       Show version
```

---

## 7. API Reference

Start the server:
```bash
uvicorn backend.api.server:app --reload --port 8000
```

### Core endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Server health + version |
| GET | `/api/devices` | List connected devices |

### V3 endpoints (30+)

| Method | Path | Description |
|---|---|---|
| GET | `/api/v3/stream/{case_id}` | SSE real-time stream for case |
| GET | `/api/v3/stream/global` | SSE global stream |
| GET | `/api/v3/stream/history/{case_id}` | Event history for reconnect |
| GET | `/api/v3/cases` | List all cases |
| POST | `/api/v3/cases` | Create case |
| GET | `/api/v3/cases/{id}` | Case detail with evidence and assignments |
| PATCH | `/api/v3/cases/{id}` | Update case |
| GET | `/api/v3/cases/{id}/evidence` | List evidence items |
| GET | `/api/v3/cases/{id}/evidence/{eid}/custody` | Chain of custody |
| GET | `/api/v3/cases/{id}/ledger` | Immutable ledger entries |
| POST | `/api/v3/cases/{id}/ledger/verify` | Verify hash-chain integrity |
| POST | `/api/v3/cases/{id}/ledger/migrate` | Migrate CoC to ledger |
| GET | `/api/v3/cases/{id}/graph` | Threat graph JSON |
| GET | `/api/v3/cases/{id}/graph.dot` | Threat graph Graphviz DOT |
| GET | `/api/v3/cases/{id}/graph.stix` | STIX 2.1 bundle |
| GET | `/api/v3/cases/{id}/timeline` | Fused cross-device timeline |
| GET | `/api/v3/cases/{id}/collab` | Collaboration dashboard |
| POST | `/api/v3/cases/{id}/collab/notes` | Add note |
| GET | `/api/v3/cases/{id}/collab/notes` | Get notes |
| POST | `/api/v3/cases/{id}/collab/tasks` | Assign task |
| GET | `/api/v3/cases/{id}/collab/tasks` | Get tasks |
| PATCH | `/api/v3/cases/{id}/collab/tasks/{tid}` | Update task status |
| POST | `/api/v3/cases/{id}/collab/annotate` | Annotate evidence |
| POST | `/api/v3/cases/{id}/collab/handoff` | Case handoff |
| GET | `/api/v3/agents` | List distributed agents |
| POST | `/api/v3/agents` | Register agent |
| POST | `/api/v3/agents/ping` | Ping all agents |
| POST | `/api/v3/agents/acquire` | Distributed acquisition |
| GET | `/api/v3/agents/jobs/{job_id}` | Job status + report |

---

## 8. Evidence Vault & Chain of Custody

### Directory structure

```
evidence/cases/<case_id>/<evidence_id>/
├── metadata.json              Full acquisition metadata
├── chain_of_custody.json      Append-only event log
├── ledger.jsonl               Immutable hash-chain (v3.0)
├── acquisition.log            Free-text log
├── tags.json                  Evidence tags
├── <evidence_id>.<ext>        Image/dump file
├── <evidence_id>.<ext>.hashes SHA256/MD5/SHA1 manifest
├── report_<id>.html           HTML report
├── report_<id>.json           JSON report
└── collab/
    ├── notes.json
    ├── tasks.json
    ├── annotations.json
    └── activity_feed.json
```

### Evidence object schema

```json
{
  "evidence_id": "EV-5758DA1C",
  "case_id": "CASE-2026-001",
  "session_id": "uuid",
  "examiner": "Alice",
  "timestamp_utc": "2026-06-01T16:15:57+00:00",
  "acquisition_method": "physical",
  "tool_version": "ForgeLens 3.0.0",
  "notes": "Workstation seized per warrant #2026-0042",
  "geo_location": "Lab Room 3",
  "device": {
    "device_id": "\\\\.\\PhysicalDrive0",
    "model": "Samsung 970 EVO 1TB",
    "serial": "S4EVNX0M123456",
    "interface": "NVMe",
    "size_bytes": 1000204886016
  },
  "hash_sha256": "8befb629...",
  "hash_md5": "d3b1994f...",
  "hash_sha1": "5ad3331b...",
  "acquisition_start": "2026-06-01T16:15:57+00:00",
  "acquisition_end": "2026-06-01T17:32:14+00:00",
  "duration_seconds": 4577.0,
  "bytes_acquired": 1000204886016,
  "output_path": "evidence/cases/CASE-2026-001/EV-5758DA1C/EV-5758DA1C.dd",
  "verified": true
}
```

### Chain of custody event types

| Event | Meaning |
|---|---|
| `created` | Evidence entry created, acquisition started |
| `verified` | Integrity check passed |
| `integrity_failed` | SHA256 mismatch — possible tampering |
| `failed` | Acquisition failed (error recorded in notes) |
| `tagged` | Tags added or updated |
| `repaired` | metadata.json reconstructed by vault repair |
| `mounted` | Image mounted read-only |
| `unmounted` | Image unmounted |
| `exported` | Report generated |
| `transferred` | Custody transferred to another examiner |

---

## 9. Development Phases & Version History

See [dev-phases.md](dev-phases.md) for the full phase-by-phase history.

| Version | Milestone |
|---|---|
| v0.1 | Foundation — CLI, logging, config, device detection |
| v0.2 | Disk imaging engine + hashing |
| v0.3 | Windows acquisition + artifacts |
| v0.4 | Linux acquisition + artifacts |
| v0.5 | macOS support |
| v0.6 | External storage + USB |
| v0.7 | Android acquisition |
| v0.8 | iOS acquisition |
| v0.9 | Evidence management system |
| v1.0 | GUI scaffolding |
| v1.1 | Memory forensics + Volatility3 |
| v1.2 | Artifact intelligence (YARA, IOC, entropy) |
| v1.3 | Remote acquisition agents |
| v1.4 | AI-assisted analysis |
| v2.0 | Enterprise platform (SIEM, threat intel, RBAC) |
| v2.1 | Cloud & container forensics |
| v2.2 | Advanced mobile forensics |
| v2.3 | Offensive DFIR features |
| v3.0 | Battlefield Edition (distributed, ledger, graph, streaming, collab, auth) |

---

## 10. Installation & Environment Setup

See [install.md](install.md) for the complete step-by-step guide.

### Quick start

```bash
git clone https://github.com/your-org/forgelens.git
cd forensic-toolkit
python -m venv .pyenv
.pyenv\Scripts\activate      # Windows
pip install -r backend/requirements.txt
python forgelens.py setup check
python forgelens.py version
```

### Required tools by platform

| Platform | Tool | How to get |
|---|---|---|
| Windows RAM | WinPmem | `python forgelens.py memory setup` |
| Windows mount | ImDisk | `python forgelens.py setup mounter` |
| Linux RAM | AVML | `python forgelens.py setup mounter` |
| Android | ADB | Android Platform Tools |
| iOS | libimobiledevice | `pip install pymobiledevice3` |
| Memory analysis | Volatility3 | included in requirements.txt |
| YARA | yara-python | `pip install yara-python` (needs C compiler) |

---

## 11. Configuration

### settings.yaml (defaults)

```yaml
app:
  name: ForgeLens
  version: 3.0.0
  debug: false

evidence:
  base_path: ./evidence
  hash_algorithm: sha256

logging:
  level: INFO
  log_dir: ./backend/logs

acquisition:
  block_size: 65536
  threads: 4

features:
  disabled:
    - v3
    - cloud
    - dfir
```

### Feature Hiding & Customization

You can hide specific CLI subcommand groups and Desktop GUI tabs by adding them to the `features.disabled` list.
- **CLI Subcommands**: Hiding a feature (e.g. `v3`) prevents it from registering on the Typer `app`. The commands will be hidden from the CLI help page (`python forgelens.py --help`).
- **GUI Views**: Hiding a feature removes the tab from the sidebar, skips view initialization, hides associated quick actions on the Dashboard, and updates the Capability Matrix checkmarks to reflect the disabled status.
```

### .env overrides

```ini
SECRET_KEY=your-secret-key-here
EVIDENCE__BASE_PATH=/mnt/evidence
LOGGING__LEVEL=DEBUG
ACQUISITION__BLOCK_SIZE=131072
APP__DEBUG=false
```

### Key files

| File | Purpose |
|---|---|
| `evidence/users.json` | PBKDF2-hashed user credentials |
| `evidence/.session` | Active session (chmod 600) |
| `evidence/.auth_enabled` | Auth gate toggle |
| `evidence/case_registry.json` | Case index |
| `evidence/evidence_index.json` | Evidence search index |
| `.env` | Environment overrides (gitignored) |

---

## 12. Strategic Notes

### Build Order Priority

1. Reliable acquisition engine — if this is wrong, everything downstream is evidence
2. Integrity verification — every byte accounted for before analysis begins
3. Chain of custody — courtroom-grade audit trail
4. Platform parsers — Windows first for density, then Linux/macOS/mobile
5. Analysis and AI — built on top of solid acquisition foundation
6. Enterprise and distribution — scale last, not first

### Competitive Positioning

ForgeLens differentiates from commercial tools by being:

- **Open and auditable** — source is transparent, plugins are extensible
- **Cross-platform from day one** — not Windows-centric
- **AI-native** — analysis assistance built into the pipeline, not bolted on
- **Enterprise-ready** — RBAC, distributed agents, immutable ledger, SIEM integration
- **Offline-capable** — no phone-home required

### The Non-Negotiables

Every acquisition must produce:
1. A byte-perfect image with verified hash
2. An immutable chain of custody record
3. A tamper-evident metadata manifest
4. A human-readable acquisition report

Without all four, the evidence is not courtroom-grade.

---

*Last updated: June 2026 — ForgeLens v3.0 Battlefield Edition*
