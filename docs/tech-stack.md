# ForgeLens — Tech Stack

All technology decisions, versions, and rationale.

---

## Core Backend

| Component | Technology | Version | Notes |
|---|---|---|---|
| Language | Python | 3.10+ | Main backend language |
| CLI framework | Typer | 0.25.1 | Auto-generates help, completions |
| Terminal output | Rich | 15.0.0 | Tables, progress bars, colors |
| Logging | Loguru | 0.7.3 | Structured, rotating, JSON logs |
| System info | psutil | 7.2.2 | RAM, CPU, disk, processes |
| Config | PyYAML + pydantic-settings | 6.0.3 / 2.14.1 | YAML defaults + env var overlay |
| Data validation | Pydantic | 2.13.4 | Evidence models, API schemas |
| Env files | python-dotenv | 1.2.2 | .env loading |

---

## Forensics Libraries

| Component | Technology | Version | Notes |
|---|---|---|---|
| Filesystem parsing | pytsk3 | ≥20260418 | Python bindings for The Sleuth Kit |
| Memory forensics | Volatility3 | 2.28.0 | Process, network, credential analysis |
| Encryption | cryptography | ≥44.0.0 | AES-256-GCM, PBKDF2, HMAC-SHA256 |
| YARA scanning | yara-python | 4.5.1 | Optional, needs C compiler on Windows |
| E01 imaging | pyewf | — | Optional, needs libewf-dev |
| BLAKE3 hashing | blake3 | — | Optional, pure Python fallback |
| PDF reports | reportlab | — | Optional |
| Backup decryption | iphone-backup-decrypt | — | Optional, iOS backups |

---

## Mobile

| Component | Technology | Version | Notes |
|---|---|---|---|
| Android | adb-shell | 0.4.4 | ADB Python library |
| Android | adb (binary) | — | Android Platform Tools |
| iOS | libimobiledevice | — | idevicebackup2, ideviceinfo, etc. |
| iOS | pymobiledevice3 | 4.14.16 | Python fallback, needs MSVC on Windows |

---

## API Server

| Component | Technology | Version | Notes |
|---|---|---|---|
| REST framework | FastAPI | 0.109.2 | Async, OpenAPI docs auto-generated |
| ASGI server | Uvicorn | 0.27.1 | Production-ready ASGI |
| Real-time | SSE (Server-Sent Events) | built-in | Via FastAPI StreamingResponse |

---

## Frontend (Desktop UI)

| Component | Technology | Version | Notes |
|---|---|---|---|
| UI framework | React | 18.3.1 | Component-based UI |
| Language | TypeScript | 5.5.3 | Type safety |
| Build tool | Vite | 5.4.2 | Fast dev server |
| Desktop shell | Tauri | v2.0.0 | Native desktop app (Rust backend) |
| Styling | Tailwind CSS | 3.4.11 | Utility-first CSS |
| Charts | Recharts | 2.12.7 | Forensic timeline/graph visualization |
| Icons | Lucide React | 0.441.0 | Icon library |

---

## Authentication

| Component | Technology | Notes |
|---|---|---|
| Password hashing | PBKDF2-HMAC-SHA256 | 600,000 iterations, per-user salt |
| Session tokens | secrets.token_urlsafe(32) | 256-bit cryptographically secure |
| Session storage | Local JSON file | chmod 600, current user only |
| Brute-force protection | Lockout file | 3 attempts → 30s lockout |
| HMAC signing | hmac + hashlib.sha256 | Evidence metadata signing |

---

## Development & Tooling

| Component | Technology | Version | Notes |
|---|---|---|---|
| Linting | Ruff | 0.15.14 | Fast Python linter + formatter |
| Testing | pytest | 8.3.5 | Unit and integration tests |
| Pre-commit | pre-commit | 4.6.0 | Git hook enforcement |
| Containerization | Docker | — | Dockerfile + docker-compose.yml |

---

## Memory Acquisition Tools

| Platform | Tool | License | Notes |
|---|---|---|---|
| Windows | WinPmem | AGPL | Auto-downloaded via `memory setup` |
| Windows | DumpIt | Freeware | Alternative, place in tools/ |
| Linux | AVML | MIT | Preferred, no kernel module needed |
| Linux | LiME | GPL | Kernel module, compile per kernel |

---

## Disk Mount Tools

| Platform | Tool | License | Notes |
|---|---|---|---|
| Windows | Arsenal Image Mounter | AGPL | Supports E01/AFF/VHD/DD — aim_cli.exe |
| Windows | ImDisk | GPL | DD/RAW, auto-install via winget |
| Windows | PowerShell Mount-DiskImage | Built-in | VHD/VHDX/ISO only |
| Linux | loopback + mount | Built-in kernel | DD/RAW, no extra tools |
| macOS | hdiutil | Built-in | DMG/IMG/ISO |

---

## Cloud CLIs (optional)

| Cloud | CLI | Install |
|---|---|---|
| AWS | aws | `winget install Amazon.AWSCLI` |
| Azure | az | `winget install Microsoft.AzureCLI` |
| GCP | gcloud | https://cloud.google.com/sdk |
| Docker | docker | https://docs.docker.com/get-docker/ |
| Kubernetes | kubectl | `winget install Kubernetes.kubectl` |

---

## Database

| Component | Technology | Notes |
|---|---|---|
| Primary storage | Flat JSON files | Evidence vault, case registry, evidence index |
| Optional DB | SQLite | Configured in settings, not yet wired to ORM |
| Optional DB | PostgreSQL 16 | Available in docker-compose.yml |

SQLite/PostgreSQL are configured but the primary storage is flat JSON files in the evidence vault. The database layer is a future migration target.

---

## Architecture Decisions

### Why flat JSON over a database?
Evidence vault files are forensic artifacts themselves. Flat JSON is transparent, human-readable, git-diffable, and trivially portable — no database daemon needed. The trade-off is no concurrent write safety, which is acceptable for single-investigator or careful multi-user use.

### Why Python over Rust for imaging?
The imaging hotpath (`imager.py`) is already I/O-bound — the bottleneck is disk read speed, not CPU. Python adds negligible overhead. Rust was in the original plan but the cost/benefit didn't justify it given Volatility3, pytsk3, and the full forensic stack are Python-native.

### Why FastAPI + SSE instead of WebSockets?
SSE is simpler (HTTP), firewall-friendly, and sufficient for unidirectional server→client streaming (progress, alerts). WebSockets would only be needed for bidirectional real-time interaction, which isn't required for the current use cases.

### Why Tauri over Electron?
Smaller binary, lower RAM footprint, Rust-native security model. The frontend is pure React — Tauri is just the shell.
