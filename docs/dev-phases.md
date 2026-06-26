# ForgeLens — Development Phases

Complete record of every development phase from foundation to Battlefield Edition.

---

## Phase 0 — Foundation Setup ✅

**Goal:** Build the skeleton before adding complexity.

- Monorepo structure with backend / frontend / platforms / tools / docs
- Git branching strategy, .gitignore, pre-commit hooks (Ruff)
- Python virtual environment (.pyenv)
- Loguru structured logging with rotating file output
- Pydantic + PyYAML + python-dotenv configuration manager
- Module boundary definitions
- Evidence object schema
- Acquisition pipeline skeleton
- Error-handling framework

---

## Phase 1 — Core Imaging Engine ✅

**Goal:** The heart of the platform. If this fails, everything fails.

- Physical disk enumeration (Windows WMI, Linux lsblk, macOS diskutil)
- BitLocker, LVM, RAID, LUKS, APFS detection
- Raw sector reader with configurable block size
- Chunked read/write with threading events
- Pause / resume / cancel support
- Real-time dual-algorithm hashing (SHA256 + MD5 in single pass)
- Read-only enforcement on source devices
- Throughput and progress tracking
- Post-acquisition verification
- RAW/DD export
- E01 export (via pyewf)
- Evidence metadata model (AcquisitionMetadata, DeviceMetadata)
- Evidence directory structure (`evidence/cases/<case_id>/<evidence_id>/`)

---

## Phase 2 — Chain of Custody + Logging ✅

**Goal:** Transform "copy tool" into "forensic platform."

- Unique evidence ID generation (EV-XXXXXXXX)
- Examiner tracking and geo-location logging
- Append-only chain of custody JSON event log
- HMAC-SHA256 signed metadata for tamper detection
- Hash manifest sidecar files
- Acquisition audit log per session
- JSON, HTML, and Text report generation
- PDF reports via reportlab
- Evidence index with full-text search
- Tags system
- Case registry with status, priority, examiner, notes

---

## Phase 3 — Windows Artifact Engine ✅

**Goal:** Start artifact intelligence. Windows gives maximum forensic density.

- Registry hive parsing
- Registry run key collection
- Event log (EVTX) parsing via PowerShell
- Login activity extraction (4624/4625/4648)
- PowerShell activity extraction
- Prefetch parser
- Browser history (Chrome, Firefox, Edge) via SQLite
- Scheduled task enumeration
- Windows version and system info collection
- Partition layout enumeration with BitLocker status
- Shadow copy enumeration

---

## Phase 4 — Linux + macOS Artifacts ✅

**Goal:** Expand platform intelligence.

**Linux:**
- Block device enumeration (lsblk)
- LVM volume detection (lvs)
- RAID array detection (/proc/mdstat)
- Encrypted partition detection (LUKS)
- Bash history, SSH keys, crontabs
- Syslog, auth.log, journalctl
- Docker container artifact collection

**macOS:**
- APFS container and volume enumeration
- FileVault and SIP status
- T2 / Apple Silicon detection
- Unified log collection
- Safari history parsing
- Keychain metadata
- LaunchAgents / LaunchDaemons enumeration
- APFS snapshot listing
- Time Machine artifact collection

---

## Phase 5 — Memory Acquisition ✅

**Goal:** Volatile data acquisition — elite-tier DFIR territory.

- WinPmem integration for Windows RAM acquisition
  - Auto-download via `python forgelens.py memory setup`
  - Exit code 1 tolerance (WinPmem quirk)
- AVML integration for Linux (no kernel module required)
- LiME kernel module support for Linux
- Chain of custody integration for memory dumps
- Post-acquisition hash verification
- Volatility3 integration via subprocess wrapper
  - Plain-text renderer (resilient to `_MM_SESSION_SPACE` symbol errors on Win11 24H2)
  - Windows pslist, pstree, dlllist, netstat, malfind, hashdump, SSDT
  - Suspicious process enrichment
  - Memory timeline reconstruction
- Process/connection export to JSON for YARA/VirusTotal analysis
- 30-minute subprocess timeout for large dumps

---

## Phase 6 — Mobile Forensics ✅

**Goal:** The battlefield shifts to phones.

**Android:**
- ADB device detection with manufacturer/model/Android version
- Root detection via uid=0 check
- Installed app inventory
- SMS, contacts, call log extraction (root)
- Media file pull (DCIM, Pictures, Downloads)
- APK extraction (up to 50)
- WhatsApp database extraction (root)

**iOS:**
- idevice_id + ideviceinfo detection
- pymobiledevice3 fallback detection
- Full iTunes backup via idevicebackup2
- AFC media partition access via ifuse
- Syslog collection
- Jailbreak detection (Cydia/Sileo)

---

## Phase 7 — Evidence Management System ✅ (v0.9)

**Goal:** Evidence vault, search, tagging, chain of custody, case management.

- EvidenceManager with directory structure management
- EvidenceIndex for fast search across all evidence
- CaseManager with status/priority/tags/notes/evidence linking
- CaseOrchestrator for multi-examiner assignment
- vault tag, vault search, vault index, vault repair commands
- AES-256-GCM file encryption and decryption
- PBKDF2 key derivation from password
- HMAC-signed metadata verification

---

## Phase 8 — Memory Forensics Deep Dive ✅ (v1.1)

**Goal:** Full Volatility3 integration with production-grade reliability.

- VolatilityEngine with auto-detection of vol3/vol/volatility3
- All major Volatility3 plugins wired
- Text renderer approach (avoids JSON abort on symbol errors)
- Columnar text output parser
- Memory timeline builder with process + network events
- `memory export` command for YARA/VirusTotal pipeline
- Symbol pack documentation and download guide
- Volatility3 2.28.0 upgrade for Windows 11 24H2 support

---

## Phase 9 — Artifact Intelligence Engine ✅ (v1.2)

**Goal:** YARA, IOC matching, entropy analysis, persistence detection.

- YARA rule scanning via yara-python
- Shannon entropy analysis (packed/encrypted detection)
- IOC extraction (IPs, domains, URLs, hashes, emails)
- Known-bad hash/domain/IP matching
- Windows persistence detection (run keys, scheduled tasks, startup folders)
- SQLite parser for mobile databases
- Browser history parser
- EXIF metadata parser
- Registry parser
- IOC prioritization engine (P1–P4 scoring)

---

## Phase 10 — Remote Acquisition ✅ (v1.3)

**Goal:** Secure agent-based remote acquisition.

- RemoteAgent HTTP server with HMAC-SHA256 authentication
- AgentClient with ping, live response, imaging, artifact collection, memory tasks
- EvidenceSync for vault push/pull and integrity verification
- Sync manifest tracking
- Vault integrity audit

---

## Phase 11 — AI-Assisted Analysis ✅ (v1.4)

**Goal:** DFIR copilot — triage, summarize, narrate.

- Behavioral anomaly detector with MITRE ATT&CK mapping
- IOC prioritizer with P1–P4 scoring and recommended actions
- Evidence summarizer (acquisition, artifacts, cases)
- Optional LLM augmentation via Ollama/OpenAI-compatible endpoint
- Timeline narrator — attack phase detection, kill chain narration
- Activity explainer — plain-English process/IOC/persistence explanations

---

## Phase 12 — Enterprise DFIR Platform ✅ (v2.0)

**Goal:** Scale beyond single-machine analysis.

- Role-based access control (admin/examiner/analyst/viewer)
- PBKDF2-hashed user management
- SIEM integration: Splunk HEC, Elasticsearch/OpenSearch, syslog CEF, generic HTTP
- Threat intelligence feeds: MISP, OTX, generic JSON with local cache
- Case orchestrator: assignment, escalation, dashboard
- Multi-case workload tracking
- Case handoff workflow
- FastAPI REST server with devices endpoint and health check
- CORS for Tauri/Vite frontend

---

## Phase 13 — Cloud & Container Forensics ✅ (v2.1)

**Goal:** Modern infrastructure investigations.

**AWS:** EBS snapshots, CloudTrail, IAM/EC2/VPC/S3 artifact collection  
**Azure:** Managed disk SAS access, VMs/NSGs/Activity Log/Azure AD  
**GCP:** Persistent disk snapshots, instances/IAM/firewall/audit logs  
**Docker:** Container filesystem export, metadata, logs, memory (/proc + nsenter), host inventory  
**Kubernetes:** Pods/services/events/RBAC, cluster timeline, privileged container detection

---

## Phase 14 — Advanced Mobile Forensics ✅ (v2.2)

**Goal:** Close the gap with commercial mobile tools.

**Android:**
- Full filesystem extraction (tar root, ADB backup, dd image, TWRP)
- SQLite deleted record recovery (WAL + freelist page scan)
- Keystore / TEE enumeration with secure enclave research docs
- Deep artifact collection (/proc, dmesg, WiFi, Bluetooth, accounts)

**iOS:**
- Full filesystem via AFC2, SSH tar, or pymobiledevice3
- Keychain extraction (jailbreak)
- Encrypted backup decryption (iphone-backup-decrypt)
- SEP/Keybag architecture research documentation
- Crash log collection

---

## Phase 15 — Offensive DFIR Features ✅ (v2.3)

**Goal:** Hybrid IR + adversary simulation analysis.

- Persistence hunting (registry, tasks, services, WMI, IFEO, startup)
- Beacon detection (LOLBin network, C2 ports, DNS C2, statistical interval analysis)
- Credential theft detection (Mimikatz, Kerberoasting, DCSync, PtH, WDigest)
- Ransomware triage (notes, extensions, VSS deletion, blast radius)
- Lateral movement mapping (logon paths, admin shares, remote services, tools)
- Full-triage command running all five modules
- Every finding MITRE ATT&CK mapped
- DFIRReport/DFIRFinding dataclasses with JSON export
- `dfir` CLI sub-app with 6 commands

---

## Phase 16 — Battlefield Edition ✅ (v3.0)

**Goal:** Full-spectrum forensic platform.

**Distributed Acquisition:**
- Multi-agent coordinator with parallel job dispatch
- Thread-safe job queue, per-agent result tracking
- Automatic CoC entries per agent
- Job state machine (pending/running/complete/failed/partial)

**Immutable Evidence Ledger:**
- SHA256 hash-chain — each entry contains hash of previous
- HMAC signing per entry
- Offline chain verification
- Migration from existing chain_of_custody.json

**AI Threat Graph:**
- Directed graph from processes/connections/IOCs/DFIR findings
- Attack path detection via DFS
- JSON / Graphviz DOT / STIX 2.1 export

**Cross-Device Timeline Fusion:**
- Merges memory/events/filesystem/network/mobile/cloud timelines
- UTC normalization, cross-device correlation, attack sequence detection

**Real-Time SSE Streaming:**
- In-memory pub/sub broker, thread-safe from sync code
- History replay, keep-alive, per-case and global channels

**Multi-Investigator Collaboration:**
- Notes, tasks, annotations, activity feed, case handoff

**Authentication Gate:**
- Password-protected CLI with PBKDF2 hashing
- Session file with 8-hour TTL
- Brute-force lockout
- Role-based command access
- First-time admin account setup wizard

**Expanded API (v3.0):**
- 30+ new REST endpoints
- SSE streaming at `/api/v3/stream/{case_id}`
- Full case/evidence/ledger/graph/timeline/collab/agents coverage

---

## Planned (Future)

| Feature | Notes |
|---|---|
| GUI (Tauri + React) | Frontend scaffolded, backend API ready |
| Database ORM | SQLite/PostgreSQL configured, migration pending |
| Plugin marketplace | Directory structure exists, community plugins TBD |
| MFA | TOTP support for auth gate |
| Sigma rule integration | Architecture exists, implementation pending |
| Network capture (PCAP) | Architecture planned |
| Hypervisor / VMware forensics | Planned for v3.1 |
| Full-text evidence search | Whoosh/Elasticsearch integration planned |
