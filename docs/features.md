# ForgeLens — Feature Reference

Complete feature list across all versions (v0.1 through v3.0).

---

## 1. Authentication & Access Control (v3.0)

- Password-protected CLI — auth gate enforced before every command
- PBKDF2-HMAC-SHA256 password hashing (600,000 iterations)
- Session persistence — log in once, valid for 8 hours
- Session file restricted to current OS user (chmod 600)
- Brute-force protection — 3 attempts then 30-second lockout
- Role-based access control (admin / examiner / analyst / viewer)
- User management — create, deactivate, role-change, password-change
- Auth disabled by default for single-analyst offline use
- Auth exempt commands: `auth`, `setup`, `--help`

---

## 2. Disk Imaging

- Full physical sector-by-sector imaging
- Logical acquisition
- Partition imaging
- Live system imaging
- Dead-box acquisition
- Remote imaging (via agent)
- Pause / resume / cancel support
- Real-time dual-algorithm hashing during acquisition (SHA256 + MD5)
- Throughput monitoring and progress tracking
- Post-acquisition integrity verification
- Configurable block size

**Supported export formats:** RAW/DD, E01, split images

**Supported filesystems:** NTFS, FAT32, exFAT, ReFS, EXT2/3/4, XFS, Btrfs, ZFS, APFS, HFS+, YAFFS2, F2FS

---

## 3. Hashing & Verification

- SHA256, MD5, SHA1, BLAKE3
- Multi-algorithm single-pass hashing
- Chunk-level hashing
- Post-acquisition hash verification
- Hash manifest sidecar files (`.hashes`)
- VirusTotal hash lookup integration
- Physical drive hashing (Windows raw device access via CreateFileW)

---

## 4. Evidence Vault & Chain of Custody

- Unique evidence IDs (EV-XXXXXXXX)
- Per-evidence directory structure
- Metadata JSON with full acquisition context
- Append-only chain of custody event log (`chain_of_custody.json`)
- HMAC-SHA256 signed metadata for tamper detection
- Tags system with indexed search
- Evidence index with full-text search
- Case registry with status, priority, tags
- Vault repair — reconstruct missing metadata.json from existing artifacts
- Case audit trail across all evidence items

---

## 5. Immutable Evidence Ledger (v3.0)

- Hash-chain ledger (SHA256 of previous entry links every event)
- Append-only — no modification or deletion
- HMAC signing per entry (optional key)
- Offline chain verification (detects retroactive tampering)
- Migration from existing chain_of_custody.json events
- JSON export of full ledger
- API endpoint for chain verification

---

## 6. Encryption

- AES-256-GCM file encryption with custom magic header
- PBKDF2-derived keys from passwords
- Random nonce per encryption
- Base64 key storage
- GCM authentication tag — detects any modification
- HMAC-SHA256 signed metadata files

---

## 7. Platform Acquisition

### Windows (live)
- Physical disk enumeration via WMI
- BitLocker volume detection
- Partition table detection (GPT/MBR)
- Shadow copy enumeration
- Running processes + command lines
- Network connections (TCP/UDP)
- ARP table
- DNS cache
- Scheduled tasks
- Registered services
- Live RAM acquisition via WinPmem (open-source, AGPL)

### Linux (live)
- Block device enumeration (lsblk)
- LVM logical volume detection
- RAID array detection (/proc/mdstat)
- Encrypted partition detection (LUKS)
- Filesystem type mapping
- Bash history, SSH keys, crontabs
- System logs, auth.log, journalctl
- Docker container artifacts
- RAM acquisition via AVML (no kernel module) or LiME

### macOS (live)
- APFS container and volume enumeration
- FileVault status
- SIP (System Integrity Protection) status
- T2 / Apple Silicon chip detection
- Disk layout via diskutil
- Unified logs
- Safari history
- Keychain metadata
- LaunchAgents / LaunchDaemons
- APFS snapshots
- Time Machine artifacts

### Android (connected via ADB)
- Device metadata and property dump
- Installed app inventory (with APK paths)
- SMS database extraction (root)
- Contacts database (root)
- Call log (root)
- Media files (DCIM, Pictures, Downloads)
- APK extraction
- WhatsApp database (root)

### Android Advanced (v2.2)
- Full filesystem via tar+ADB (root)
- ADB backup method (non-root, Android <12)
- Raw dd partition image (root + unlocked bootloader)
- TWRP-assisted backup
- SQLite deleted record recovery (WAL + freelist page scan)
- Keystore / TEE artifact enumeration
- Secure Enclave research documentation
- /proc memory maps, dmesg, WiFi networks, Bluetooth config
- All system properties dump

### iOS (connected device)
- iTunes full backup via idevicebackup2
- AFC media partition access
- Syslog and crash log collection
- Device metadata via ideviceinfo
- Jailbreak detection (Cydia/Sileo)

### iOS Advanced (v2.2)
- Full filesystem via AFC2 (jailbreak)
- SSH + tar filesystem extraction (jailbreak + OpenSSH)
- pymobiledevice3 filesystem pull
- Keychain database extraction (jailbreak)
- Encrypted iTunes backup decryption (iphone-backup-decrypt)
- SEP / Keybag architecture research documentation
- Key class hierarchy documentation
- Acquisition strategy guide by access level

### MS-DOS / Legacy FAT
- Sector-by-sector imaging (same engine as physical imaging)
- DD and E01 output

---

## 8. Memory Forensics

- Live RAM acquisition (WinPmem on Windows, AVML/LiME on Linux)
- Memory dump analysis via Volatility3
- Process listing with suspicious process enrichment
- Process tree (parent-child hierarchy)
- DLL / loaded module enumeration
- Network connection extraction
- Injected code / process hollowing detection (malfind)
- NTLM hash extraction (hashdump)
- SSDT hook detection (rootkit)
- Memory timeline of process events
- Full memory dump analysis suite
- Plain-text output parser (resilient to partial symbol errors)
- Export all processes + connections to JSON for YARA/VirusTotal

---

## 9. Artifact Collection

### Windows
Registry hive parser, shimcache, amcache, jump lists, prefetch, shellbags, USB history, EVTX event logs, PowerShell activity, browser history (Chrome/Firefox/Edge), scheduled tasks

### Linux
Bash history, SSH keys, crontabs, syslog, auth.log, journalctl, Docker artifacts, /proc filesystem

### macOS
Unified logs, Safari history, keychain metadata, LaunchAgents/Daemons, APFS snapshots

### Mobile
WhatsApp databases, SMS, contacts, call logs, GPS history, EXIF metadata, installed apps

---

## 10. YARA & IOC Detection

- YARA rule scanning (yara-python)
- Rules auto-loaded from `plugins/yara_rules/`
- Shannon entropy analysis (packed/encrypted file detection)
- IOC pattern extraction (IPs, domains, URLs, hashes, emails)
- Known-bad hash, domain, and IP matching
- IOC deduplication and scoring (P1–P4 priority tiers)
- VirusTotal API enrichment
- Persistence detection (Run keys, scheduled tasks, startup folders)

---

## 11. Offensive DFIR (v2.3)

### Persistence Hunting
Registry Run/RunOnce keys (HKLM + HKCU), scheduled tasks, Windows services, WMI event subscriptions, IFEO debugger hijacks, AppCert/AppInit DLLs, LSA providers, startup folders. Every finding mapped to MITRE ATT&CK.

### Beacon Detection
LOLBin HTTP/S connections, classic C2 ports (4444/1337/31337), DNS C2 indicators, statistical interval analysis against known C2 frameworks (Cobalt Strike 60s, Sliver, Empire 5s, Metasploit 5s, Brute Ratel).

### Credential Theft Detection
Mimikatz/WCE/fgdump/pwdump/procdump in process list, LSASS dump via comsvcs.dll MiniDump, Kerberoasting (EventID 4769 RC4), Pass-the-Hash (4624 type 3 NTLM), DCSync (4662 replication rights), WDigest plaintext credential storage.

### Ransomware Triage
Ransom note file detection (100+ patterns), known encrypted extensions (100+), VSS/shadow copy deletion commands, Recovery disabling (bcdedit/wbadmin), blast radius estimation (file count + size).

### Lateral Movement Mapping
Logon path reconstruction (4624/4648), admin share access (5140 ADMIN$/C$), remote service installation (7045/4697), PsExec/WMI/WinRM/RDP in process list and command lines.

---

## 12. Cloud & Container Forensics (v2.1)

### AWS
EBS volume snapshot creation and polling, CloudTrail configuration, IAM users/roles/policies, EC2 instances and security groups, VPC and route tables, S3 bucket inventory

### Azure
Managed disk SAS URL generation (read-only), VMs, NSGs, VNets, Storage accounts, RBAC assignments, Activity Log, Azure AD users and applications

### GCP
Persistent disk snapshots, compute instances, disks, firewall rules, VPC networks, IAM policy, service accounts, GCS buckets, Cloud Audit logs

### Docker
Container filesystem export (tar), container metadata, running processes, network stats, container logs, image layer history, host inventory (containers/images/volumes/networks), system info, container memory via /proc + nsenter (Linux)

### Kubernetes
Pods, services, deployments, replicasets, daemonsets, statefulsets, jobs, cronjobs, events, configmaps, serviceaccounts, network policies, ingresses, PVCs, nodes, PVs, cluster roles, RBAC bindings, cluster timeline reconstruction with privileged container detection

---

## 13. AI Analysis

### Behavioral Anomaly Detection
Suspicious parent-child process chains, privilege escalation tools, lateral movement indicators, data staging tools, abnormal network connection volumes, suspicious C2 ports, brute-force indicators (EventID 4625), service installs, off-hours logins, cross-correlated process+network anomalies. Risk scoring 0–10 with MITRE mapping.

### IOC Prioritization
Deduplication, scoring by type/occurrence/context, P1–P4 tiers, recommended actions, MITRE mapping.

### Evidence Summarizer
Acquisition summaries, artifact collection summaries, case summaries. Optional LLM augmentation (Ollama-compatible).

### Timeline Narrator
Attack phase detection, kill chain ordering, narrative generation, process tree narration.

### Activity Explainer
Plain-English explanations for processes, IOCs, persistence entries, injected code, high-entropy files.

---

## 14. AI Threat Graph (v3.0)

- Directed graph: nodes (process/file/ip/domain/user/host/technique/artifact) and edges (spawned/connected_to/accessed/used_by/lateral_moved_to/exfiltrated_to)
- Ingests: processes, network connections, DFIR findings, IOC reports, timeline events
- Attack path detection via DFS through suspicious nodes
- MITRE technique node tagging
- IOC node highlighting
- Export formats: JSON (API), Graphviz DOT (visualization), STIX 2.1 bundle (threat intel sharing)

---

## 15. Cross-Device Timeline Fusion (v3.0)

- Merges timelines from memory dumps, Windows events, filesystem MAC times, network captures, mobile logs, cloud audit logs
- Automatic UTC timestamp normalization
- Cross-device correlation: same actor across devices, temporal proximity (5-min window), attack sequence detection (credential access → lateral movement)
- Suspicious event highlighting
- Correlated cluster report

---

## 16. Distributed Acquisition (v3.0)

- Register multiple remote agents
- Parallel acquisition dispatch to all online agents simultaneously
- Thread-safe job queue
- Per-agent result tracking
- Automatic chain of custody entry per agent
- Job state: pending / running / complete / failed / partial
- Wait or fire-and-forget mode
- Job report with per-agent success/failure/duration

---

## 17. Real-Time Streaming (v3.0)

- Server-Sent Events (SSE) broker
- Thread-safe publish from sync acquisition code
- Event history replay on reconnect
- Keep-alive pings every 15 seconds
- Channels: per-case and global
- Event types: acquisition_progress, alert, analysis_complete, agent_status, case_created, task_assigned, etc.
- FastAPI SSE endpoints at `/api/v3/stream/{case_id}`

---

## 18. Multi-Investigator Collaboration (v3.0)

- Investigator notes with replies and tags (case-level and evidence-level)
- Task assignment and tracking (open/in_progress/review/done/blocked)
- Evidence annotations (flag/bookmark/comment/critical/reviewed/dispute)
- Activity feed with actor, action, target, timestamp
- Case handoff workflow with formal handoff record
- Open task count, note count, critical annotation count in dashboard

---

## 19. Reporting

**Export formats:** JSON, HTML, Text, PDF (via reportlab)

**Report types:**
- Acquisition summary
- Chain of custody
- Hash verification report
- Memory analysis report
- DFIR findings report
- Threat graph (JSON/DOT/STIX 2.1)
- Fused timeline JSON

---

## 20. Enterprise & Integration

- SIEM integration: Splunk HEC, Elasticsearch/OpenSearch, syslog (CEF), generic HTTP
- Threat intelligence feeds: MISP, OTX, generic JSON
- Local IOC cache for offline operation
- Remote acquisition agent (HMAC-signed HTTP)
- Agent client with ping, live response, imaging, artifact collection, memory
- Evidence synchronization with integrity verification
- Case orchestrator: assignment, escalation, dashboard
- FastAPI REST server with 30+ endpoints
- CORS for Tauri/Vite frontend

---

## 21. Disk Image Mounting

- Read-only enforcement
- Windows: Arsenal Image Mounter (AGPL), ImDisk (GPL), PowerShell Mount-DiskImage (VHD/ISO)
- Linux: loopback device + kernel mount (built-in)
- macOS: hdiutil (built-in)
- Chain of custody event recorded on mount/unmount
- Active mount tracking with mount_id
- Unmount by ID or unmount all

---

## 22. Plugin System

- YARA rules directory (`plugins/yara_rules/`)
- Community parsers directory (`plugins/parsers/`)
- Python plugin architecture (extensible)
