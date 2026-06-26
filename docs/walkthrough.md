# ForgeLens — Architecture Walkthrough

A guided tour of how the platform is structured and how the pieces fit together.

---

## The Core Pipeline

Everything in ForgeLens is built around one pipeline:

```
Acquire → Hash → Verify → Analyze → Report → Collaborate
```

Every module serves one of those six stages. If a feature doesn't strengthen one of them, it doesn't belong in the core.

---

## Project Layout

```
forensic-toolkit/
├── backend/                    Python backend
│   ├── api/                    FastAPI REST + SSE server
│   │   ├── server.py           App factory, CORS, startup
│   │   └── routes/
│   │       ├── devices.py      GET /api/devices
│   │       └── v3.py           All /api/v3/* routes (30+ endpoints)
│   ├── cli/
│   │   └── main.py             Typer CLI — every command lives here
│   ├── configs/
│   │   ├── settings.yaml       Default config
│   │   └── .env.example        Environment variable template
│   └── core/
│       ├── acquisition/        Device detection, metadata, disk enumeration
│       ├── ai/                 Anomaly detection, IOC scoring, summarizer, explainer, timeline narrator
│       ├── artifacts/          YARA, IOC matching, entropy, browser, registry, SQLite parsers
│       ├── auth/               Authentication gate, session management
│       ├── chain_of_custody/   Evidence vault, case manager, evidence index, crypto
│       ├── dfir/               Offensive DFIR — persistence, beacons, creds, ransomware, lateral
│       ├── enterprise/         SIEM, threat intel, cloud acquisition, case orchestrator
│       ├── hashing/            SHA256/MD5/SHA1/BLAKE3 engine
│       ├── imaging/            DiskImager, ImageMounter
│       ├── logging/            Loguru setup
│       ├── memory/             Volatility3 engine, memory timeline
│       ├── remote/             Agent, agent client, RBAC, evidence sync
│       ├── reporting/          JSON/HTML/Text/PDF report generator
│       ├── setup/              Dependency checker and installer
│       └── v3/                 Battlefield Edition
│           ├── distributed.py  Multi-agent acquisition coordinator
│           ├── ledger.py       Immutable hash-chain ledger
│           ├── streaming.py    SSE pub/sub broker
│           ├── threat_graph.py AI threat graph
│           ├── timeline_fusion.py Cross-device timeline fusion
│           └── collaboration.py Multi-investigator workspace
├── frontend/                   React + TypeScript + Tauri desktop UI
├── platforms/                  Platform-specific acquisition
│   ├── windows/                Registry, event logs, live response, memory (WinPmem)
│   ├── linux/                  Block devices, artifacts, AVML/LiME memory
│   ├── macos/                  APFS, FileVault, unified logs
│   ├── android/                ADB acquisition + advanced filesystem
│   ├── ios/                    libimobiledevice + jailbreak
│   └── usb/                    USB/removable device detection
├── plugins/
│   └── yara_rules/             Place .yar files here
├── tools/                      Third-party binaries (WinPmem, AVML, etc.)
├── evidence/                   Runtime vault (gitignored)
│   ├── cases/
│   │   └── <case_id>/
│   │       ├── case.json
│   │       └── <evidence_id>/
│   │           ├── metadata.json
│   │           ├── chain_of_custody.json
│   │           ├── ledger.jsonl        (immutable hash-chain)
│   │           ├── tags.json
│   │           ├── acquisition.log
│   │           ├── <image>.dd
│   │           ├── <image>.dd.hashes
│   │           └── collab/             (notes, tasks, annotations)
│   ├── evidence_index.json
│   ├── case_registry.json
│   ├── users.json              (PBKDF2-hashed credentials)
│   ├── .session                (current session token, chmod 600)
│   └── .auth_enabled           (exists = auth is on)
├── forgelens.py                Root CLI launcher with auth gate
└── docs/                       Documentation
```

---

## Authentication Flow

```
python forgelens.py <any command>
        │
        ▼
    forgelens.py
        │
        ├── Is this an exempt command? (auth, setup, --help)
        │   YES → skip auth, run command
        │
        └── NO → gate.require()
                    │
                    ├── Auth disabled? → synthetic admin session, continue
                    │
                    ├── Valid .session file? → continue with existing session
                    │
                    └── No session → interactive login prompt
                                    │
                                    ├── No users yet? → first-time admin setup
                                    │
                                    ├── Locked out? → show remaining wait time
                                    │
                                    ├── Credentials valid? → write .session, continue
                                    │
                                    └── Invalid → record failed attempt, exit 1
```

---

## Acquisition Flow

```
python forgelens.py image acquire --source /dev/sda --case CASE-001 --examiner Alice
        │
        ▼
    DiskImager.acquire()
        │
        ├── MetadataCollector.new_session()   → creates AcquisitionMetadata
        │
        ├── EvidenceManager.create_evidence_entry()
        │       └── creates evidence/ directory structure
        │       └── writes chain_of_custody.json (event: "created")
        │       └── writes tags.json, acquisition.log
        │
        ├── open(source, "rb")   ← READ ONLY
        │       └── chunked read → write to image file
        │       └── SHA256 + MD5 + SHA1 updated per chunk
        │       └── pause/resume/cancel via threading events
        │
        ├── EvidenceManager.write_hash_file()   → <image>.dd.hashes
        │
        ├── EvidenceManager.verify_evidence_integrity()
        │       └── re-hashes image, compares against manifest
        │       └── records "verified" or "integrity_failed" CoC event
        │
        ├── MetadataCollector.finalize()   → fills hashes, duration, output_path
        │
        ├── EvidenceManager.write_metadata()   → metadata.json
        │
        └── ReportGenerator.generate()   → JSON + HTML + Text reports
```

---

## Memory Analysis Flow

```
python forgelens.py memory processes dump.raw
        │
        ▼
    VolatilityEngine._run_plugin("windows.pslist.PsList")
        │
        ├── Find vol3/vol/volatility3 on PATH or venv Scripts/
        │
        ├── subprocess.run([vol, "-f", dump, "-q", plugin], timeout=1800)
        │
        ├── Parse tab-separated output (plain text renderer)
        │       └── Skip "Volatility 3 Framework" header line
        │       └── First content line = column headers
        │       └── Subsequent lines = data rows
        │       └── Stop at warning/error lines
        │
        └── _enrich_process() → adds _suspicious + _suspicious_reasons flags
```

---

## V3.0 Streaming Flow

```
Acquisition running in thread
        │
        ▼
    broker.publish_progress("case:CASE-001", evidence_id, "imaging", 42.0)
        │
        ├── Stores event in broker._history["case:CASE-001"]
        │
        └── broker._loop.call_soon_threadsafe(q.put_nowait, event)
                └── Pushed to every asyncio.Queue in _subscribers["case:CASE-001"]

FastAPI SSE endpoint
        │
        ▼
    GET /api/v3/stream/CASE-001
        │
        ├── broker.subscribe("case:CASE-001")
        │       └── Creates asyncio.Queue, adds to _subscribers
        │       └── Replays history on connect
        │
        └── Yields SSE-formatted strings until client disconnects
                "id: abc123\nevent: acquisition_progress\ndata: {...}\n\n"
```

---

## Immutable Ledger Structure

Each line in `ledger.jsonl` is a JSON-encoded `LedgerEntry`:

```json
{
  "seq": 1,
  "case_id": "CASE-001",
  "evidence_id": "EV-XXXXXXXX",
  "event_type": "created",
  "actor": "alice",
  "timestamp": "2026-06-07T14:00:00+00:00",
  "notes": "Physical acquisition via WinPmem",
  "metadata": {},
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "entry_hash": "sha256(seq+case+evidence+event+actor+ts+notes+metadata+prev_hash)",
  "hmac_sig": "hmac_sha256(entry_hash, signing_key)"
}
```

To verify the chain: for each entry, recompute `entry_hash` and check `prev_hash` matches the previous entry's `entry_hash`. Any modification to any entry breaks the chain from that point forward.

---

## Threat Graph Data Model

```
Nodes (node_type: label):
  process: "mimikatz.exe:1234"
  ip:      "185.220.101.1"
  domain:  "evil.com"
  file:    "abc123sha256hash"
  technique: "T1003.001"
  user:    "DOMAIN\alice"
  host:    "WORKSTATION-01"

Edges (edge_type):
  spawned          winword.exe → powershell.exe
  connected_to     powershell.exe → 185.220.101.1
  used_by          T1003.001 → mimikatz.exe
  lateral_moved_to WORKSTATION-01 → DC-01
```

Export formats:
- **JSON**: Full node/edge graph with risk scores and MITRE tags
- **DOT**: `digraph { ... }` for Graphviz rendering (`dot -Tpng graph.dot -o graph.png`)
- **STIX 2.1**: IOC nodes → STIX Indicators in a Bundle for sharing

---

## Evidence Vault Layout

```
evidence/
├── cases/
│   └── CASE-2026-001/
│       ├── case.json                    Case metadata
│       └── EV-5758DA1C/
│           ├── metadata.json            Full acquisition metadata + hashes
│           ├── chain_of_custody.json    Append-only event log (legacy)
│           ├── ledger.jsonl             Immutable hash-chain (v3.0)
│           ├── acquisition.log          Free-text acquisition log
│           ├── tags.json                Evidence tags
│           ├── EV-5758DA1C.raw          Memory dump / disk image
│           ├── EV-5758DA1C.raw.hashes   SHA256/MD5/SHA1 manifest
│           ├── EV-5758DA1C.processes.json  Process/connection export
│           ├── report_EV-5758DA1C.html  HTML acquisition report
│           ├── report_EV-5758DA1C.json  JSON acquisition report
│           ├── report_EV-5758DA1C.txt   Text acquisition report
│           └── collab/
│               ├── notes.json           Investigator notes + replies
│               ├── tasks.json           Assigned tasks
│               ├── annotations.json     Evidence annotations
│               └── activity_feed.json   Activity log
├── evidence_index.json                  Fast search index (all evidence)
├── case_registry.json                   Case metadata index
├── case_assignments.json                Examiner assignments
├── distributed_jobs.json                Agent job state
├── users.json                           PBKDF2-hashed user credentials
├── .session                             Active session token (chmod 600)
├── .auth_enabled                        Auth gate toggle
├── .lockout                             Brute-force lockout state
└── .mount_state.json                    Active image mounts
```

---

## Configuration Priority

Settings are loaded in this order (highest to lowest priority):

```
1. Environment variables    (APP__DEBUG=true)
2. .env file                (ROOT/.env)
3. settings.yaml            (backend/configs/settings.yaml)
```

Key settings:

```yaml
# settings.yaml defaults
evidence:
  base_path: ./evidence
  hash_algorithm: sha256

logging:
  level: INFO
  log_dir: ./backend/logs

acquisition:
  block_size: 65536
  threads: 4
```

Override anything via environment variables using `__` as delimiter:
```
EVIDENCE__BASE_PATH=/mnt/evidence
LOGGING__LEVEL=DEBUG
ACQUISITION__BLOCK_SIZE=131072
```

---

## Design Principles

**1. Read-only sources** — source devices are never written to. The imager opens devices in `"rb"` mode and verifies write-protection where possible.

**2. Evidence-first** — every acquisition creates a chain of custody entry before any data is collected. Failures are also recorded in the custody log.

**3. Graceful degradation** — optional dependencies (YARA, BLAKE3, reportlab, pymobiledevice3) degrade silently with clear install instructions. The core pipeline never fails due to a missing optional dependency.

**4. MITRE ATT&CK throughout** — every detection finding maps to a technique and tactic. This makes findings actionable and comparable across cases.

**5. Offline-first** — everything works without internet access. Threat intel, LLM augmentation, and VirusTotal are opt-in enhancements, never required.
