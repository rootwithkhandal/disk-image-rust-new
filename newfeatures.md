# ThirdEye — New Feature Ideas

A curated list of potential features to extend the toolkit's capabilities across forensics, analysis, and usability.

---

## 1. CLI Interface
**Priority: High**

Replace the hardcoded `main.py` with a proper command-line interface using `argparse` or `click`.

- Subcommands: `image`, `mount`, `scan`, `report`, `unmount`
- Flags for image path, mount point, VT API key, YARA rules path, output directory
- `--help` for every subcommand

---

## 2. Report Generation
**Priority: High**

Generate structured output reports after a scan run.

- Export results to JSON, CSV, and/or PDF
- Include: file hashes, VT results, YARA matches, metadata, timestamps
- Use existing `json_to_table.py` as a base, extend with PDF support via `reportlab` or `fpdf2`

---

## 3. Windows Disk Imaging & Mounting Support
**Priority: High**

The current pipeline is Linux-only. Add Windows support.

- Use `dd` for Windows (via WSL or native port) or leverage `pywin32` / `wmi`
- Mount images on Windows using Arsenal Image Mounter or `imdisk`
- Detect OS at runtime and route to the correct implementation

---

## 4. Timeline Analysis
**Priority: Medium**

Build a filesystem timeline from file timestamps (MAC times: Modified, Accessed, Created).

- Parse `mtime`, `atime`, `ctime` from all files in the mounted image
- Sort and visualize as a chronological event timeline
- Flag anomalies (e.g., files modified after system shutdown, future timestamps)
- Export as CSV or interactive HTML chart

---

## 5. Registry Analysis (Windows Images)
**Priority: Medium**

Parse Windows registry hives from mounted images.

- Use `python-registry` library to read hives (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`)
- Extract: installed programs, run keys (persistence), USB history, user accounts, last login times
- Flag known malicious registry keys

---

## 6. String Extraction & Analysis
**Priority: Medium**

Extract printable strings from binary files (like the Unix `strings` command).

- Identify suspicious patterns: IPs, URLs, file paths, registry keys, base64 blobs
- Cross-reference extracted IPs/domains against threat intel feeds
- Integrate with the existing IOC detection pipeline

---

## 7. Network Artifact Extraction
**Priority: Medium**

Parse network-related artifacts from the imaged system.

- Extract browser history, DNS cache, ARP tables, firewall logs
- Parse PCAP files if present on the image
- Use `scapy` (already in requirements) for packet-level analysis

---

## 8. Threat Intelligence Feed Integration
**Priority: Medium**

Go beyond VirusTotal — integrate additional threat intel sources.

- **AbuseIPDB** — check extracted IPs
- **AlienVault OTX** — IOC lookups
- **MalwareBazaar** — hash lookups
- **Shodan** — passive recon on IPs found in artifacts
- Abstract behind a common `ThreatIntelProvider` interface

---

## 9. YARA Rule Management
**Priority: Medium**

Improve how YARA rules are handled.

- Support loading multiple `.yar` files from a rules directory
- Auto-download community rulesets (e.g., from [Awesome YARA](https://github.com/InQuest/awesome-yara))
- Fix the invalid `in (sections)` syntax in the existing `malware_rules.yar`
- Rule validation on load with clear error messages

---

## 10. Artifact Carving
**Priority: Medium**

Recover deleted or hidden files from disk images.

- Integrate with `photorec` or implement basic file carving by magic bytes
- Support common formats: JPEG, PDF, ZIP, EXE, DOCX
- Report carved files separately in the output

---

## 11. Memory Dump Analysis
**Priority: Medium**

Extend beyond disk images to support memory forensics.

- Integrate with **Volatility 3** for memory dump analysis
- Extract: running processes, network connections, loaded DLLs, injected code
- Cross-reference with YARA rules

---

## 12. Hash Database / Case Management
**Priority: Low**

Persist scan results across sessions.

- Store file hashes, VT results, and YARA matches in a local SQLite database
- Compare new scans against previous ones to detect changes
- Support multiple named "cases" for organizing investigations

---

## 13. Web Dashboard
**Priority: Low**

A lightweight local web UI for viewing scan results.

- Built with Flask or FastAPI + a simple frontend
- Display timeline, hash results, VT stats, YARA matches in a browser
- No external dependencies — runs fully offline

---

## 14. Docker / Portable Environment
**Priority: Low**

Package the toolkit for easy deployment.

- Dockerfile with all dependencies pre-installed (including `exiftool`, YARA, Volatility)
- Works consistently across Linux distros and CI environments
- Optional: AppImage or PyInstaller binary for field use

---

## 15. Plugin System
**Priority: Low**

Allow custom analyzers to be dropped in without modifying core code.

- Define a simple `Analyzer` base class with `analyze(directory: Path)` interface
- Auto-discover plugins from a `plugins/` directory
- Each plugin can add its own output section to the report

---

## Quick Wins (Low effort, high value)

| Item | Description |
|------|-------------|
| Fix `malware_rules.yar` | Invalid YARA syntax in rule 1 will crash on load |
| Remove code duplication | Consolidate mount/unmount logic into `mounter.py` only |
| Config file support | Load API keys and paths from a `.env` or `config.yaml` instead of hardcoding |
| Progress bars | Add `tqdm` progress bars to directory scans (already a dependency) |
| Dry-run mode | `--dry-run` flag to simulate a scan without making changes |
| Logging to file | Wire `logger_config.py` into all modules consistently |
