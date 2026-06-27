# ThirdEye 🔍

> A cross-platform digital forensics and malware analysis toolkit for imaging, mounting, and investigating disk data.

---

## Overview

ThirdEye automates the core forensic workflow — from raw disk imaging to deep file analysis — in a single CLI-driven pipeline. It combines file hashing, VirusTotal lookups, YARA-based IOC detection, metadata extraction, and live system artifact collection into a modular, extensible toolkit.

---

## Features

### Core Pipeline
- **Disk Imaging** — Read raw disk images block-by-block with per-block SHA-256 integrity hashing and `tqdm` progress bar
- **Disk Mounting** — Mount `.img` files via loop devices (read-only, forensically sound) with automatic partition detection
- **File Hashing** — Compute MD5, SHA-1, and SHA-256 for every file in a directory; results exported to JSON/CSV
- **File Metadata** — Extract MAC timestamps (modified, accessed, created), file size, and extended metadata via `exiftool`

### Threat Analysis
- **VirusTotal Integration** — Hash-based lookups with exponential backoff on rate limits; full directory scanning
- **YARA IOC Detection** — Scan files against a single `.yar` file or an entire directory of rules; returns structured match results

### System Artifact Collection
- **Linux** — Running processes (`ps aux`), network connections (`ss`), syslog, cron jobs, bash history
- **Windows** — Running processes (`tasklist`), network connections (`netstat`), Event Logs, startup items (`wmic`), Prefetch files

### Reporting
- **JSON + CSV export** — Every scan command saves structured results via `ReportGenerator`
- **Named sections** — Each scan type (hashes, VT results, IOC matches, etc.) is a separate section in the report

### Developer Experience
- **CLI interface** — `click`-based subcommands with `--help` on every command
- **Config file** — Central `config.yaml` for API keys, paths, and settings
- **Environment variable overrides** — Override any config value without editing files
- **Dry-run mode** — `--dry-run` on every command to simulate without side effects
- **Structured logging** — Rotating file + coloured console logs via `loguru`

---

## Project Structure

```
thirdeye/
├── main.py                     # CLI entry point (click)
├── config.yaml                 # Central configuration
├── malware_rules.yar           # YARA rules for malware detection
├── requirements.txt
│
├── analysis/
│   ├── file_hasher.py          # MD5/SHA-1/SHA-256 directory hashing
│   ├── file_metadata.py        # File timestamps and exiftool metadata
│   └── virus_total_checker.py  # VirusTotal API hash lookups
│
├── automation/
│   ├── auto_linux.py           # Linux artifact collection
│   └── auto_win.py             # Windows artifact collection
│
├── imaging/
│   ├── disk_imager.py          # Raw disk imaging with progress + integrity
│   └── mounter.py              # mount_img / unmount_img helpers
│
├── ioc/
│   └── ioc_detector.py         # YARA rule loading and directory scanning
│
└── utils/
    ├── config_loader.py        # config.yaml loader with env var overrides
    ├── json_to_table.py        # JSON → CSV export helper
    ├── logger_config.py        # Loguru logger setup
    └── reporter.py             # ReportGenerator — JSON + CSV output
```

---

## Requirements

```
loguru==0.7.2
psutil==5.9.8
scapy==2.5.0
pandas==2.2.2
requests==2.32.3
yara-python==4.5.1
PyExifTool==0.5.6
click==8.1.7
pyyaml==6.0.1
tqdm==4.66.4
```

Install dependencies:

```bash
pip install -r requirements.txt
```

> `exiftool` must also be installed on your system for extended metadata extraction.
> - Linux: `sudo apt install libimage-exiftool-perl`
> - Windows: Download from [exiftool.org](https://exiftool.org)

---

## Configuration

Edit `config.yaml` before running:

```yaml
virustotal:
  api_key: "YOUR_VIRUSTOTAL_API_KEY"
  rate_limit_sleep: 15       # seconds between requests (free tier)

imaging:
  block_size_mb: 4
  default_image_path: ""
  default_mount_point: ""

yara:
  rules_path: "malware_rules.yar"   # file or directory of .yar files

logging:
  log_file: "logs/thirdeye.log"
  level: "INFO"

reporting:
  output_dir: "reports"
  formats: [json, csv]
```

Any value can be overridden with an environment variable:

| Environment Variable    | Config key              |
|-------------------------|-------------------------|
| `THIRDEYE_VT_API_KEY`   | `virustotal.api_key`    |
| `THIRDEYE_LOG_LEVEL`    | `logging.level`         |
| `THIRDEYE_LOG_FILE`     | `logging.log_file`      |
| `THIRDEYE_YARA_RULES`   | `yara.rules_path`       |
| `THIRDEYE_REPORT_DIR`   | `reporting.output_dir`  |

---

## Usage

### Full scan (mount → VirusTotal → YARA → report → unmount)

```bash
python main.py scan \
  --image /path/to/disk.img \
  --mount-point /mnt/forensic \
  --vt-key YOUR_API_KEY \
  --rules malware_rules.yar \
  --output-dir reports
```

### Hash all files in a directory

```bash
python main.py hash --directory /mnt/forensic --output-dir reports
```

### YARA IOC scan on a directory

```bash
python main.py ioc --directory /mnt/forensic --rules malware_rules.yar
```

### Collect live system artifacts

```bash
python main.py sysinfo --output-dir reports
```

### Image a disk (Linux only)

```bash
python main.py image --device /dev/sdb --output /evidence/disk.img
```

### Dry-run any command

```bash
python main.py scan --image disk.img --mount-point /mnt/forensic --dry-run
```

### Help

```bash
python main.py --help
python main.py scan --help
```

---

## YARA Rules

`malware_rules.yar` ships with six rules out of the box:

| Rule | Description |
|------|-------------|
| `Suspicious_PE_SectionName` | PE files containing a `.evil` section |
| `Suspicious_API_Strings` | Common malware API calls (`CreateRemoteThread`, `VirtualAlloc`, etc.) |
| `Suspicious_PowerShell` | Obfuscated or suspicious PowerShell patterns |
| `Base64_Encoded_Payload` | Files with multiple long base64 blobs |
| `RAT_Indicators` | Strings common in Remote Access Trojans |
| `Suspicious_Network_Indicators` | Hardcoded Tor, Pastebin, ngrok, or raw GitHub URLs |

You can point `--rules` at a directory to load multiple `.yar` files at once.

---

## Reports

Every command saves results to the configured `output_dir`. Files are timestamped:

```
reports/
├── scan_20250605_143022.json
├── scan_20250605_143022_virustotal.csv
├── scan_20250605_143022_ioc_matches.csv
├── hashes_20250605_143500.json
├── hashes_20250605_143500_hashes.csv
└── sysinfo_20250605_144001.json
```

---

## Platform Support

| Feature | Linux | Windows |
|---------|:-----:|:-------:|
| Disk Imaging | ✅ | ⚠️ Planned |
| Disk Mounting | ✅ | ⚠️ Planned |
| File Hashing | ✅ | ✅ |
| VirusTotal Scan | ✅ | ✅ |
| YARA IOC Detection | ✅ | ✅ |
| File Metadata | ✅ | ✅ |
| Process Collection | ✅ | ✅ |
| Network Collection | ✅ | ✅ |
| Cron / Startup Items | ✅ | ✅ |
| Bash History / Prefetch | ✅ | ✅ |

---

## Roadmap

See [`newfeatures.md`](newfeatures.md) for full details. Highlights:

- Timeline analysis from MAC timestamps
- Windows registry hive parsing
- String extraction and suspicious pattern flagging
- Threat intel feed integration (AbuseIPDB, OTX, MalwareBazaar)
- Artifact carving for deleted file recovery
- Memory dump analysis via Volatility 3
- SQLite-backed case management
- Local web dashboard (Flask/FastAPI)
- Docker / portable environment

---

## License

MIT
