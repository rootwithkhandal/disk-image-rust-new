# ForgeLens — Installation Guide

Complete setup guide for all tools required by ForgeLens across all platforms and features.

---

## 1. Prerequisites

### Python 3.10+

ForgeLens requires Python 3.10 or newer.

**Windows:**
```powershell
# Check version
python --version

# Download from https://www.python.org/downloads/
# Or via winget:
winget install Python.Python.3.12
```

**Linux:**
```bash
sudo apt install python3.12 python3.12-venv python3-pip
# or
sudo dnf install python3.12
```

**macOS:**
```bash
brew install python@3.12
```

---

## 2. Clone and Set Up the Virtual Environment

```bash
git clone https://github.com/your-org/forgelens.git
cd forensic-toolkit

# Create virtual environment
python -m venv .pyenv

# Activate (Windows)
.pyenv\Scripts\activate

# Activate (Linux/macOS)
source .pyenv/bin/activate
```

---

## 3. Install Python Dependencies

```bash
pip install -r backend/requirements.txt
```

### Core dependencies (installed automatically):

| Package | Version | Purpose |
|---|---|---|
| `typer` | 0.25.1 | CLI framework |
| `rich` | 15.0.0 | Terminal output |
| `loguru` | 0.7.3 | Structured logging |
| `psutil` | 7.2.2 | System information |
| `pyyaml` | 6.0.3 | Config files |
| `python-dotenv` | 1.2.2 | Environment variables |
| `pydantic` | 2.13.4 | Data validation |
| `pydantic-settings` | 2.14.1 | Settings management |
| `cryptography` | ≥44.0.0 | AES-256-GCM encryption |
| `pytsk3` | ≥20260418 | Sleuth Kit filesystem parsing |
| `volatility3` | 2.28.0 | Memory forensics |
| `adb-shell` | 0.4.4 | Android acquisition |
| `fastapi` | 0.109.2 | REST API server |
| `uvicorn` | 0.27.1 | ASGI server |

### Optional dependencies (install as needed):

```bash
# YARA rule scanning (requires C compiler on Windows — see section 6)
pip install yara-python

# BLAKE3 hashing (faster than SHA256)
pip install blake3

# PDF report generation
pip install reportlab

# E01 forensic image format (requires libewf — see section 7)
pip install pyewf

# iOS acquisition via Python (requires MSVC Build Tools on Windows)
pip install pymobiledevice3

# iTunes backup decryption
pip install iphone-backup-decrypt
```

---

## 4. Check All Dependencies

```bash
python forgelens.py setup check
```

This shows two tables — required and optional — with status, version, and fix hints.

To auto-install everything possible:
```bash
python forgelens.py setup install --optional
```

---

## 5. Windows RAM Acquisition — WinPmem

WinPmem is required for `memory acquire` on Windows.

**Auto-download (recommended):**
```bash
python forgelens.py memory setup
# or
python forgelens.py setup mounter --tool imdisk
```

**Manual download:**
1. Go to https://github.com/Velocidex/WinPmem/releases
2. Download `winpmem_mini_x64_rc2.exe`
3. Place it in `tools/winpmem_mini_x64_rc2.exe`

**Verify:**
```bash
python forgelens.py setup check
# WinPmem should show ✔ OK
```

---

## 6. YARA Rule Scanning

YARA requires a C compiler to build on Windows.

### Windows

1. Install **Microsoft C++ Build Tools:**
   - Download: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Select: "C++ build tools" workload
   - Or via winget: `winget install Microsoft.VisualStudio.2022.BuildTools`

2. Install yara-python:
   ```bash
   pip install yara-python
   ```

3. Add YARA rules:
   - Place `.yar` / `.yara` files in `plugins/yara_rules/`
   - Rules are auto-detected at scan time

### Linux
```bash
sudo apt install build-essential
pip install yara-python
```

### macOS
```bash
brew install yara
pip install yara-python
```

---

## 7. E01 Image Support — pyewf / libewf

E01 (Expert Witness Format) requires the libewf native library.

### Linux
```bash
sudo apt install libewf-dev
pip install pyewf
```

### macOS
```bash
brew install libewf
pip install pyewf
```

### Windows
E01 support on Windows requires building libewf from source.
See: https://github.com/libyal/libewf/blob/main/documentation/Building.md

For most Windows use cases, DD (raw) images are recommended instead.

---

## 8. Disk Image Mounting

To mount DD/RAW disk images for analysis on Windows, a third-party tool is needed.

### Option A — ImDisk (GPL, recommended for DD/RAW)

```bash
# Auto-install attempt via winget or choco:
python forgelens.py setup mounter

# Or manual install:
# Download: https://sourceforge.net/projects/imdisk-toolkit/files/latest/download
# Run ImDiskToolkit.exe as Administrator
# imdisk.exe is installed to C:\Windows\System32\ automatically
```

### Option B — Arsenal Image Mounter (AGPL, supports E01/AFF/VHD)

1. Download from: https://arsenalrecon.com/products/arsenal-image-mounter/downloads
2. Extract `aim_cli.exe` from the zip
3. Place in `tools/aim_cli.exe`

**Mount a DD image:**
```bash
python forgelens.py image mount evidence\image.dd --drive Z --case CASE-001 --examiner "You"
```

**Linux/macOS** — mounting uses built-in kernel loopback (no extra tools needed):
```bash
python forgelens.py image mount /evidence/image.dd --case CASE-001 --examiner "You"
```

---

## 9. Memory Analysis — Volatility3

Volatility3 is installed automatically via `requirements.txt`.

### First-run symbol download

On first use with a dump file, Volatility3 downloads Windows symbol files (~50 MB). This is a one-time operation per Volatility3 installation.

**Manual symbol download (if auto-download is slow):**
1. Go to: https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
2. Extract into: `.pyenv\Lib\site-packages\volatility3\symbols\windows\`

**Verify Volatility3:**
```bash
.pyenv\Scripts\vol.exe --version
```

---

## 10. Android Acquisition — ADB

ADB is required for Android device acquisition.

### Install Android Platform Tools

**Windows:**
```powershell
# Via winget:
winget install Google.PlatformTools

# Or download zip from:
# https://developer.android.com/tools/releases/platform-tools
# Extract and add to PATH
```

**Linux:**
```bash
sudo apt install android-tools-adb
# or
sudo apt install adb
```

**macOS:**
```bash
brew install android-platform-tools
```

### Enable USB debugging on the Android device

1. Settings → About Phone → tap **Build Number** 7 times
2. Settings → Developer Options → enable **USB Debugging**
3. Connect USB → accept the "Allow USB Debugging" prompt
4. Verify: `adb devices`

**Verify:**
```bash
python forgelens.py setup check
# ADB should show ✔ OK
```

---

## 11. iOS Acquisition — libimobiledevice

### Option A — libimobiledevice (binary tools)

**Windows:**
```bash
# Not easily installable as binaries on Windows
# Use Option B (pymobiledevice3) instead
pip install pymobiledevice3
```

**Linux:**
```bash
sudo apt install libimobiledevice-utils ideviceinstaller ifuse
```

**macOS:**
```bash
brew install libimobiledevice ideviceinstaller ifuse
```

### Option B — pymobiledevice3 (Python, all platforms)

```bash
# Windows requires MSVC Build Tools (section 6) first
pip install pymobiledevice3
```

### Pair the device

```bash
idevicepair pair          # libimobiledevice
# or accept trust prompt on device screen
```

**Verify:**
```bash
python forgelens.py setup check
# libimobiledevice or pymobiledevice3 should show ✔ OK
```

---

## 12. Linux RAM Acquisition — AVML

AVML is the preferred Linux memory acquisition tool (no kernel module needed).

```bash
# Download from GitHub releases:
# https://github.com/microsoft/avml/releases

# Or auto-download via ForgeLens:
python forgelens.py setup mounter

# Place binary in tools/ directory and make executable:
chmod +x tools/avml
```

**Alternative — LiME (kernel module):**
```bash
# Must be compiled for your exact running kernel:
# https://github.com/504ensicsLabs/LiME
git clone https://github.com/504ensicsLabs/LiME
cd LiME/src
make
# Copy lime-*.ko to tools/
```

---

## 13. Cloud Forensics CLIs

These are optional — only needed for cloud acquisition commands.

### AWS CLI
```bash
# Windows
winget install Amazon.AWSCLI

# Linux
sudo apt install awscli
# or
pip install awscli

# macOS
brew install awscli

# Configure credentials:
aws configure
```

### Azure CLI
```bash
# Windows
winget install Microsoft.AzureCLI

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# macOS
brew install azure-cli

# Login:
az login
```

### Google Cloud CLI
```bash
# Download: https://cloud.google.com/sdk/docs/install
# or
# Linux/macOS:
curl https://sdk.cloud.google.com | bash

# Login:
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

### Docker CLI
```bash
# Install Docker Desktop: https://docs.docker.com/get-docker/
# Verify:
docker --version
```

### kubectl
```bash
# Windows
winget install Kubernetes.kubectl

# Linux
sudo apt install kubectl

# macOS
brew install kubectl
```

---

## 14. SIEM Integration

No additional tools needed — ForgeLens connects to existing SIEM endpoints.

### Splunk HEC
```bash
python forgelens.py  # SIEM is configured in settings.yaml or .env
# SIEM_ENDPOINT=https://splunk:8088
# SIEM_TOKEN=your-hec-token
```

### Elasticsearch / OpenSearch
```bash
# SIEM_ENDPOINT=https://elastic:9200
# SIEM_TOKEN=your-api-key
```

---

## 15. Environment Configuration

Copy the example config and edit as needed:

```bash
cp backend/configs/.env.example .env
```

Key variables in `.env`:

```ini
# Required — change before any deployment
SECRET_KEY=change_me_before_use

# Evidence vault location (default: ./evidence)
EVIDENCE__BASE_PATH=./evidence

# Logging
LOGGING__LEVEL=INFO

# Acquisition defaults
ACQUISITION__BLOCK_SIZE=65536

# Optional: LLM endpoint for AI narrative augmentation
# LLM_ENDPOINT=http://localhost:11434
```

---

## 16. Docker Deployment

```bash
docker-compose up -d
```

Services started:
- `forgelens-backend` on port 8000
- `forgelens-db` (PostgreSQL) on port 5432

**Fix for Dockerfile CMD bug** — if the default CMD fails, edit `Dockerfile`:
```dockerfile
# Change this:
CMD [".venv/bin/python", "-m", "backend.cli"]
# To:
CMD ["python", "-m", "cli"]
```

---

## 17. Verification Checklist

After setup, run:

```bash
python forgelens.py setup check
```

Expected on a fully configured Windows system:

```
Required:
  ✔ cryptography    48.0.0
  ✔ pytsk3          —
  ✔ Volatility3     —
  ✔ WinPmem         winpmem_mini_x64_rc2.exe

Optional:
  ✔ yara-python     —
  ✔ blake3          —
  ✔ reportlab       —
  ✔ ADB             Android Debug Bridge 35.x
  ✔ Docker CLI      Docker version 29.x
```

---

## 18. Quick Smoke Test

```bash
# 1. Check CLI works
python forgelens.py version

# 2. Detect devices
python forgelens.py devices

# 3. Create a test case
python forgelens.py case create TEST-001 --examiner "Test" --title "Smoke test"

# 4. Hash a file
python forgelens.py hash file README.md --multi

# 5. Check setup
python forgelens.py setup check
```

All commands should complete without errors.

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'core'`
Run commands from the project root (`forensic-toolkit/`) not from `backend/`.

### WinPmem exits with code 1 but dump exists
This is expected — WinPmem returns 1 even on success on some systems.
ForgeLens handles this automatically (checks file existence, not exit code).

### Volatility3 `_MM_SESSION_SPACE` symbol error
Download the full Windows symbol pack:
https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
Extract into `.pyenv\Lib\site-packages\volatility3\symbols\windows\`

### `yara` crashes with DLL error on Windows
The installed yara-python has a broken native DLL.
Reinstall after installing MSVC Build Tools (section 6):
```bash
pip uninstall yara-python -y
pip install yara-python
```

### ADB device not detected
- Enable USB debugging on the device
- Accept the authorization prompt on the device screen
- Try `adb kill-server && adb start-server`
- Try a different USB cable (data cable, not charge-only)

### `aim_cli.exe` / ImDisk not found
- Place binaries in the `tools/` directory
- Or ensure they are on system PATH
- Run `python forgelens.py setup check` to diagnose
