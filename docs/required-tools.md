# Windows Development Arsenal — Forensic Toolkit Build Environment

This is your DFIR weapons rack.
Install this correctly once, and your development pipeline becomes surgical instead of chaotic.

---

# 1. Core Development Stack

## Python

Primary backend language.

Install:

* [https://www.python.org/downloads/windows/](https://www.python.org/downloads/windows/)

### During Installation

Enable:

* Add Python to PATH
* Install pip

Then verify:

```powershell
python --version
pip --version
```

---

## Git

Version control. Non-negotiable.

Install:

* [https://git-scm.com/download/win](https://git-scm.com/download/win)

Verify:

```powershell
git --version
```

---

## VS Code

Your command center.

Install:

* [https://code.visualstudio.com/](https://code.visualstudio.com/)

---

# 2. Essential VS Code Extensions

Install these immediately.

| Extension                 | Purpose                  |
| ------------------------- | ------------------------ |
| Python                    | Python support           |
| Pylance                   | IntelliSense             |
| Ruff                      | Fast linting             |
| Error Lens                | Instant error visibility |
| GitLens                   | Git intelligence         |
| Better TOML               | Config handling          |
| Docker                    | Container workflows      |
| Hex Editor                | Binary analysis          |
| SQLite Viewer             | SQLite inspection        |
| Markdown Preview Enhanced | Documentation            |

---

# 3. Windows Terminal Stack

## Windows Terminal

Install:

* [https://apps.microsoft.com/detail/9N0DX20HK701](https://apps.microsoft.com/detail/9N0DX20HK701)

---

## PowerShell 7

Install:

* [https://github.com/PowerShell/PowerShell/releases](https://github.com/PowerShell/PowerShell/releases)

---

## WSL2

Critical for Linux forensic tooling.

Install:

```powershell
wsl --install
```

Recommended distro:

* Ubuntu

---

# 4. Python Libraries

## Core Development

```powershell
pip install typer rich loguru psutil pyyaml python-dotenv
```

---

## Forensics Libraries

```powershell
pip install pytsk3 pyewf yara-python volatility3
```

---

## Mobile & Parsing

```powershell
pip install adb-shell pymobiledevice3
```

---

## Hashing

```powershell
pip install blake3
```

---

# 5. Low-Level Forensic Tools

## Sleuth Kit

Filesystem forensic framework.

Install:

* [https://www.sleuthkit.org/sleuthkit/](https://www.sleuthkit.org/sleuthkit/)

Includes:

* fls
* icat
* mmls
* fsstat

---

## Autopsy

Analysis platform.

Install:

* [https://www.autopsy.com/download/](https://www.autopsy.com/download/)

---

## FTK Imager

Industry-standard imaging reference.

Install:

* [https://www.exterro.com/digital-forensics-software/ftk-imager](https://www.exterro.com/digital-forensics-software/ftk-imager)

Use it:

* for comparison
* validation
* workflow inspiration

---

## Arsenal Image Mounter

Mount forensic images.

Install:

* [https://arsenalrecon.com/downloads/](https://arsenalrecon.com/downloads/)

---

## WinPMEM

RAM acquisition.

Install:

* [https://github.com/Velocidex/WinPmem/releases](https://github.com/Velocidex/WinPmem/releases)

---

## Volatility 3

Memory forensics.

Install:

* [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)

---

## YARA

Malware detection.

Install:

* [https://virustotal.github.io/yara/](https://virustotal.github.io/yara/)

---

## ExifTool

Metadata extraction monster.

Install:

* [https://exiftool.org/](https://exiftool.org/)

---

# 6. Android Forensics Stack

## Android Platform Tools (ADB)

Critical.

Install:

* [https://developer.android.com/tools/releases/platform-tools](https://developer.android.com/tools/releases/platform-tools)

Verify:

```powershell
adb version
```

---

## Scrcpy

Screen mirroring.

Install:

* [https://github.com/Genymobile/scrcpy](https://github.com/Genymobile/scrcpy)

---

## JADX

APK reverse engineering.

Install:

* [https://github.com/skylot/jadx](https://github.com/skylot/jadx)

---

## APKTool

APK unpacking.

Install:

* [https://apktool.org/](https://apktool.org/)

---

## Frida

Dynamic instrumentation.

Install:

* [https://frida.re/](https://frida.re/)

Python package:

```powershell
pip install frida-tools
```

---

# 7. iOS Forensics Stack

Apple’s ecosystem fights back like a paranoid submarine AI.

## libimobiledevice

Install via WSL or Windows builds.

Official:

* [https://github.com/libimobiledevice/libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)

---

## pymobiledevice3

Install:

```powershell
pip install pymobiledevice3
```

---

## iTunes

Needed for drivers + device communication.

Install:

* [https://www.apple.com/itunes/](https://www.apple.com/itunes/)

---

# 8. Disk & Filesystem Utilities

## TestDisk

Partition recovery.

Install:

* [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

---

## dd for Windows

Useful for imaging.

Install:

* [https://www.chrysocome.net/dd](https://www.chrysocome.net/dd)

---

## OSFMount

Mount raw images.

Install:

* [https://www.osforensics.com/tools/mount-disk-images.html](https://www.osforensics.com/tools/mount-disk-images.html)

---

# 9. Database & Artifact Analysis

## DB Browser for SQLite

Critical for mobile artifacts.

Install:

* [https://sqlitebrowser.org/](https://sqlitebrowser.org/)

---

## CyberChef

Artifact decoding.

Use:

* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

---

# 10. Reverse Engineering Toolkit

## Ghidra

Install:

* [https://ghidra-sre.org/](https://ghidra-sre.org/)

---

## Detect It Easy (DIE)

Install:

* [https://github.com/horsicq/DIE-engine](https://github.com/horsicq/DIE-engine)

---

## PE-bear

PE analysis.

Install:

* [https://github.com/hasherezade/pe-bear-releases](https://github.com/hasherezade/pe-bear-releases)

---

# 11. Recommended DevOps Stack

## Docker Desktop

Install:

* [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)

---

## Postman

API testing.

Install:

* [https://www.postman.com/downloads/](https://www.postman.com/downloads/)

---

# 12. Recommended UI Stack

| Option   | Recommendation   |
| -------- | ---------------- |
| Tauri    | Best choice      |
| Electron | Heavy but mature |
| Qt       | Native desktop   |
| React    | Frontend         |

---

# 13. Recommended Folder Structure

```text
D:\ForgeLens\
│
├── tools\
├── evidence\
├── cases\
├── scripts\
├── logs\
├── temp\
├── mobile\
├── images\
└── exports\
```

---

# 14. Environment Variables

Add to PATH:

```text
Python
Git
ADB
Sleuth Kit
ExifTool
YARA
Volatility
```

---

# 15. Recommended Hardware

| Component        | Recommendation     |
| ---------------- | ------------------ |
| RAM              | 32GB               |
| CPU              | Ryzen 7 / i7       |
| Storage          | NVMe SSD           |
| External Storage | 4TB+               |
| USB Hub          | Powered            |
| Write Blocker    | Hardware preferred |

---

# 16. Suggested Build Order

## Week 1

```text
[ ] Setup environment
[ ] Setup CLI
[ ] Setup imaging engine
[ ] Setup hashing engine
```

---

## Week 2

```text
[ ] Windows acquisition
[ ] Linux acquisition
[ ] Evidence logs
```

---

## Week 3

```text
[ ] Android support
[ ] RAM acquisition
[ ] Reporting engine
```

---

## Week 4

```text
[ ] GUI prototype
[ ] Autopsy integration
[ ] E01 export
```

---

# Tactical Advice

Do not install random forensic tools like a cyberpunk raccoon hoarding shiny objects.

Every tool should answer one question:

> Does this strengthen acquisition reliability, evidence integrity, or investigation speed?

If not:
cut it.

Your first real milestone should be:

```text
Acquire → Hash → Verify → Export → Analyze
```

That pipeline is the spine of the entire platform.
