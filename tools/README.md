# ForgeLens Tools Directory

Place third-party forensic binaries here. ForgeLens will auto-detect them.

## WinPmem (Windows RAM acquisition)

**Download:** https://github.com/Velocidex/WinPmem/releases

Place the executable here as one of:
- `winpmem.exe`
- `winpmem_mini_x64.exe`
- `winpmem_mini_x86.exe`

Or run the setup helper (requires internet access):

```
python tools/setup_winpmem.py
```

## DumpIt (alternative RAM acquisition)

**Download:** https://www.comae.com/

Place as `DumpIt.exe` in this directory.

## Usage after setup

```
python forgelens.py memory acquire --output evidence/memory.raw --case CASE-001 --examiner "Your Name"
```
