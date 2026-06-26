# ForgeLens — Manual Test Checklist

Work through this list top to bottom. Each item is a discrete test you can run and tick off.
Mark items: ✅ pass  ❌ fail  ⚠ partial  ⏭ skipped (tool/device not available)

---

## 0. Environment Sanity

| # | Test | Command | Expected |
|---|---|---|---|
| 0.1 | Python version | `python --version` | 3.10+ |
| 0.2 | Virtual env active | `.pyenv\Scripts\activate` then `where python` | points to `.pyenv` |
| 0.3 | CLI launches | `python forgelens.py --help` | shows command list, no errors |
| 0.4 | Version command | `python forgelens.py version` | prints version string |
| 0.5 | Dependency check | `python forgelens.py setup check` | shows Required / Optional tables |

---

## 1. Authentication

| # | Test | Command / Steps | Expected |
|---|---|---|---|
| 1.1 | Auth disabled by default | `python forgelens.py auth status` | Auth gate: DISABLED |
| 1.2 | Commands work without login | `python forgelens.py devices` | runs without prompting for password |
| 1.3 | Enable auth | `python forgelens.py auth enable` | prompts for admin username + password |
| 1.4 | Admin account created | `python forgelens.py auth status` | shows 1 user, role=admin |
| 1.5 | Login | `python forgelens.py auth login` | prompts credentials, shows "Logged in as..." |
| 1.6 | Whoami | `python forgelens.py auth whoami` | shows username, role, expiry |
| 1.7 | Session persists | open new terminal, `python forgelens.py auth whoami` | still logged in (same session) |
| 1.8 | Commands work after login | `python forgelens.py devices` | runs normally |
| 1.9 | Add examiner user | `python forgelens.py auth user-add testuser --role examiner` | enter password twice, user created |
| 1.10 | Add analyst user | `python forgelens.py auth user-add reader --role analyst` | user created |
| 1.11 | List users | `python forgelens.py auth status` | shows all 3 users |
| 1.12 | Wrong password lockout | `python forgelens.py auth login` — type wrong password 3× | "Too many failed attempts. Wait 30s" |
| 1.13 | Lockout expires | wait 30s, try login again | accepts correct credentials |
| 1.14 | Change password | `python forgelens.py auth passwd testuser` | enter new password, success |
| 1.15 | Login with new password | `python forgelens.py auth logout` then `auth login` as testuser | success with new password |
| 1.16 | Change role | `python forgelens.py auth user-role testuser analyst` | role updated |
| 1.17 | Deactivate user | `python forgelens.py auth user-remove reader --force` | user deactivated |
| 1.18 | Deactivated user can't login | try `auth login` as reader | fails (inactive) |
| 1.19 | Logout | `python forgelens.py auth logout` | "Logged out (username)" |
| 1.20 | Command blocked after logout | `python forgelens.py devices` | prompts for login |
| 1.21 | Disable auth | `python forgelens.py auth login` (admin), then `auth disable` | confirms, auth disabled |
| 1.22 | Commands open again | `python forgelens.py devices` | runs without password prompt |

---

## 2. Device Detection

| # | Test | Command | Expected |
|---|---|---|---|
| 2.1 | List physical disks | `python forgelens.py devices` | table of disks with size/interface/serial |
| 2.2 | Enumerate partitions | `python forgelens.py enumerate "\\.\PhysicalDrive0"` | partition table, filesystems |
| 2.3 | Android detection | Connect Android phone with USB debugging, `python forgelens.py devices --android` | device listed with model/version |
| 2.4 | Detect all | `python forgelens.py acquire detect` | disks + Android + iOS tables |

---

## 3. Hashing & Verification

| # | Test | Command | Expected |
|---|---|---|---|
| 3.1 | Hash a file (sha256) | `python forgelens.py hash file README.md --algo sha256` | SHA256 digest printed |
| 3.2 | Hash a file (md5) | `python forgelens.py hash file README.md --algo md5` | MD5 digest printed |
| 3.3 | Multi-hash | `python forgelens.py hash file README.md --multi` | SHA256 + MD5 + SHA1 all printed |
| 3.4 | Verify pass | run 3.1, copy hash, then `python forgelens.py hash verify README.md <HASH> --algo sha256` | ✔ VERIFIED |
| 3.5 | Verify fail | `python forgelens.py hash verify README.md aaaa1234 --algo sha256` | ✘ MISMATCH, exit 1 |
| 3.6 | BLAKE3 hash | `python forgelens.py hash file README.md --algo blake3` | BLAKE3 digest (or "blake3 not installed") |

---

## 4. Case Management

| # | Test | Command | Expected |
|---|---|---|---|
| 4.1 | Create case | `python forgelens.py case create TEST-001 --examiner "You" --title "Test case" --tags "test" --priority high` | ✔ Case created |
| 4.2 | List cases | `python forgelens.py cases` | TEST-001 in list |
| 4.3 | List by status | `python forgelens.py case list --status open` | TEST-001 shown |
| 4.4 | Update status | `python forgelens.py case update TEST-001 --status active` | updated |
| 4.5 | Search | `python forgelens.py case search "test"` | finds TEST-001 |
| 4.6 | Audit trail | `python forgelens.py case audit TEST-001` | empty or with events |

---

## 5. Disk Imaging

> Run as Administrator on Windows.

| # | Test | Command | Expected |
|---|---|---|---|
| 5.1 | Image a small file (simulated) | Create 10 MB test file: `fsutil file createnew test10mb.bin 10485760` then `python forgelens.py image acquire --source test10mb.bin --output evidence --case TEST-001 --examiner "You"` | ✔ Acquisition complete, SHA256 shown |
| 5.2 | Verify image created | `dir evidence\cases\TEST-001\` | EV-XXXXXXXX folder with image + hashes + metadata.json |
| 5.3 | Post-verification pass | check output — "Verified: PASS" | ✔ |
| 5.4 | E01 format | same as 5.1 but add `--format e01` | .e01 file created |
| 5.5 | No-verify flag | add `--no-verify` | image created, verified=false in metadata |
| 5.6 | Export report | `python forgelens.py export report --case TEST-001 --evidence EV-XXXXXXXX --formats "html,json,text"` | 3 report files created |
| 5.7 | View chain of custody | `python forgelens.py export custody --case TEST-001 --evidence EV-XXXXXXXX` | table of events |

---

## 6. Disk Mounting

> Windows only for 6.1–6.4. Linux/macOS for 6.5–6.6.

| # | Test | Command | Expected |
|---|---|---|---|
| 6.1 | Mount without tool (should fail gracefully) | `python forgelens.py image mount evidence\...\EV-XXXXXXXX.dd --drive Z` | clear error with install instructions |
| 6.2 | Install ImDisk | `python forgelens.py setup mounter` | download/install instructions shown |
| 6.3 | Mount after ImDisk install (run as Admin) | `python forgelens.py image mount evidence\...\EV-XXXXXXXX.dd --drive Z --case TEST-001 --evidence EV-XXXXXXXX` | ✔ Mounted at Z:\ |
| 6.4 | List mounts | `python forgelens.py image mounts` | table showing Z:\ mount |
| 6.5 | Browse mount | `dir Z:\` (Windows) or `ls /mnt/forgelens_*` (Linux) | files visible |
| 6.6 | Unmount | `python forgelens.py image unmount <MOUNT_ID>` | ✔ Unmounted |
| 6.7 | Unmount all | `python forgelens.py image unmount ALL` | "0 images currently mounted" after |

---

## 7. Memory Forensics

| # | Test | Command | Expected |
|---|---|---|---|
| 7.1 | Setup WinPmem | `python forgelens.py memory setup` | "Already present" or downloads |
| 7.2 | Check WinPmem found | `python forgelens.py setup check` | WinPmem ✔ OK |
| 7.3 | Acquire RAM (run as Admin) | `python forgelens.py memory acquire --output evidence\memory.raw --case TEST-001 --examiner "You"` | dump written, SHA256 shown |
| 7.4 | List processes | `python forgelens.py memory processes evidence\...\EV-XXXXXXXX.raw` | process table (may take 5–20 min first time) |
| 7.5 | Suspicious processes only | add `--suspicious` | filtered list |
| 7.6 | Network connections | `python forgelens.py memory connections evidence\...\EV-XXXXXXXX.raw` | connection table |
| 7.7 | DLL list | `python forgelens.py memory dlls evidence\...\EV-XXXXXXXX.raw` | DLL table |
| 7.8 | Malfind | `python forgelens.py memory malfind evidence\...\EV-XXXXXXXX.raw` | "No injected code" or findings |
| 7.9 | Memory timeline | `python forgelens.py memory timeline evidence\...\EV-XXXXXXXX.raw --output evidence\timeline.json` | timeline JSON written |
| 7.10 | Export processes to JSON | `python forgelens.py memory export evidence\...\EV-XXXXXXXX.raw --output evidence\memory_export.json` | JSON with processes + connections |

---

## 8. Evidence Vault

| # | Test | Command | Expected |
|---|---|---|---|
| 8.1 | Tag evidence | `python forgelens.py vault tag --case TEST-001 --evidence EV-XXXXXXXX "test,windows"` | tags added |
| 8.2 | Search by tag | `python forgelens.py vault search --tag test` | EV-XXXXXXXX shown |
| 8.3 | Search by case | `python forgelens.py vault search --case TEST-001` | evidence listed |
| 8.4 | Rebuild index | `python forgelens.py vault index` | N items indexed |
| 8.5 | Vault repair | `python forgelens.py vault repair --dry-run` | shows what would be repaired |
| 8.6 | Encrypt a file | `python forgelens.py vault encrypt README.md --output README.md.enc` | .enc created, .key created |
| 8.7 | Decrypt file | `python forgelens.py vault decrypt README.md.enc --key README.key --output README_dec.md` | decrypted file matches original |
| 8.8 | Verify decryption | `python forgelens.py hash verify README_dec.md <original_hash>` | ✔ VERIFIED |
| 8.9 | Sign metadata | (requires vault encrypt key) `python forgelens.py vault verify-sig --case TEST-001 --evidence EV-XXXXXXXX --key README.key` | VALID or "no signed metadata" |
| 8.10 | Cleanup test files | `del README.md.enc README.key README_dec.md` | — |

---

## 9. Platform Acquisition — Windows

> Run as Administrator.

| # | Test | Command | Expected |
|---|---|---|---|
| 9.1 | Windows live artifacts (no RAM) | `python forgelens.py acquire windows --case TEST-001 --examiner "You" --output evidence\win` | processes, connections, tasks, drives counted |
| 9.2 | Windows live + RAM | add `--memory` to above | RAM dump also acquired |
| 9.3 | Evidence created | `python forgelens.py vault search --case TEST-001` | new EV entry |

---

## 10. Platform Acquisition — Linux

> Run on a Linux system or WSL.

| # | Test | Command | Expected |
|---|---|---|---|
| 10.1 | Linux artifacts | `python forgelens.py acquire linux --case TEST-001 --examiner "You" --output /evidence/linux` | block devices, artifacts collected |
| 10.2 | Linux + RAM (requires AVML/root) | add `--memory` | AVML or LiME acquires RAM |

---

## 11. Platform Acquisition — macOS

> Run on a macOS system.

| # | Test | Command | Expected |
|---|---|---|---|
| 11.1 | macOS artifacts | `python forgelens.py acquire macos --case TEST-001 --examiner "You" --output /evidence/macos` | APFS, FileVault, logs collected |

---

## 12. Platform Acquisition — Android

> Requires: Android phone with USB debugging enabled.

| # | Test | Command | Expected |
|---|---|---|---|
| 12.1 | Detect device | `python forgelens.py acquire detect` | Android device shown |
| 12.2 | Basic acquisition | `python forgelens.py acquire android --case TEST-001 --examiner "You" --output evidence\android` | installed apps, media collected; SMS/contacts may need root |
| 12.3 | Deep artifacts | `python forgelens.py mobile android-deep --output evidence\android-deep` | /proc, dmesg collected |
| 12.4 | Keystore info | `python forgelens.py mobile android-keystore --output evidence\keystore` | keystore enumeration + secure enclave doc |
| 12.5 | SQLite recovery (test with a db) | Pull mmssms.db manually, then `python forgelens.py mobile android-recover mmssms.db --output evidence\recovery` | recovery summary JSON |
| 12.6 | Full filesystem (root only) | `python forgelens.py mobile android-filesystem --output evidence\android-fs --method tar_root` | filesystem.tar created |

---

## 13. Platform Acquisition — iOS

> Requires: iPhone/iPad unlocked and trusted.

| # | Test | Command | Expected |
|---|---|---|---|
| 13.1 | Detect device | `python forgelens.py acquire detect` | iOS device shown |
| 13.2 | iTunes backup | `python forgelens.py acquire ios --case TEST-001 --examiner "You" --output evidence\ios` | backup extracted |
| 13.3 | SEP research doc | `python forgelens.py mobile ios-sep --output evidence\ios` | sep_keybag_research.json written |
| 13.4 | Crash logs | `python forgelens.py mobile ios-crashes --output evidence\ios-crashes` | crash reports collected |
| 13.5 | Full filesystem (jailbreak only) | `python forgelens.py mobile ios-filesystem --method afc2 --output evidence\ios-fs` | filesystem extracted |

---

## 14. Offensive DFIR

| # | Test | Command | Expected |
|---|---|---|---|
| 14.1 | Persistence hunt | `python forgelens.py dfir persist --output evidence\dfir` | findings table (Run keys, tasks, etc.) |
| 14.2 | Beacon detection (from JSON) | `python forgelens.py dfir beacons --connections evidence\...\EV-XXXXXXXX.processes.json --output evidence\dfir` | findings or "No C2 beaconing detected" |
| 14.3 | Credential theft (from dump) | `python forgelens.py dfir creds --dump evidence\...\EV-XXXXXXXX.raw --output evidence\dfir` | credential findings |
| 14.4 | Ransomware triage | `python forgelens.py dfir ransomware C:\Users --output evidence\dfir --max-files 1000` | ransom notes, encrypted exts, blast radius |
| 14.5 | Lateral movement | `python forgelens.py dfir lateral --output evidence\dfir` | logon paths, share access |
| 14.6 | Full triage | `python forgelens.py dfir full-triage C:\ --output evidence\dfir` | 5 JSON reports written |
| 14.7 | Verify JSON output | check `evidence\dfir\dfir_persistence.json` exists and has findings | valid JSON |

---

## 15. Cloud & Container Forensics

> Requires appropriate CLIs installed and authenticated.

| # | Test | Command | Expected |
|---|---|---|---|
| 15.1 | AWS collect (if configured) | `python forgelens.py cloud aws-collect --output evidence\aws` | IAM/EC2/VPC JSON files written |
| 15.2 | Docker collect (if Docker running) | `python forgelens.py cloud docker-collect --output evidence\docker` | containers/images/volumes JSON |
| 15.3 | Docker acquire a container | `docker run -d --name test-nginx nginx` then `python forgelens.py cloud docker-acquire test-nginx --output evidence\docker` | filesystem tar + metadata |
| 15.4 | Docker cleanup | `docker stop test-nginx && docker rm test-nginx` | — |
| 15.5 | K8s collect (if kubectl configured) | `python forgelens.py cloud k8s-collect --output evidence\k8s` | pod/service/event JSONs |
| 15.6 | K8s timeline | `python forgelens.py cloud k8s-timeline --output evidence\k8s` | timeline JSON |

---

## 16. V3.0 — Immutable Ledger

| # | Test | Command | Expected |
|---|---|---|---|
| 16.1 | Migrate CoC to ledger | `python forgelens.py v3 ledger TEST-001 --migrate` | N events migrated |
| 16.2 | View ledger | `python forgelens.py v3 ledger TEST-001` | table of entries with hash previews |
| 16.3 | Verify chain (clean) | `python forgelens.py v3 ledger TEST-001 --verify` | ✔ CHAIN VALID — N entries verified |
| 16.4 | Export ledger | `python forgelens.py v3 ledger TEST-001 --export evidence\ledger_export.json` | JSON file written |
| 16.5 | Tamper detection | manually edit one entry in `evidence/cases/TEST-001/*/ledger.jsonl`, then re-run verify | ✘ TAMPERING DETECTED at seq=X |
| 16.6 | Restore ledger | revert the manual edit, verify again | ✔ CHAIN VALID |

---

## 17. V3.0 — Threat Graph

| # | Test | Command | Expected |
|---|---|---|---|
| 17.1 | Build graph from processes JSON | `python forgelens.py v3 graph TEST-001 --output evidence\graph --processes evidence\...\EV-XXXXXXXX.processes.json` | JSON + DOT files created |
| 17.2 | Check JSON output | open `evidence\graph\TEST-001_threat_graph.json` | valid JSON with nodes/edges/summary |
| 17.3 | Check DOT output | open `evidence\graph\TEST-001_threat_graph.dot` | valid DOT format |
| 17.4 | Render DOT (if Graphviz installed) | `dot -Tpng evidence\graph\TEST-001_threat_graph.dot -o evidence\graph\graph.png` | graph.png created |
| 17.5 | STIX export | add `--stix` to 17.1 | STIX 2.1 JSON bundle created |
| 17.6 | Verify STIX format | check `TEST-001_stix.json` starts with `{"type":"bundle"` | valid STIX 2.1 |

---

## 18. V3.0 — Timeline Fusion

| # | Test | Command | Expected |
|---|---|---|---|
| 18.1 | Auto-fuse from vault | `python forgelens.py v3 timeline-fuse TEST-001 --output evidence\timeline.json` | fused timeline JSON |
| 18.2 | Check output | open `evidence\timeline.json` | valid JSON with events array |
| 18.3 | Multi-source fusion | create two process JSON files, `python forgelens.py v3 timeline-fuse TEST-001 --output evidence\timeline.json --source "host1:memory:file1.json" --source "host2:events:file2.json"` | merged timeline from both sources |
| 18.4 | Suspicious only | add `--suspicious` | only is_suspicious=true events |
| 18.5 | Check correlated clusters | verify `correlated_clusters` array in output JSON | present (may be empty if no cross-device data) |

---

## 19. V3.0 — Distributed Acquisition

> Requires two ForgeLens instances running as agents on separate machines or ports.

| # | Test | Command | Expected |
|---|---|---|---|
| 19.1 | Register agent | `python forgelens.py v3 agent-add http://localhost:8765 --token secret1 --label "Test-Agent"` | agent registered |
| 19.2 | List agents | `python forgelens.py v3 agents` | agent shown with OFFLINE state |
| 19.3 | Ping agents | `python forgelens.py v3 ping` | ✔ or ✘ per agent |
| 19.4 | Dispatch job (agent must be online) | `python forgelens.py v3 acquire-all --case TEST-001 --examiner "You" --task live_response` | job dispatched |
| 19.5 | Check job report | output shows per-agent success/failure | job report printed |

---

## 20. V3.0 — Collaboration

| # | Test | Command | Expected |
|---|---|---|---|
| 20.1 | View dashboard | `python forgelens.py v3 collab TEST-001` | tasks/notes/annotations counts |
| 20.2 | Add note | `python forgelens.py v3 note --case TEST-001 --author alice "Test note for memory dump"` | ✔ Note added |
| 20.3 | Add note to evidence | add `--evidence EV-XXXXXXXX` | note linked to specific evidence |
| 20.4 | Assign task | `python forgelens.py v3 task --case TEST-001 --from alice --to bob "Analyse memory dump" --priority high` | ✔ Task assigned |
| 20.5 | Dashboard updated | `python forgelens.py v3 collab TEST-001` | note count +1, task count +1 |
| 20.6 | Case handoff | `python forgelens.py v3 handoff --case TEST-001 --from alice --to bob "Handing over for legal review"` | handoff record created |
| 20.7 | Check handoff file | `dir evidence\cases\TEST-001\*\collab\handoff_*.json` | JSON file exists |

---

## 21. V3.0 — API & SSE Streaming

| # | Test | Steps | Expected |
|---|---|---|---|
| 21.1 | Start API server | `uvicorn backend.api.server:app --reload --port 8000` | "Application startup complete" |
| 21.2 | Health check | `curl http://localhost:8000/api/health` | `{"status":"ok","version":"3.0.0"}` |
| 21.3 | List devices | `curl http://localhost:8000/api/devices` | JSON array of devices |
| 21.4 | List cases | `curl http://localhost:8000/api/v3/cases` | JSON with cases array |
| 21.5 | Get case | `curl http://localhost:8000/api/v3/cases/TEST-001` | TEST-001 case detail JSON |
| 21.6 | SSE stream | open `http://localhost:8000/api/v3/stream/TEST-001` in browser | page stays open, shows `: keep-alive` lines |
| 21.7 | Event published | while stream is open, run any vault/case command | SSE event appears in browser |
| 21.8 | Ledger verify | `curl -X POST http://localhost:8000/api/v3/cases/TEST-001/ledger/verify` | `{"valid":true,...}` |
| 21.9 | Get threat graph | `curl http://localhost:8000/api/v3/cases/TEST-001/graph` | JSON with nodes/edges |
| 21.10 | Get fused timeline | `curl http://localhost:8000/api/v3/cases/TEST-001/timeline` | JSON with events |
| 21.11 | Collab dashboard | `curl http://localhost:8000/api/v3/cases/TEST-001/collab` | dashboard JSON |

---

## 22. Setup & Dependency Management

| # | Test | Command | Expected |
|---|---|---|---|
| 22.1 | Full check | `python forgelens.py setup check` | Required all ✔, Optional shows status |
| 22.2 | Check all platforms | `python forgelens.py setup check --all` | shows tools for non-current OS too |
| 22.3 | Info reference | `python forgelens.py setup info` | categorised tool list with install hints |
| 22.4 | Install optional (dry run) | `python forgelens.py setup install --optional --dry-run` | shows what would be installed |
| 22.5 | WinPmem setup | `python forgelens.py memory setup` | "Already present" with SHA256 |
| 22.6 | Mounter setup | `python forgelens.py setup mounter` | ImDisk install instructions |
| 22.7 | AIM info | `python forgelens.py setup mounter --tool aim` | Arsenal Image Mounter instructions |

---

## 23. Reporting

| # | Test | Command | Expected |
|---|---|---|---|
| 23.1 | Generate HTML report | `python forgelens.py export report --case TEST-001 --evidence EV-XXXXXXXX --formats "html"` | report_EV-XXXXXXXX.html created |
| 23.2 | Open HTML report | open file in browser | acquisition details rendered |
| 23.3 | Generate JSON report | add `json` to formats | report_EV-XXXXXXXX.json created |
| 23.4 | Generate text report | add `text` | report_EV-XXXXXXXX.txt created |
| 23.5 | Chain of custody output | `python forgelens.py export custody --case TEST-001 --evidence EV-XXXXXXXX` | timestamped events table |

---

## 24. End-to-End Workflow

Run this as a complete smoke test after individual features pass.

| # | Step | Command |
|---|---|---|
| E1 | Enable auth | `python forgelens.py auth enable` |
| E2 | Login | `python forgelens.py auth login` |
| E3 | Create case | `python forgelens.py case create E2E-001 --examiner "You" --title "End-to-end test" --priority high` |
| E4 | Acquire disk image | `python forgelens.py image acquire --source test10mb.bin --output evidence --case E2E-001 --examiner "You"` |
| E5 | Acquire RAM | `python forgelens.py memory acquire --output evidence\e2e.raw --case E2E-001 --examiner "You"` |
| E6 | List processes | `python forgelens.py memory processes evidence\...\EV-XXXXXXXX.raw` |
| E7 | Export processes | `python forgelens.py memory export evidence\...\EV-XXXXXXXX.raw --output evidence\cases\E2E-001\EV-XXXXXXXX\EV-XXXXXXXX.processes.json` |
| E8 | Hunt persistence | `python forgelens.py dfir persist --output evidence\cases\E2E-001` |
| E9 | Migrate to ledger | `python forgelens.py v3 ledger E2E-001 --migrate` |
| E10 | Verify ledger | `python forgelens.py v3 ledger E2E-001 --verify` |
| E11 | Build threat graph | `python forgelens.py v3 graph E2E-001 --output evidence\cases\E2E-001\graph` |
| E12 | Fuse timeline | `python forgelens.py v3 timeline-fuse E2E-001 --output evidence\cases\E2E-001\timeline.json` |
| E13 | Add a note | `python forgelens.py v3 note --case E2E-001 --author "You" "End-to-end test complete"` |
| E14 | Generate report | `python forgelens.py export report --case E2E-001 --evidence EV-XXXXXXXX --formats "html,json"` |
| E15 | Verify chain of custody | `python forgelens.py export custody --case E2E-001 --evidence EV-XXXXXXXX` |
| E16 | Close case | `python forgelens.py case update E2E-001 --status closed` |
| E17 | Logout | `python forgelens.py auth logout` |

**All 17 steps passing = full platform is working end-to-end.**

---

## Notes

- Replace `EV-XXXXXXXX` with the actual evidence ID printed during acquisition
- Replace `evidence\...\EV-XXXXXXXX.raw` with the actual path shown after `memory acquire`
- Tests marked ⏭ are valid skips if the required device/tool/service is unavailable
- For Windows tests that require Administrator: right-click terminal → "Run as administrator"
- Volatility3 first-run will take 5–20 minutes to build symbol caches — this is normal
