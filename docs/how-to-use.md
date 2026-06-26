# ForgeLens: Step-by-Step User Guide

Welcome to the **ForgeLens User Guide**! This guide is designed for investigators, analysts, and managers who need to operate ForgeLens to collect and analyze digital evidence, without needing any software programming or command-line expertise.

---

## 1. Launching and Logging In

To start your investigation, we first need to open the application and log into your workspace.

1. **Start the App**: Open your terminal or shortcut launcher and run:
   ```bash
   python forgelens.py gui
   ```
2. **Log In**: If security credentials are enabled on your workstation:
   - Select the **Auth** prompt or button.
   - Enter your assigned **Username** and **Password** (e.g. `Priyansh` / `Examiner`).
   - Click **Submit**. You will now see the main dashboard.

---

## 2. Setting Up a New Case

Before collecting any evidence, you must create a "case container." This organizes all files and ensures logs are kept separately.

1. Navigate to the **Cases** tab in the left sidebar (marked by the folder icon `🗂`).
2. Click the **New Case** button.
3. Fill in the following details:
   - **Case ID**: A unique identifier for the project (e.g., `CASE-2026-XYZ`).
   - **Lead Examiner**: Your name (this is stamped onto the audit log).
   - **Case Title**: A short name (e.g., `Marketing Server Audit`).
   - **Priority**: Select from Low, Medium, High, or Critical.
4. Click **Create Case**. You are now ready to collect data.

---

## 3. Safely Copying Storage Drives (Acquisition)

Now we will make a byte-perfect copy of the target device (like a USB drive or hard disk) for analysis.

1. Connect the target storage drive to the workstation.
2. Go to the **Devices** tab (`⛁`) and click **Scan Devices** to see all connected drives. Note the device path (e.g., `\\.\PhysicalDrive1`).
3. Click the **Acquisition** tab (`⬇`).
4. Fill out the collection settings:
   - **Source Device**: Select your scanned drive from the list.
   - **Output Folder**: Choose where to store the files safely (defaults to your evidence folder).
   - **Case ID**: Enter the Case ID you created in Section 2.
   - **Hashing Method**: Select `SHA-256` (this calculates the unique digital fingerprint of the copy).
5. Click **Start Acquisition**.
6. **Watch Progress**: A status bar will track the progress. Once completed, a green checkmark `✔` indicates the data is successfully verified and locked.

---

## 4. Analysing System Memory (RAM)

System memory contains live information that disappears when a computer shuts down.

1. Go to the **Memory** tab (`🧠`).
2. Click **Acquire RAM** (if you need to capture live memory) or **Load Memory Dump** (if you are reviewing a file collected earlier).
3. Switch between analysis sub-panels:
   - **Processes**: Review what programs were running. Look for unfamiliar names.
   - **Network Connections**: Inspect what websites or remote servers the computer was communicating with.
   - **Malfind**: Scan for hidden software code injected into system utilities.

---

## 5. Hunting for Cyber Threats

ForgeLens automatically scans the collected evidence files to find hacker footprints.

1. Go to the **DFIR** tab (`🛡`).
2. Click **Run Full Triage**.
3. **Inspect Alerts**: ForgeLens will list threats labeled with color-coded severity:
   - > [!CAUTION]
     > **CRITICAL** (Red): Active malware, ransomware notes, or registry modifications that start virus programs automatically.
   - > [!WARNING]
     > **HIGH** (Orange): Secret internet traffic beacons communicating with unauthorized IP addresses.
   - > [!NOTE]
     > **MEDIUM / LOW** (Yellow/Dim): Security configurations that could be hardened.
4. Click on any threat row to view specific details, including the file path and potential MITRE ATT&CK technique IDs.

---

## 6. Exporting and Verifying the Evidence Report

Once your analysis is complete, you must export the case logs and reports to present to managers or legal departments.

1. Go to the **Evidence** tab (`🔒`).
2. Choose your case from the dropdown.
3. Select the evidence item and click **Generate Report**.
4. Choose your preferred format:
   - **HTML Report**: A clean, printable web page summary.
   - **JSON / Text**: Detailed spreadsheets for tech teams.
5. **Chain of Custody**: Scroll down to review the tamper-evident event log. This lists every action taken (Created, Verified, Mounted, Tagged) with precise timestamps, ensuring that the evidence is courtroom-grade and verifiable.
