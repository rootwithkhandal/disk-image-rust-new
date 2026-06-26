# ForgeLens: Non-Technical Showcase & Overview Guide

Welcome to the **ForgeLens Showcase Guide**! This guide is designed to introduce **ForgeLens** to non-technical stakeholders, decision-makers, and clients. It explains the core concepts of digital forensics using simple real-world analogies, explains why ForgeLens is valuable, and provides a visual tour of all the platform's core modules.

---

## What is ForgeLens? (The Digital Detective)

Imagine a physical crime scene. Detectives seal the area, take photos of evidence, and collect fingerprints—all while keeping a strict log of who touched what. If they don't do this carefully, the evidence can't be used in court.

**ForgeLens** does exactly the same thing, but in the **digital world**. 

When a computer, phone, or cloud server is hacked or involved in a security incident, ForgeLens helps security teams investigate and respond. It serves as a unified suite of tools designed to preserve evidence, detect hackers, and enable collaboration.

---

## Why ForgeLens Matters (Value Proposition)

- **Tamper-Evident Security**: ForgeLens uses an immutable "blockchain-style" ledger. Once evidence is recorded, it's impossible to modify it without triggering an alarm.
- **Speed**: During a hack, every second counts. ForgeLens can triage and analyze memory in minutes instead of hours.
- **Cross-Platform**: It works on Windows, Mac, Linux, Android, iOS, and even cloud environments (like AWS and Google Cloud).
- **Customizable**: You can hide or enable specific modules (like DFIR or Cloud Forensics) using a simple configuration file depending on the investigator's role or showcase focus.
- **Beautiful User Interface**: Unlike traditional command-line security tools, ForgeLens features a modern, easy-to-use visual dashboard that anyone can navigate.

---

## A Tour of ForgeLens Modules

Here is a step-by-step walkthrough of how investigators use each of the enabled modules in the ForgeLens suite.

### 1. The Command Center (The Dashboard)

When an investigator opens ForgeLens, they are greeted by the **Dashboard**. This is the control room of the investigation.

![ForgeLens Dashboard Mockup](file:///C:/Users/ipriyansh/.gemini/antigravity-ide/brain/079b26b5-a306-4040-8f70-c5b19a01bedc/forgelens_dashboard_1781104005196.png)

> [!NOTE]
> **What you're seeing:**
> - **Top Metrics**: Quick counts of active cases, items of evidence securely stored, and scanned storage devices.
> - **System Diagnostics**: Real-time status of the computer running the tool.
> - **Capabilities Check**: A checklist showing that all core modules (Disk Imaging, AI Analysis, YARA scanning) are active and healthy.
> - **Quick Actions**: One-click shortcuts to jump straight to case management, device scanning, or starting a new evidence collection process.

---

### 2. Secure Evidence Collection (Acquisition)

To investigate a system, we must first collect the data. This view allows investigators to select what they want to copy (such as a hard drive or system memory) and where to store it securely.

![ForgeLens Acquisition View Mockup](file:///C:/Users/ipriyansh/.gemini/antigravity-ide/brain/079b26b5-a306-4040-8f70-c5b19a01bedc/forgelens_acquisition_1781104022421.png)

> [!IMPORTANT]
> **Key Concepts Explained:**
> - **Forensic Copying (Imaging)**: Instead of copy-pasting files (which changes their "last accessed" date metadata), ForgeLens makes a bit-by-bit exact replica of the storage drive.
> - **Digital Fingerprinting (Hashing)**: ForgeLens calculates a unique code (hash) for the evidence. If even a single letter in a file is modified later, the code changes, proving the evidence was tampered with.
> - **Live Activity Log**: The scrollable window at the bottom shows real-time progress and verification milestones during collection.

---

### 3. Memory Forensics (Extracting RAM Secrets)

System memory (RAM) is like short-term memory—it holds active secrets that vanish when the computer is turned off, such as passwords, active network connections, and running viruses. ForgeLens extracts RAM and uses the Volatility3 engine to analyze it.

![ForgeLens Memory Forensics Mockup](file:///C:/Users/ipriyansh/.gemini/antigravity-ide/brain/079b26b5-a306-4040-8f70-c5b19a01bedc/forgelens_memory_1781104320352.png)

> [!TIP]
> **Key Features of Memory Analysis:**
> - **Process Explorer**: Displays a list of all active programs running in memory at the time of the capture.
> - **Malfind Injection Detection**: Scans system memory for "process hollowing"—a trick where hackers inject malicious code into trusted programs (like `explorer.exe`).
> - **Registry Hashes**: Extracts password digests directly from system memory to find compromised accounts.

---

### 4. Hunting for Hackers (DFIR Threat Hunting)

Once data is gathered, ForgeLens acts like a digital bloodhound. It scans files and processes to find suspicious patterns, malicious software (malware), and hacker activity.

![ForgeLens DFIR Threat Hunting Mockup](file:///C:/Users/ipriyansh/.gemini/antigravity-ide/brain/079b26b5-a306-4040-8f70-c5b19a01bedc/forgelens_dfir_1781104035583.png)

> [!WARNING]
> **How it detects threats:**
> - **Risk Badges**: Automatically flags found anomalies as **CRITICAL**, **HIGH**, or **MEDIUM** risk.
> - **Persistence Hunting**: Hackers love to hide programs that start automatically when the computer boots up. ForgeLens scans these registry and boot areas to find hidden startup files.
> - **C2 Beaconing**: Detects computers that are secretly sending signals back to hacker servers (beacons) at regular intervals.
> - **Security Scan Pane (Right)**: Selecting any threat shows deep details, such as file entropy (whether it is encrypted or hidden) and matches against virus signature databases (YARA rules).

---

### 5. Mobile & Device Forensics (Smartphones & Tablets)

Smartphones hold the most personal and critical timelines. The Mobile Forensics module connects to Android and iOS devices.

- **Logical Backups**: Securely pulls call logs, contacts, messages, and photos.
- **SQLite Deleted Record Recovery**: Scans message database files (like WhatsApp or Signal) for deleted chat logs and reconstructs them from database slack space.
- **Enclave Analysis**: Maps iOS keychain items and documents Secure Enclave Processor (SEP) status.

---

### 6. Cloud & Container Forensics (Virtual Landscapes)

Modern businesses run in the cloud. ForgeLens connects to cloud infrastructures (AWS, GCP, Azure) and container systems (Docker, Kubernetes) to track incidents.

- **Volume Snapshots**: Instantaneous, read-only backups of running virtual server drives (e.g. AWS EBS snapshots).
- **Cluster Timeline**: Unified activity charts tracking Kubernetes service deployments, API calls, and audit logs to pinpoint cluster breaches.
- **Container Isolation**: Acquires memory and filesystems from Docker containers without stopping the production service.

---

### 7. Battlefield Collaboration & Fused Timelines

Large investigations involve multiple investigators. The **Battlefield Edition (v3.0)** lets teams coordinate, share notes, and fuse evidence timelines from different machines into a single storyline.

![ForgeLens Battlefield Edition Mockup](file:///C:/Users/ipriyansh/.gemini/antigravity-ide/brain/079b26b5-a306-4040-8f70-c5b19a01bedc/forgelens_battlefield_1781104331039.png)

> [!IMPORTANT]
> **Collaboration Highlights:**
> - **Immutable Ledger**: Uses a cryptographically linked ledger (hash-chain) to ensure that the audit log of who handled the evidence is courtroom-grade and completely tamper-proof.
> - **Timeline Fusion**: Merges logs from Windows events, memory dumps, mobile databases, and cloud audit logs to show the *exact* progression of a hacker's attack.
> - **Distributed Agents**: Allows dispatching acquisition tasks to multiple endpoint systems simultaneously, coordinating data collection in one dashboard.
