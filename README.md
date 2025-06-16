# 🛡️ Malware Evasion Techniques – TFG Repository

This repository contains the complete development and analysis of a final year thesis (TFG) focused on malware evasion techniques, combining offensive and defensive cybersecurity approaches. The project includes the creation of a custom malware sample, the design of a Command and Control (C2) infrastructure, and the reverse engineering of a real-world malware sample.

---

## 📚 Project Summary

The project aims to explore how far malware evasion techniques have evolved and how effective modern detection mechanisms are. It is divided into two main parts:

- **Development** of a custom malware sample that implements advanced evasion techniques.
- **Reverse engineering and analysis** of a real malware sample (**AZORult**) to compare and validate the techniques.

---

## 🧪 Part 1: Malware Sample Development

### 🔧 Objectives

- Develop a modular dropper in C#.
- Execute a PowerShell-based keylogger payload in memory (fileless).
- Bypass AMSI (Antimalware Scan Interface).
- Implement persistence via DLL proxying and scheduled tasks.
- Propagate via SMB shares and removable drives.
- Evade detection by sandboxes, virtual machines, and debuggers.

### 🧱 Architecture

- **Dropper**: Written in C#, it downloads and executes a payload in memory using reflection.
- **Payload**: A PowerShell keylogger, obfuscated and encrypted using RC4.
- **Stub DLL**: Executes PowerShell scripts using `System.Management.Automation`.
- **Persistence**: Achieved via DLL hijacking (7-Zip) and Windows Task Scheduler.
- **C2 Server**: Built with Flask (Python), serves payloads and receives keystrokes over HTTPS.

### 🛡️ Evasion Techniques Implemented

- **Static evasion**: Obfuscation, packing, cryptors, AMSI bypass, steganography.
- **Dynamic evasion**: VM detection, sandbox evasion, debugger checks, sleep skipping.
- **Living off the Land (LotL)**: Uses legitimate Windows tools like PowerShell and Task Scheduler.
- **Reflective loading**: Executes DLLs and payloads directly in memory.

### 🧪 Testing

- Tested in a controlled lab with VirtualBox (Windows 10, Kali Linux).
- Snapshots used to ensure safe execution.
- Detection tested with **VirusTotal** and a real **EDR (Cytomic by Panda Security)**.

---

## 🔍 Part 2: Reverse Engineering of AZORult

### 🧾 Sample Details

- **Malware**: AZORult (Win32.Unclassified)
- **Source**: [theZoo GitHub repository](https://github.com/ytisf/theZoo)
- **Language**: Delphi (payload), C# (dropper)
- **Behavior**: Credential theft, data exfiltration, memory injection

### 🔬 Static Analysis

**Tools**: DIE, ILSpy, binwalk, entropy analysis

**Findings**:
- Packed and obfuscated with **ConfuserEx**
- High entropy in `.text` section
- Embedded resources (payloads) encrypted and executed via reflection

### ⚙️ Dynamic Analysis

**Tools**: JoeSandbox, Any.Run, VirusTotal

**Observations**:
- Process hollowing
- Memory allocation with `VirtualAlloc`
- Data exfiltration via HTTP POST disguised as `image/jpeg`
- Access to browser data, wallets, registry, and system info

---

## 🧠 MITRE ATT&CK Mapping

Both the custom malware and AZORult were mapped to ATT&CK techniques, including:

- `T1027` – Obfuscated Files
- `T1055.012` – Process Hollowing
- `T1497` – Virtualization/Sandbox Evasion
- `T1140` – Deobfuscate/Decode
- `T1573` – Encrypted Channel
- `T1036.008` – Masquerade File Type

---

## 🗂️ Repository Structure

TFG-Malware-Evasion/
│

├── docs/ # Academic documentation

├── malware_sample/ # Source code of the developed malware

├── c2_server/ # Flask-based C2 server

├── utils/ # Scripts for entropy, encoding, encryption

├── diagrams/ # Network and execution flow diagrams

├── README.md # This file

└── SECURITY.md # Ethical use disclaimer


---

## ⚙️ Technologies Used

- **C# / .NET** – Malware development  
- **Python / Flask** – Command and Control server  
- **PowerShell** – Payload scripting  
- **VirtualBox / Kali Linux / Windows 10** – Testing environment  
- **VirusTotal / JoeSandbox / ILSpy / DIE** – Malware analysis tools  

---

## 🚨 Ethical Disclaimer

> This project is strictly for educational and research purposes.  
> The code and techniques demonstrated here must **not be used** in real-world environments or for malicious purposes.  
> Always conduct malware research in isolated, controlled environments.

See [`SECURITY.md`](SECURITY.md) for more details.

