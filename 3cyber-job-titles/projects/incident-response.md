# 🧨 Incident Response Case Study – Ransomware Simulation  

**Role:** Incident Responder  
**Skills:** Incident Response, Digital Forensics, Malware Analysis  
**Tools:** Volatility, Autopsy, Wireshark, YARA, FTK Imager  

---

## 🧩 Overview  

This project simulates a **ransomware attack in a controlled lab environment** to walk through each phase of the **Incident Response Lifecycle** — from initial detection to full recovery.  

The lab emphasizes **forensic analysis, evidence collection, containment, eradication, and lessons learned**, mimicking the workflow of a real SOC investigation.

---

## 🧠 Objective  

To investigate and respond to a simulated ransomware infection on a Windows host. The exercise aims to:  

- Identify the **infection vector and root cause**  
- Capture volatile data for **memory and disk analysis**  
- Recover and analyze **malware samples** using forensic tools  
- Create a comprehensive **Incident Response (IR) Report** with Indicators of Compromise (IOCs), event timeline, and mitigation steps  

---

## ⚙️ Lab Environment  

| Component | Description |
|------------|-------------|
| **Victim Machine** | Windows 10 (infected with simulated ransomware payload) |
| **Analysis VM** | Ubuntu with Autopsy, Volatility, YARA |
| **Network Capture** | Wireshark for packet analysis |
| **Storage** | External image of infected system created using FTK Imager |

---

## 🧾 Incident Timeline  

| Phase | Description | Tools Used |
|-------|--------------|------------|
| **Preparation** | Configured isolated lab VMs and baseline snapshots | VirtualBox, CloneZilla |
| **Identification** | Detected unusual file encryption and ransom note (`READ_ME.txt`) | Windows Defender, Event Viewer |
| **Containment** | Disconnected system from network to stop spread | PowerShell, pfSense |
| **Eradication** | Removed malicious processes and registry entries | Autoruns, Regedit |
| **Recovery** | Restored clean backups and validated system integrity | Windows Backup, SHA256 checksum |
| **Lessons Learned** | Documented root cause and improved email filtering rules | Office 365 Security, Proofpoint simulation |

---

## 🔍 Forensic Analysis  

### 1. Memory Acquisition  

Memory image collected using **FTK Imager** and analyzed via **Volatility**:

```bash
volatility -f memdump.raw --profile=Win10x64 pslist
volatility -f memdump.raw malfind --dump-dir=./malfind/
volatility -f memdump.raw netscan > network_connections.txt
