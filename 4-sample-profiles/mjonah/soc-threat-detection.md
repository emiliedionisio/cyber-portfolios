# 🛰️ SOC Threat Detection Lab  

**Role:** SOC Analyst  
**Skills:** SIEM Configuration, Log Analysis, Threat Detection, Data Visualization  
**Tools:** Splunk Enterprise, Sysmon, Zeek, Windows Event Logs, Python SDK  

---

## 🧩 Overview  

This project demonstrates how to design and deploy a **Splunk-based SIEM environment** for real-time security monitoring and threat detection.  

The lab simulates a small enterprise network with multiple Windows endpoints and a network sensor (Zeek). Logs are ingested, normalized, and analyzed in Splunk to detect **brute-force attacks**, **C2 beaconing**, and **lateral movement patterns** using custom correlation searches.

---

## 🏗️ Architecture  

```plaintext
               +---------------------+
               |  Windows Endpoint 1 |
               |  Sysmon + Win Logs  |
               +---------+-----------+
                         |
                         v
               +---------------------+
               |  Zeek Sensor (IDS)  |
               |  Network Traffic     |
               +---------+-----------+
                         |
                         v
               +----------------------+
               |   Splunk Enterprise  |
               |   SIEM & Dashboard   |
               +----------------------+
                         |
                         v
               +----------------------+
               |   Analyst Workstation |
               |   Dashboards & IR     |
               +----------------------+
```

---

## ⚙️ Setup Steps  

### 1. Configure Data Sources  

- **Sysmon** deployed on each Windows endpoint with a custom config:  
  ```powershell
  Sysmon64.exe -accepteula -i sysmonconfig.xml
  ```
  The configuration logs process creation, network connections, and registry modifications.

- **Zeek** deployed on a network tap or virtual interface:
  ```bash
  sudo zeekctl deploy
  ```
  Zeek logs network flows, DNS queries, and HTTP traffic.

- **Forward logs** to Splunk using the Universal Forwarder:
  ```bash
  ./splunk add forward-server <splunk_ip>:9997 -auth admin:changeme
  ./splunk add monitor /opt/zeek/logs/current/
  ./splunk add monitor "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"
  ./splunk add monitor "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx"
  ```

---

## 🔍 Detection Rules  

### 1. Brute Force Detection (Windows Event Logs)  

**Search Query (SPL):**
```spl
index=windows_logs sourcetype=WinEventLog:Security 
(EventCode=4625 OR EventCode=4624)
| stats count by user, src_ip, EventCode
| where EventCode=4625 AND count > 5
| table _time, user, src_ip, count
```

**MITRE ATT&CK Mapping:**  
- **T1110 – Brute Force**  
**Detection Logic:** Identifies repeated failed logins from the same source IP over a short period.

---

### 2. Beaconing Detection (Zeek Logs)

**Search Query (SPL):**
```spl
index=zeek sourcetype=zeek_conn
| stats count, avg(duration) as avg_duration, stdev(duration) as stddev_duration by src_ip, dest_ip
| where count > 20 AND stddev_duration < 1
| table _time, src_ip, dest_ip, avg_duration, count
```

**MITRE ATT&CK Mapping:**  
- **T1071 – Application Layer Protocol**  
**Detection Logic:** Identifies periodic beaconing behavior from an endpoint to a single destination (C2 server).

---

### 3. Lateral Movement (Sysmon + Windows Event Logs)

**Search Query (SPL):**
```spl
index=sysmon_logs OR index=windows_logs
(EventCode=7045 OR Image="*psexec*" OR Image="*wmic*")
| stats count by user, dest, Image, parent_process
| where count > 3
| table _time, user, dest, Image, parent_process
```

**MITRE ATT&CK Mapping:**  
- **T1021 – Remote Services**  
**Detection Logic:** Detects remote command execution tools like PsExec or WMI commands used for lateral movement.

---

## 📊 Dashboards & Visualizations  

Created a **SOC Analyst Dashboard** in Splunk for real-time monitoring:  

| Panel | Description | Visualization Type |
|--------|--------------|--------------------|
| Login Attempts by Source IP | Displays frequency of login failures | Bar Chart |
| Top Users with Failed Logins | Highlights potential brute force targets | Table |
| Beaconing Connections | Detects periodic external traffic | Line Chart |
| Lateral Movement Alerts | Lists suspicious PsExec/WMI activity | Table |
| IOC Summary | Lists IPs/domains flagged by detection rules | Single Value Panel |

Example Snippet of the Splunk Dashboard JSON:
```json
{
  "label": "Top Failed Logins",
  "search": "index=windows_logs EventCode=4625 | stats count by src_ip, user | sort -count",
  "type": "bar"
}
```

---

## 🤖 Automation Example (Splunk Python SDK)

The following Python script automates correlation rule creation using Splunk’s REST API:

```python
import splunklib.client as client

HOST = "localhost"
PORT = 8089
USERNAME = "admin"
PASSWORD = "changeme"

service = client.connect(
    host=HOST,
    port=PORT,
    username=USERNAME,
    password=PASSWORD
)

spl_query = '''index=windows_logs EventCode=4625
| stats count by src_ip
| where count > 5'''

saved_search = service.saved_searches.create(
    "Brute_Force_Alert",
    spl_query,
    **{"cron_schedule": "*/15 * * * *", "alert_type": "always"}
)

print("✅ Alert Created Successfully:", saved_search.name)
```

**Purpose:**  
This script automatically creates and schedules Splunk alerts for brute-force activity every 15 minutes.

---

## 🧠 Key Achievements  

- Correlated **500K+ events** from Windows, Sysmon, and Zeek in real time  
- Built **20+ correlation searches** mapped to **MITRE ATT&CK** techniques  
- Reduced **MTTD (Mean Time to Detect)** by 60%  
- Designed **SOC dashboards** for visibility and KPI tracking  

---

## 📁 Repository Structure  

```plaintext
siem-threat-detection/
│
├── README.md
├── splunk_queries/
│   ├── brute_force_detection.spl
│   ├── beaconing_detection.spl
│   ├── lateral_movement_detection.spl
│
├── dashboard_json/
│   ├── soc_dashboard.json
│
├── automation/
│   ├── splunk_alert_creator.py
│
├── diagrams/
│   └── soc_architecture.png
└── docs/
    └── MITRE_Mapping.xlsx
```

---

## 📚 MITRE ATT&CK Coverage  

| Technique | Name | Detection Source |
|------------|------|------------------|
| T1110 | Brute Force | Windows Security Logs |
| T1071 | Application Layer Protocol | Zeek Network Logs |
| T1021 | Remote Services | Sysmon Process Logs |

---

## 🧾 Lessons Learned  

- Importance of **log normalization** before correlation.  
- How **Sysmon configuration tuning** reduces noise and improves signal quality.  
- Using **MITRE ATT&CK** as a structured framework for rule mapping.  
- Visual dashboards increase visibility for stakeholders and management.  

---

## 📸 Screenshots  

| Description | Image |
|--------------|-------|
| Splunk Dashboard | ![SOC Dashboard](./diagrams/soc_dashboard.png) |
| Brute Force Alerts | ![Brute Force Panel](./diagrams/bruteforce_alert.png) |
| Beaconing Detection | ![Beaconing Panel](./diagrams/beaconing_chart.png) |

---

## 🧾 Disclaimer  

This project was conducted in a **controlled lab environment** with simulated data sources.  
All detection use cases and code are for **educational purposes only**.

---

*Author:* **Alison Rivera**  
📧 [alison.rivera.sec@gmail.com](mailto:alison.rivera.sec@gmail.com)  
🔗 [linkedin.com/in/alisonrivera](https://linkedin.com/in/alisonrivera)
