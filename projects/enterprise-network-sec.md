# 🧱 Enterprise Network Security Lab  

**Role:** Network Security Engineer  
**Skills:** Network Segmentation, Firewall Configuration, IDS/IPS, VPN Setup  
**Tools:** pfSense, Suricata, OpenVPN, Wireshark, GNS3  

---

## 🧩 Overview  

This project focuses on designing and deploying a **segmented enterprise network** secured with pfSense firewalls, Suricata IDS, and OpenVPN for secure remote access.  

The goal is to create a scalable, secure, and monitored environment that mirrors a real-world corporate topology — including **DMZ**, **internal LAN**, and **VPN** connectivity for remote users.

---

## 🏗️ Architecture  

```plaintext
                        +------------------------+
                        |      Internet (WAN)    |
                        +-----------+------------+
                                    |
                           [ pfSense Firewall ]
                                    |
         +--------------------------+----------------------------+
         |                           |                           |
     +---+---+                 +-----+-----+               +-----+-----+
     |  DMZ  |                 | Internal  |               | Remote VPN |
     | Web, DNS, Mail Servers  | User LAN  |               |  Users     |
     +-------+                 +-----------+               +-----------+
         |                          |                           |
      [ Suricata IDS ]        [ Wireshark Monitor ]       [ OpenVPN Access ]
```

---

## ⚙️ Setup Steps  

### 1. pfSense Configuration  

**Firewall Interfaces:**  
- WAN: `10.0.2.10/24` (NAT)  
- DMZ: `192.168.10.1/24`  
- LAN: `192.168.20.1/24`  
- VPN: `10.8.0.1/24` (OpenVPN Network)  

**Steps:**  
- Created VLANs for DMZ and LAN networks.  
- Configured NAT and firewall rules for traffic segmentation.  
- Blocked direct LAN-to-DMZ communication.  
- Enabled logging on critical rules for visibility.  

Example pfSense rule to block LAN → DMZ traffic:  
```bash
Action: Block
Interface: LAN
Source: 192.168.20.0/24
Destination: 192.168.10.0/24
Description: Block LAN to DMZ Traffic
```

---

### 2. Suricata IDS Configuration  

- Installed **Suricata** package via pfSense UI.  
- Configured IDS interfaces on both **DMZ** and **LAN**.  
- Enabled **Emerging Threats Open Ruleset**.  
- Tuned rules to minimize false positives.  

Example custom Suricata rule:  
```suricata
alert tcp any any -> $HOME_NET 22 (msg:"SSH Login Attempt Detected"; flow:to_server,established; content:"SSH"; sid:100001; rev:1;)
```

**Command-line Verification:**  
```bash
tail -f /var/log/suricata/fast.log
```

---

### 3. OpenVPN Setup  

Configured a secure remote access VPN for remote employees using **pfSense OpenVPN Wizard**.  

- Authentication: Local User Database  
- Encryption: AES-256-GCM  
- Tunnel Network: `10.8.0.0/24`  
- Redirect all client traffic through VPN  

Example OpenVPN Server Configuration (exported `.ovpn` file):  
```bash
dev tun
proto udp
remote your_public_ip 1194
cipher AES-256-GCM
auth SHA256
redirect-gateway def1
verb 3
```

Clients authenticate using credentials generated within pfSense and connect securely to the internal LAN and DMZ networks.

---

### 4. Wireshark Monitoring  

Used **Wireshark** to capture and analyze traffic between DMZ, LAN, and VPN clients.  

Sample capture command:  
```bash
sudo tshark -i eth0 -f "net 192.168.10.0/24 or net 192.168.20.0/24"
```

Filtered for IDS alerts and verified Suricata’s detection accuracy.

---

## 🔍 Security Baseline Documentation  

Created a **security baseline document** detailing the following controls:  

| Control | Implementation | Verification |
|----------|----------------|---------------|
| Network Segmentation | pfSense VLAN & Firewall | Ping, Traceroute, Firewall Logs |
| IDS/IPS Deployment | Suricata | Alert Logs, Rule Validation |
| VPN Encryption | OpenVPN AES-256-GCM | Wireshark, VPN Log Review |
| Change Management | pfSense Config Backup | Backup Files in /conf/ |

All configurations were version-controlled in a GNS3 project repository for reproducibility.

---

## 📊 Network Monitoring Dashboard  

Built a pfSense dashboard and IDS visualization panel:  

| Panel | Description | Visualization Type |
|--------|--------------|--------------------|
| Interface Traffic by VLAN | Monitors throughput by interface | Line Chart |
| Top Blocked IPs | Displays top external IPs blocked by pfSense | Bar Chart |
| IDS Alert Summary | Lists triggered Suricata alerts | Table |
| VPN Client Connections | Shows connected remote users | Single Value |

Example pfSense RRD Graph (Traffic Visualization):  
```plaintext
[Traffic Graph] WAN <-> DMZ/LAN (Updated Every 5 Min)
Packets In/Out: 500k+ per day
Average CPU Load: < 20%
```

---

## 🧠 Key Achievements  

- Reduced attack surface by **70%** through proper segmentation  
- Deployed **50+ Suricata rules** tailored for SSH, RDP, and SMB detection  
- Established **secure remote VPN** access for simulated employees  
- Created detailed **network topology diagrams** and baseline documentation  

---

## 📁 Repository Structure  

```plaintext
enterprise-network-security-lab/
│
├── README.md
├── pfSense_Config/
│   ├── firewall_rules.xml
│   ├── openvpn_config.ovpn
│
├── suricata_rules/
│   ├── custom_rules.rules
│
├── gns3_project/
│   ├── enterprise_lab_topology.gns3
│
├── diagrams/
│   └── network_topology.png
└── docs/
    └── security_baseline.docx
```

---

## 📚 Network Segmentation Overview  

| Zone | Subnet | Description |
|------|---------|-------------|
| WAN | 10.0.2.0/24 | Internet-facing network |
| DMZ | 192.168.10.0/24 | Hosts public services (web, DNS, mail) |
| LAN | 192.168.20.0/24 | Internal user network |
| VPN | 10.8.0.0/24 | Remote user secure access |

---

## 🧾 Lessons Learned  

- Importance of **DMZ isolation** and firewall rule precision.  
- Regular IDS rule updates reduce exposure to new threats.  
- VPN access should use **multi-factor authentication (MFA)** in production.  
- Network segmentation simplifies **incident response** and **forensic analysis**.  

---

## 📸 Screenshots  

| Description | Image |
|--------------|-------|
| pfSense Dashboard | ![pfSense Dashboard](./diagrams/pfsense_dashboard.png) |
| Suricata Alerts | ![Suricata Alerts](./diagrams/suricata_alerts.png) |
| OpenVPN Status | ![VPN Clients](./diagrams/vpn_clients.png) |

---

## 🧾 Disclaimer  

This project was created for **educational and demonstration purposes** within a virtualized lab environment (GNS3).  
No production systems or live data were involved.

---

*Author:* **Alison Rivera**  
📧 [alison.rivera.sec@gmail.com](mailto:alison.rivera.sec@gmail.com)  
🔗 [linkedin.com/in/alisonrivera](https://linkedin.com/in/alisonrivera)
