# THREAT-INTELLIGENCE-INVESTIGATION-AND-ATTACK-SIMULATION-AGAINST-A-CHOSEN-INDUSTRY-DOMAIN.

# 🔐 LockBit 3.0 Attack Simulation on Mayo Clinic – Threat Intelligence Report

## 📖 Overview

This repository presents a detailed threat intelligence investigation and simulated attack scenario centered on **LockBit 3.0**, a notorious ransomware group. The target domain is **Mayo Clinic**, representing a critical healthcare infrastructure. The report includes:

- 🎯 Threat actor profiling  
- 🛠️ Reconnaissance tools and techniques  
- 🧪 Simulated kill chain walkthrough  
- 🧭 MITRE ATT&CK technique mapping  
- 🛡️ Tactical security recommendations  
- 📂 References and attribution disclaimers  

---

## 🧠 Executive Summary

Mayo Clinic, a premier institution in global healthcare and medical research, operates a highly sensitive digital infrastructure that supports patient data, clinical systems, and research networks. These assets make the Clinic a high-value target for cyber adversaries—especially ransomware operators seeking maximum disruption and financial gain.

This investigation focuses on **LockBit 3.0**, a formidable Ransomware-as-a-Service (RaaS) group known for rapid encryption and double extortion. Using Open-Source Intelligence (OSINT) and passive reconnaissance techniques, we simulate a kill chain and map potential intrusion paths based on adversarial behaviors observed in past LockBit campaigns.

Recommendations are offered to fortify cybersecurity resilience, detection readiness, and incident response agility—aligning with the MITRE ATT&CK Framework for threat modeling.

---

## 🧰 Reconnaissance Tools & Findings

| Tool          | Purpose |
|---------------|---------|
| **theHarvester** | Gathers publicly exposed emails and subdomains for social engineering. |
| **Shodan** | Identifies exposed infrastructure, open ports, and vulnerable services. |
| **Whois** | Examines domain registration metadata for attribution profiling. |
| **Google Dorking** | Unearths misconfigured endpoints and sensitive file disclosures via advanced search operators. |
| **Hunter.io** | Harvests organizational email formats and employee contact patterns for phishing exploitation. |

---

## 🕵️‍♂️ Threat Actor Profile – LockBit 3.0

| Attribute    | Details |
|-------------|---------|
| Group Name  | LockBit 3.0 (aka LockBit Black) |
| Type        | Ransomware-as-a-Service (RaaS) |
| First Seen  | March 2022 |
| Origin      | Advertised in Russian-speaking forums; avoids targeting CIS-region victims |
| Tools       | LockBit Builder (ransomware customization), StealBit (data exfiltration) |
| Motive      | Financial gain through data encryption and extortion |

### ⚔️ Notable Campaigns

- **Accenture (USA)** – $50M ransom threat with leaked data implications.  
- **Royal Mail (UK)** – Disruption of operational infrastructure and logistics.  
- **SickKids Hospital (Canada)** – Medical outage, followed by free decryption citing internal ethics policy.  
- **Motilal Oswal (India)** – Swift containment minimized operational impact.  
- **Phorpiex Botnet (Global)** – Mass phishing vector to deliver LockBit payloads internationally.  

---

## 🧪 Simulated Kill Chain Scenario

| Phase              | Description |
|--------------------|-------------|
| **Reconnaissance** | Collect intelligence via Shodan, Hunter.io, theHarvester. |
| **Weaponization**  | Compile malware using LockBit builder with StealBit integrated. |
| **Delivery**       | Launch via spear-phishing emails or compromised sites. |
| **Exploitation**   | PowerShell execution triggered by user interaction (e.g., document open). |
| **Installation**   | Persist through DLL injection, registry keys, and service creation. |
| **Command & Control (C2)** | Encrypted communication via HTTPS/DNS using proxy infrastructure. |
| **Actions on Objectives** | Credential harvesting, data exfiltration, file encryption, ransom note drop, backup deletion. |

---

## 🧭 MITRE ATT&CK Mapping – LockBit 3.0 on Mayo Clinic

| Tactic              | Technique ID  | Technique Name                | Description |
|---------------------|---------------|-------------------------------|-------------|
| **Initial Access**   | T1566.001     | Spear Phishing Attachment     | Email-based attack targeting individuals with malware-laced attachments or URLs. |
| **Execution**        | T1047         | Windows Management Instrumentation (WMI) | Executes malicious scripts remotely via system management commands. |
| **Persistence**      | T1543.003     | Windows Service               | Establishes persistence by installing malicious services that auto-run on startup. |
| **Credential Access**| T1003.001     | LSASS Memory                  | Dumps credentials by exploiting LSASS memory using tools like Mimikatz. |
| **Lateral Movement** | T1021.002     | Windows Admin Shares          | Leverages network shares and admin credentials to move laterally across systems. |
| **Command & Control**| T1071.001     | Application Layer Protocol    | Maintains control and evades detection using encrypted channels (HTTPS/DNS). |
| **Exfiltration**     | T1041         | Exfiltration Over C2 Channel  | Transfers data to external servers through secure outbound channels before encryption. |

---

## 🛡️ Security Recommendations

### 🔐 Credential & Access Hardening

- Enforce phishing-resistant MFA for remote access  
- Disable unused remote services (e.g., RDP, SSH) and control access by IP  
- Monitor abnormal login behavior across privileged accounts  

### 📧 Phishing & Email Protection

- Train staff to recognize and report phishing attempts  
- Use email filters, attachment sandboxing  
- Implement DMARC, SPF, and DKIM  

### 🖥️ Endpoint & Network Defense

- Enable antivirus and behavioral threat detection  
- Whitelist approved applications and block unauthorized executables  
- Monitor usage of PsExec, Mimikatz, and Rclone  

### 📊 Threat Detection & Logging

- Watch for LSASS access, PowerShell execution, registry changes  
- Detect exfiltration tools like StealBit and FileZilla  
- Monitor for event log clearing and deletion of shadow copies  

### 🔐 Network Segmentation & Backup Strategy

- Isolate critical systems from general user access  
- Maintain offline, immutable backups and regularly test restoration  
- Restrict lateral movement protocols like SMB  

### 🛠️ Vulnerability Management

- Rapidly patch known exploited vulnerabilities  
- Monitor exploitation attempts against public-facing services  

---

## 📂 References

- [MITRE ATT&CK Framework](https://attack.mitre.org)  
- [CISA Ransomware Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories)  
- [VirusTotal](https://www.virustotal.com)  
- [Shodan](https://www.shodan.io)  
- [Hunter.io](https://hunter.io)  

---

## ⚖️ Legal & Ethical Notice

> ⚠️ This repository is for educational and research purposes only.  
> It does not reflect any actual compromise or breach of Mayo Clinic or its infrastructure.  
> All data and tactics referenced are based on publicly available intelligence.  

---

## 🤝 Contributions & Feedback

Suggestions, forks, and pull requests are welcome.  
Feel free to share improvements, new indicators of compromise (IOCs), or insights to enhance this simulation.

---

## 🧠 Author

Threat research and simulation conducted by me.  
This work is part of an ongoing series of adversary emulation reports designed to raise awareness and improve cybersecurity resilience.

---
