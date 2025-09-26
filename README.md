<p align="center">
  <img src="https://github.com/user-attachments/assets/544ac8c3-8ffc-44c3-b9fd-347a20dfe786" alt="Project banner" width="900"/>
</p>

---

# Azure-SOC: Sentinel Honeynet & Detection Lab
### Hector M. Reyes

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb" width="700" alt="Azure SOC Lab Overview">
</p>

## 📚 Table of Contents

- [🔰 Introduction & Methodology](#-introduction--methodology)
  - [📜 Introduction](#-introduction)
  - [🧪 Methodology](#-methodology)
- [📉 Initial Posture](#-initial-posture)
  - [📂 Secured Storage Access via Private Endpoint](#-secured-storage-access-via-private-endpoint)
- [🌍 Sentinel Maps: Monitoring Active Cyber Threats](#-sentinel-maps-monitoring-active-cyber-threats)
- [🛡️ Initial Attack Surface](#-initial-attack-surface)
  - [1. NSG Inbound Flows](#1-nsg-inbound-flows)
  - [2. Linux SSH Attacks – Authentication Failures](#2-linux-ssh-attacks--authentication-failures)
  - [3. Windows RDP Attacks – SMB/RDP Authentication Failures](#3-windows-rdp-attacks--smbrdp-authentication-failures)
  - [4. SQL Server Attacks – Authentication Failures](#4-sql-server-attacks--authentication-failures)
- [🧠 Incident Analysis & Assessment](#-incident-analysis--assessment)
- [📈 Analyzing the Traffic (Sentinel Analytics)](#-analyzing-the-traffic-sentinel-analytics)
- [🕵️ Azure Investigation Graph](#-azure-investigation-graph)
- [🔧 Application & NSG Hardening](#-application--nsg-hardening)
- [📊 Post-Hardening Attack Surface](#-post-hardening-attack-surface)
  - [🔐 VLAN and Subnet Configuration](#-vlan-and-subnet-configuration)
- [🧰 Azure NIST Overview](#-azure-nist-overview)
- [🏗️ Project Architecture Overview](#-project-architecture-overview)
  - [Architecture Before Hardening](#architecture-before-hardening)
  - [Architecture After Hardening](#architecture-after-hardening)
- [📏 Metrics & Results](#-metrics--results)
- [🧪 KQL & Python SDK Automation Queries](#-kql--python-sdk-automation-queries)
- [✅ Conclusion](#-conclusion)

---

## 🔰 Introduction & Methodology

### 📜 Introduction

This report summarizes a cybersecurity analysis conducted in a live Microsoft Azure environment to capture real-world cyber threats. A honeynet of intentionally vulnerable Windows, Linux, and SQL Server virtual machines was deployed, attracting unauthorized activity from global threat actors. The primary goal was to observe malicious behavior and analyze attack patterns while implementing effective defenses based on best practices.

Using Microsoft Sentinel as the primary Security Information and Event Management (SIEM) tool, threat data was ingested and visualized in real-time. Insights from Microsoft Defender for Cloud, guided by the NIST SP 800-53 framework, helped identify vulnerabilities and apply hardening controls.

The engagement highlights advancements in security monitoring, incident response, and compliance-driven remediation, emphasizing their importance for Security Operations Center (SOC) analysts and Governance, Risk, and Compliance (GRC) functions. Findings were validated through post-remediation monitoring to enhance the environment's overall security posture.

### 🧪 Methodology

Our six-phase lifecycle transforms an intentionally vulnerable Azure footprint into a self-defending cloud workload, ensuring that all lessons learned are fed back into automated protection.

| Phase | Objective | Key Actions |
|-------|-----------|-------------|
| **Phase 1 – Exposed Environment** | Attract live threats | Deploy Windows, Linux & SQL VMs with public IPs and permissive NSGs. |
| **Phase 2 – Log Integration** | Centralize telemetry | Route diagnostics to **Azure Log Analytics**; onboard **Microsoft Sentinel** & **Defender for Cloud**. |
| **Phase 3 – Baseline Threat Monitoring (24 h)** | Quantify risk | Observe malicious traffic and authentication failures to establish statistical baselines. |
| **Phase 4 – Detection & Automated Response** | Halt live attacks | Create Sentinel analytics rules & playbooks aligned with **NIST SP 800-61** to isolate or block IOCs in real time. |
| **Phase 5 – Security Hardening** | Shrink attack surface | Apply Microsoft and **NIST SP 800-53** controls (network segmentation, MFA, patching, PAM). |
| **Phase 6 – Post-Hardening Assessment & Continuous Defense** | Prevent recurrence | Re-monitor for 24 h, compare metrics, and convert new findings into updated playbooks, TI blocklists, and policy-as-code to stop future attacks. |

<p align="center">
  <img src="https://github.com/user-attachments/assets/b5e7f54e-f39f-4769-884f-0fd1eb8b5496" alt="Methodology Diagram" width="1866" />
</p>

---

## 📉 Initial Posture

Initial analysis from Microsoft Defender for Cloud showed a low Secure Score. Most issues are related to identity protection, endpoint configuration, and a lack of resource-level segmentation.

- **Security Score:** The Azure environment initially scored **34%**, with critical Defender recommendations for enabling multi-factor authentication (MFA), reducing exposed endpoints, and applying OS-level patches.
- **NIST SP 800-53 R5 Access Control (AC) Findings:** The setup lacked enforced role-based access, secure defaults, and audit logging—violating core NIST controls under the Access Control (AC) family.

#### 📂 Secured Storage Access via Private Endpoint

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/70416dd1-70eb-4933-a0c7-f0a341276abb" width="700" alt="Private Endpoint">
</p>

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/343d9f0f-4a53-49c6-b540-0ae7bf918b2e" width="400" alt="Security Score Screenshot">
</p>

> **NIST SP 800-53 R5 – Access Control (AC) Findings:** In access control, we can see what is missing to meet NIST standards.

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/1a89ae0f-1d81-47b7-852d-b66cdafb0748" width="600" alt="NIST AC Findings 1">
</p>

<p align="left">
  <img src="https://github.com/user-attachments/assets/b79fc23a-764b-4b23-afe5-2962621f2e6b" width="600" alt="NIST AC Findings 2">
</p>

---

## 🌍 Sentinel Maps: Monitoring Active Cyber Threats
> **Cyber Threat Landscape:** Visualizing live cyberattacks with Sentinel Maps.

---

## 🛡️ Initial Attack Surface

### 1. NSG Inbound Flows
#### 🌐 Network Security Groups (NSG) – Malicious Inbound Flows

This query identifies potentially malicious inbound traffic targeting your environment through Azure Network Security Groups (NSGs). It focuses on flows categorized as malicious that have been allowed access to your virtual network, often from untrusted or unidentified IP addresses associated with threats.

Monitoring this traffic is crucial for security teams to detect early signs of compromise, including reconnaissance scans and brute-force attacks. Analysts can streamline threat investigations by presenting key information, such as source and destination IP addresses and timestamps.

<details>
  <summary><strong>⚙ How NSG Traffic Query Works — Click to View</strong></summary>

**NSG Traffic Query Table:**
- **Table:** `AzureNetworkAnalytics_CL` — Custom log table containing flow-level analytics and metadata from Azure NSGs.
- **Filter:**
  - `FlowType_s == "MaliciousFlow"` — Traffic labeled as malicious based on TI or behavioral analysis.
  - `AllowedInFlows_d >= 1` — Returns entries where **inbound flows were allowed**.
- **Output:**
  - `TimeGenerated`, `SrcIP_s` (source), `DestIP_s` (destination)
</details>

> NSG received inbound traffic from untrusted IPs.

<details>
  <summary><strong>📋 Click to View Query: NSG Traffic</strong></summary>

```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d >= 1
| project TimeGenerated, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s
```

<img width="975" height="226" alt="image" src="https://github.com/user-attachments/assets/a59b6f4e-445c-4492-bd84-c006ad110d3c" />


</details> <p align="left"> <img src="https://github.com/user-attachments/assets/73cc9fbe-f8b9-4593-b40f-f4a485c9150b" width="600" alt="NSG Map"> </p>


2. Linux SSH Attacks – Authentication Failures

SSH services on Ubuntu servers faced persistent brute-force login attempts. Sentinel flagged multiple password failures from a small set of rotating global IPs.

Phase 1: Hundreds of "Failed password" messages in Syslog.

Phase 2: Automation isolated attacker IPs and blocked them at the NSG level. Attempts dropped post-hardening.

Description: Detected failed SSH login attempts targeting Ubuntu VM.

<details> <summary><strong>📋 Click to View Query: SSH Attacks</strong></summary>
Syslog
| where Facility == "auth" and SyslogMessage contains "Failed password"

<img width="975" height="231" alt="067e7d93-2757-4375-8d27-4b3472a9900c" src="https://github.com/user-attachments/assets/1f66627f-06e4-43ac-a367-e6662efba0b7" />

</details> <p align="left"> <img src="https://github.com/user-attachments/assets/f722c441-841d-4044-9181-3f2cea84a558" width="600" alt="SSH Timeline"> </p>
3. Windows RDP Attacks – SMB/RDP Authentication Failures

Attackers repeatedly targeted exposed Windows VMs through port 3389 using common usernames and password variations. These brute-force attempts triggered Sentinel rules once they reached detection thresholds.

Phase 1: Failed logons observed in SecurityEvent logs with EventID 4625 and LogonType 10 (RDP).

Phase 2: Accounts protected via lockouts and narrowed NSG rules.

Description: Observed brute-force attempts via RDP/SMB protocols on Windows VMs.

<details> <summary><strong>📋 Click to View Query: SMB/RDP Attacks</strong></summary>
SecurityEvent
| where EventID == 4625
| where LogonType == 10



<img width="1678" height="340" alt="13021670-248a-4aa0-8266-deb373dfd6a7" src="https://github.com/user-attachments/assets/4de12146-a401-43c1-be39-96392f49d065" />


</details> <p align="left"> <img src="https://github.com/user-attachments/assets/97d93c53-713c-4857-9643-a3149a2317f0" width="600" alt="RDP Timeline"> </p>
4. SQL Server Attacks – Authentication Failures

SQL Server faced login brute-force attempts through unauthenticated probes targeting default accounts (e.g., sa). Sentinel registered spikes in failed logins and clustered alerts from similar IP ranges.

Phase 1: SQL logs highlighted repeated login failures often spaced in short intervals.

Phase 2: Sentinel playbooks quarantined source IPs and notified security teams.

Description: Repeated failed login attempts targeting exposed SQL Server.

<details> <summary><strong>📋 Click to View Query: SQL Attacks</strong></summary>
// Failed SQL logins
SqlSecurityAuditEvents
| where action_name == "FAILED_LOGIN"


<img width="975" height="157" alt="06872696-6720-4d20-8d54-68233c7ab16d" src="https://github.com/user-attachments/assets/b409c155-d98b-428d-88aa-0a954f19f94f" />


</details> <p align="left"> <img src="https://github.com/user-attachments/assets/a687ffa2-0469-4f4a-a54b-8758583b7985" width="600" alt="SQL Timeline"> </p>














