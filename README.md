<p align="center">
  <img src="https://github.com/user-attachments/assets/544ac8c3-8ffc-44c3-b9fd-347a20dfe786" alt="ezgif-7650866c6a50db" width="900"/>
</p>

---

# Azure SOC Lab: Sentinel SIEM + Honeynet  
### Hector M. Reyes

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb" width="700" />
</p>

Detect attacks fast → harden → prove the impact.

> **TL;DR**
> - **Scope:** A public-facing lab that attracts real internet attacks, monitored using Microsoft Sentinel.  
> - **Key wins:** Clear detections, mapped hardening, measurable drop in attack noise, and auth failures.  
> - **Run it:** Follow the phase guide below; each step links to existing repo content.

**Jump to:** [Executive Summary](#executive-summary) · [Architecture](#project-architecture-overview) · [Phases](#getting-started-with-phases) · [Metrics](#metrics--results)

---

# 📜**Executive Summary**
This runbook outlines the framework for a live Azure honeynet comprising intentionally vulnerable Windows, Linux, and SQL Server virtual machines, strategically designed to attract commodity-level attacks. Microsoft Sentinel is utilized to ingest and correlate telemetry in real-time, while guidance from Microsoft Defender for Cloud—anchored to **NIST SP 800-53**—provides a robust foundation for hardening our systems. We establish a risk baseline, deploy appropriate security controls, and subsequently conduct re-testing to validate the effectiveness of our improvements.
**Outcomes at a glance**
- Reduced failed SSH/RDP/SQL authentications after hardening  
- Malicious IPs blocked earlier via NSG and subnet isolation  
- Faster investigations using Sentinel incidents + Investigation Graph pivots

---

## 🧪 **Methodology**
Our comprehensive six-phase lifecycle enhances a deliberately vulnerable Azure environment, transforming it into a self-defending cloud workload. This process guarantees that insights gained are systematically integrated into automated protection strategies.

| Phase | Objective | Key Actions |
|-------|-----------|-------------|
| **Phase 1 – Exposed Environment** | Attract live threats | Deploy Windows, Linux & SQL VMs with public IPs and permissive NSGs. |
| **Phase 2 – Log Integration** | Centralize telemetry | Route diagnostics to **Azure Log Analytics**; onboard **Microsoft Sentinel** & **Defender for Cloud**. |
| **Phase 3 – Baseline Threat Monitoring (24 h)** | Quantify risk | Observe malicious traffic and authentication failures to establish statistical baselines. |
| **Phase 4 – Detection & Automated Response** | Halt live attacks | Create Sentinel analytics rules & playbooks aligned with **NIST SP 800-61** to isolate or block IOCs in real time. |
| **Phase 5 – Security Hardening** | Shrink attack surface | Apply Microsoft and **NIST SP 800-53** controls (network segmentation, MFA, patching, PAM). |
| **Phase 6 – Post-Hardening Assessment & Continuous Defense** | Prevent recurrence | Re-monitor for 24 h, compare metrics, and convert new findings into updated playbooks, TI blocklists, and policy-as-code to stop future attacks.|
<p align="center">
  <img src="https://github.com/user-attachments/assets/b5e7f54e-f39f-4769-884f-0fd1eb8b5496" width="700" />
</p>

---

# 🛡️**Architecture Overview**

## 🔓**Initial Azure Architecture** — Before (Deliberately Vulnerable)
The Azure environment (Linux SSH, Windows RDP/SMB, SQL) was configured with basic security designed to simulate a high-risk production workload in a sandboxed environment (the honeynet) and attract live cyber threats, gather telemetry, and observe adversary behavior.
- **Public exposure of critical resources:** Windows & Linux VMs, SQL Server, Storage, Key Vault reachable from the internet.  
- **Permissive NSGs:** Broad inbound rules allow scanning, brute force, and lateral probes.  
- **Initial monitoring:** Logs centralized in Log Analytics and surfaced in Sentinel for alerts and investigations.
<div align="center">
  <img src="https://github.com/user-attachments/assets/f5ec8a80-09b3-42a4-ac2b-8f6cfb5d2918" width="70%" />
</div>
`Public-facing VMs & services are  exposed and attract attackers.`

---

## 🔒**Hardened Azure Architecture** —  After (Secure)
Following the threat analysis, the environment was restructured to align with secure architecture principles and NIST SP 800-53, specifically SC-7(3) for Access Restrictions. Key enhancements included minimizing external exposure, tightening NSG rules, segmenting subnets/VLANs, and securing OS/app configurations. Data now flows into Microsoft Sentinel for enhanced correlation, improved alerts, and more effective investigations.
- **Restricted access:** NSGs allow only trusted source IPs; deny all else.  
- **Private Endpoints:** Storage and Key Vault move behind Private Endpoints (no public exposure).  
- **Platform controls:** Azure Firewall/Defender policies enforce standardized guardrails and continuous compliance.
<div align="center">
  <img src="https://github.com/user-attachments/assets/a8eeaf5e-f941-4db5-9a1c-dfd87f05b160" width="70%" />
</div>
`NSGs tightened, firewalls tuned, public endpoints replaced by private endpoints, controls aligned to NIST SC-7(3).`

---

## 🏛️**NIST Overview**
NIST SP-800-53 serves as a comprehensive framework for establishing security and privacy controls within federal information systems. It is foundational for various compliance frameworks, including FedRAMP, the Cybersecurity Framework (CSF), and the Azure Security Benchmark. This structured approach facilitates the effective management of security controls throughout their lifecycle, ultimately enhancing an organization's resilience against emerging threats.

### **NIST Control Mapping** (Quick View)
| Area | Example Controls | What We Implement |
|---|---|---|
| Network Boundary | SC-7, AC-4 | Least-privilege NSGs, allow-lists, subnet isolation |
| Identification & Auth | IA-2, IA-5 | Stronger auth/lockout/back-off on exposed services |
| System/Comms Protection | SC-5, SC-12 | Disable weak protocols; encryption where supported |
| Audit & Monitoring | AU-2, AU-6 | Centralized logging to Sentinel; triage workflows |
| Incident Response | IR-4, IR-5 | Investigation Graph usage; playbook-driven response |

---

# 📐**Setup & Baseline** (How the Lab Works)
## **Methodology** (What you’ll see and why)
We intentionally expose prevalent services to capture genuine attack behaviors, such as scans, credential stuffing, and brute force attempts. Signals are transmitted to Sentinel; subsequently, we engage in a cycle of observation, detection, fortification, and re-evaluation.
**observe → detect → harden → re-test**.

### Starting Baseline (Deliberately Vulnerable)
Adopting a permissive security posture produces immediate indicators, such as significant increases in failed SSH and RDP login attempts, which contribute to measurable enhancements in security protocols.

Initial Attack Surface (What’s Exposed)
- SSH (22/tcp), RDP/SMB (3389/445), SQL (1433) initially reachable  
- NSGs broadly allow inbound to capture noise  
- Goal: establish a worst-case baseline before adding controls

<h3 align="center">📂 Secured Storage Access via Private Endpoint </h3>

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/70416dd1-70eb-4933-a0c7-f0a341276abb" width="700">
</p>

---

# 🛠️**Initial Sentinel Monitoring**
> Cyber Threat Landscape: Visualizing Live Cyberattacks with Sentinel Maps

## 🌐1. **Network Security Groups (NSG)** – Malicious Inbound Flows
This query identifies potentially malicious inbound traffic targeting your environment through Azure Network Security Groups (NSGs). It focuses on flows categorized as malicious that have been allowed access to your virtual network, often from untrusted or unidentified IP addresses associated with threats.

Monitoring this traffic is crucial for security teams to detect early signs of compromise, including reconnaissance scans and brute-force attacks. Analysts can streamline threat investigations by presenting key information, such as source and destination IP addresses and timestamps.

<details>
  <summary><strong>⚙ How NSG Traffic Query Works: Click to View </strong></summary>

**NSG Traffic Query Table:**

- **Table**: `AzureNetworkAnalytics_CL` – This custom log table contains flow-level analytics and metadata from Azure NSGs.
- **Filter**:
  - `FlowType_s == "MaliciousFlow"` – Filters for traffic labeled as malicious based on threat intel or behavioral analysis.
  - `AllowedInFlows_d >= 1` – Ensures the query only returns entries where **inbound flows were allowed**, indicating a potential exposure.
- **Output**:
  - `TimeGenerated`: When the traffic occurred  
  - `SrcIP_s`: The originating (possibly malicious) IP  
  - `DestIP_s`: The destination IP within your environment  

</details>

> NSG received inbound traffic from untrusted IPs.

<details>
   <summary><strong> 📋Click to View Query: NSG Traffic </strong></summary>
     
KQL Query: NSGs Inbound Traffic from all untrusted IPs.
```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d >= 1
| project TimeGenerated, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/04e1dffa-958e-4d1c-b326-dc75a3ca91df)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/73cc9fbe-f8b9-4593-b40f-f4a485c9150b" width="600">
</p>

## 🐧2. **Linux SSH Attacks** – Authentication Failures
SSH services on Ubuntu servers faced persistent brute-force login attempts. Sentinel flagged multiple password failures from a small set of rotating global IPs.

* **Phase 1:** Detection began with hundreds of "Failed password" messages in the Syslog stream.
* **Phase 2:** Analysts used automation to isolate attacker IPs and block them at the NSG level. These attacks slowed significantly post-hardening.

> **Description:** Detected failed SSH login attempts targeting Ubuntu VM.

 <details>
   <summary><strong> 📋Click to View Query: SSH Attacks </strong></summary>
   
🔹KQL Query: SSH Authentication Fails for Linux VMs
```kql
Syslog
| where Facility == "auth" and SyslogMessage contains "Failed password"
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/067e7d93-2757-4375-8d27-4b3472a9900c)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/f722c441-841d-4044-9181-3f2cea84a558" width="600">
</p>

## 🪟3. **Windows RDP Attacks** – SMB/RDP Authentication Failures
Attackers repeatedly targeted exposed Windows VMs through port 3389 using common usernames and password variations. These brute-force attempts triggered Sentinel rules once they reached detection thresholds.

* **Phase 1:** Failed logons were seen in `SecurityEvent` logs, marked with EventID 4625 and logonType 10 (RDP).
* **Phase 2:** Accounts were protected by enabling lockouts and narrowing NSG rules.

> **Description:** Observed brute-force attempts via RDP/SMB protocols on Windows VMs.

 <details>
   <summary><strong> 📋Click to View Query: SMB/RDP Attacks </strong></summary>
   
🔹KQL Query: SMB/RDP Authentication Fails for Windows VMs
```kql
SecurityEvent
| where EventID == 4625
| where LogonType == 10
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/13021670-248a-4aa0-8266-deb373dfd6a7)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/97d93c53-713c-4857-9643-a3149a2317f0" width="600">
</p>

## 🛢️4. **SQL Server Attacks** – Authentication Failures

SQL Server faced login brute-force attempts through unauthenticated probes targeting default accounts, such as the "sa" account. Sentinel registered spikes in failed logins and clustered alerts from similar IP ranges.

Phase 1: SQL logs highlighted repeated login failures often spaced in short intervals.
Phase 2: Sentinel playbooks were deployed to quarantine source IPs and notify security teams.

> **Description:** Repeated failed login attempts targeting exposed SQL Server.

<details>
  <summary><strong> 📋Click to View Query: SQL Attacks </strong></summary>

🔹KQL Query: SQL Server Authentication Fails
```kql
// Failed SQL logins
SqlSecurityAuditEvents
| where action_name == "FAILED_LOGIN"
```
  
  ![image](https://github.com/user-attachments/assets/06872696-6720-4d20-8d54-68233c7ab16d)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/a687ffa2-0469-4f4a-a54b-8758583b7985" width="600">
</p>

---

# 📊**Analysis & Incident Assessment**
This section highlights how Microsoft Sentinel was used to investigate and respond to coordinated brute-force attacks across Windows, SQL Server, and Linux systems within a 24-hour monitoring period.
**Incident ID: 329** Wass linked to malicious IP 74.249.102.160, which triggered multiple alerts.
> 1. **Alert 205:** Brute Force Attempt – Windows
> 2. **Alert 214:** Brute Force Attempt – MS SQL Server
> 3. **Alert 329:** Brute Force Success – Linux Syslog

<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/2fa96acc-9a23-44a0-87a3-e1d74ac72856" width="350"/> 

---

## 📉**Analyzing the Traffic**
Sentinel analytics helped correlate these events, enabling a detailed examination of attacker behavior, IP reputation, and sequence of actions. I analyzed both successful and failed attempts, filtering out false positives and tracking escalation patterns.

  **The included visuals show:**
> 1.	Sharp spikes in brute-force login attempts during the vulnerable phase
> 2.	NSG flow logs mapping inbound malicious traffic
> 3.	Timelines that illustrate how these threats stopped once hardening controls were applied

<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9d31a24c-d5b6-41b5-9089-7675844cf60d" width="600"/> 

✅ **Result:** Sentinel detections and NSG rule adjustments significantly reduced the attack surface and prevented further compromise. 

---

## 📈**Azure Investigation Graph**
Microsoft Sentinel’s Investigation Graph stitches all elements—hosts, alerts, IP addresses, and user actions—into a single, navigable chain. This visualization helped responders understand event sequences and attribution.

> Connecting alerts, affected hosts, and user accounts in a unified timeline. This enables analysts to swiftly transition from one indicator to corresponding evidence, enhancing the speed of triage and root-cause analysis.

<img src="https://github.com/user-attachments/assets/0b4fd94a-d8f0-46ab-b832-5fdfe0c2858c" width="50%" />

## 📉**Application and NSG hardening**
Remediated by associating and resetting the passwords for the compromised users and locking down NSGs
> Impact: The account was local to the Linux machine and non-admin, resulting in minimal impact. However, NSG hardening will remediate the attacks that have resulted in many other incidents.

  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/23a192c8-65d3-4dc7-8112-d57e522eefac" width="600"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/ea612103-e77f-4529-be2a-c867c3c3f7aa" width="600"/>

---

## 📱**Post-Hardening Attack Surface**
All map queries returned no results because there was zero malicious activity during the 24 hours following hardening.
After implementing hardening measures, we detected no malicious activity. All queries on the Sentinel map returned zero results, confirming the effectiveness of tightening our Network Security Groups (NSGs), utilizing private endpoints, and adhering to compliance requirements. By following Microsoft-recommended hardening steps alongside NIST SP 800-53 controls, we successfully reduced malicious traffic and incidents to zero within 24 hours.
<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/727edb36-b4e2-448d-aed0-60b5484ae91e" alt="No incidents after hardening" width="600"/>
</p>

## 🛡️**VLAN and Subnet Configuration**
These visuals illustrate how the lab's single virtual network was divided into three purpose-built subnets. These subnets serve as isolation zones, restricting traffic and limiting the potential damage if an attacker compromises a single host.

**Azure Topology:** The Azure topology view displays all virtual machines (VMs), databases, and gateways on a single subnet within a virtual network. These subnets are separate rooms within the same building, each with doors (network security groups) that can be locked individually. The resource list in the right-hand pane is filtered by subnet, confirming that web, SQL, and management workloads reside in their segments.

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/67ba9152-de43-4345-82fd-92b2da05b9f2" alt="Subnet config 1" width="330"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/fa608462-bba8-4dea-975a-5c9fc9905081" alt="Subnet config 2" width="340"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/49cb6ca9-e3d9-4bd5-bea5-44e0a19cc78a" alt="Subnet config 3" width="330"/>
</p>

---

### 🏛️**Azure NIST Overview**
NIST SP-800-53 is a comprehensive guideline for security and privacy controls in federal information systems. It serves as the foundation for compliance frameworks such as FedRAMP, CSF, and Azure Security Benchmark.
To check NIST SP-800-53-R5 compliance:
> Navigate to: **Azure Home > Microsoft Defender for Cloud > Regulatory compliance > NIST SP-800-53-R5**
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/00b13f92-53cb-4cec-a630-d168dcec4542" alt="Defender compliance 1" width="700"/>

## 📊**Metrics & Results**

> The dramatic drop in alerts, flows, and incidents demonstrates how quickly and effectively the environment improved after implementing targeted hardening strategies.

## ⏱️**Before vs After** (24 h)

| Metric | Before | After | Δ % |
|--------|-------:|------:|----:|
| **Security Events** (Windows) | 221 542 | 84 | **-99.96** |
| **Syslog** (Linux)            | 2 310   | 2  | **-99.91** |
| **Security Alerts**           | 4       | 0  | **-100.00** |
| **Sentinel Incidents**        | 662     | 0  | **-100.00** |
| **Malicious NSG Flows**       | 1 742   | 0  | **-100.00** |

> 🔍 These figures confirm a complete elimination of detected attacks after hardening.

🧱 This comparison shows how exposed infrastructure was transformed into a secure environment by integrating best practices, including private endpoints and network security group (NSG) restrictions.sa

----

## 🔄**Kusto Query Language (KQL) & Python SDK Automation Queries**

<details>
<summary> 📋 Click to View KQL All Automation Queries <</summary>
  
### Start & Stop Time
```
range x from 1 to 1 step 1
| project StartTime = ago(24h), StopTime = now()
```

### Security Events (Windows VMs)
```
SecurityEvent
| where TimeGenerated >= ago(24h)
| count
```

### Syslog (Ubuntu Linux VMs)  
```
Syslog
| where TimeGenerated >= ago(24h)
| count
```

### Security Alert (Microsoft Defender for Cloud)
```
SecurityAlert
| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"
| where TimeGenerated >= ago(24h)
| count
```

### Security Incidents (Sentinel Incidents)
```
SecurityIncident
| where TimeGenerated >= ago(24h)
| count
```

### Azure NSG Inbound Malicious Flows Allowed
```
AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```

### Azure NSG Inbound Malicious Flows Allowed
```
AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow" and DeniedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```

</details>

---

##  🏁 **Conclusion**
The honeynet deployed in the Microsoft Azure environment simulated a high-risk scenario exposed to modern cyberattacks via misconfigured virtual machines. Utilizing Azure Log Analytics and Microsoft Sentinel for centralized logging enabled real-time threat alerts and visualization, supporting structured triage workflows akin to a SOC.

Following a baseline threat analysis, the environment was fortified with Azure-native security controls based on NIST SP 800-53, resulting in a notable decrease in unauthorized access attempts and brute-force attacks. This highlights the importance of layered security and continuous monitoring in strengthening cloud security.

---
