<p align="center">
  <img src="https://github.com/user-attachments/assets/544ac8c3-8ffc-44c3-b9fd-347a20dfe786" alt="ezgif-7650866c6a50db" width="900"/>
</p>

---

# Azure SOC Lab: Sentinel SIEM + Honeynet  
### Hector M. Reyes

Detect attacks fast → harden → prove the impact

> **TL;DR**
> - **Scope:** Public-facing lab that attracts real internet attacks, monitored with Microsoft Sentinel.  
> - **Key wins:** Clear detections, mapped hardening, measurable drop in attack noise and auth failures.  
> - **Run it:** Follow the phase guide below; each step links to existing repo content.

**Jump to:** [Executive Summary](#executive-summary) · [Architecture](#project-architecture-overview) · [Phases](#getting-started-with-phases) · [Metrics](#metrics--results)

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb" width="700" />
</p>

---

# 📜 **Executive Summary**
This runbook delineates the framework for a live Azure honeynet composed of intentionally vulnerable Windows, Linux, and SQL Server virtual machines, strategically designed to attract commodity-level attacks. Microsoft Sentinel is utilized to ingest and correlate telemetry in real-time, while guidance from Microsoft Defender for Cloud—anchored to **NIST SP 800-53**—provides a robust foundation for hardening our systems. We establish a risk baseline, deploy appropriate security controls, and subsequently conduct re-testing to validate the effectiveness of our improvements.
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
  <img src="https://github.com/user-attachments/assets/b5e7f54e-f39f-4769-884f-0fd1eb8b5496" width="900" />
</p>

---

# 🔓 **Project Architecture Overview**

## **Initial Azure Architecture** — Before (Deliberately Vulnerable)
The Azure environment (Linux SSH, Windows RDP/SMB, SQL) was configured with basic security designed to simulate a high-risk production workload in a sandboxed environment (the honeynet) and attract live cyber threats, gather telemetry, and observe adversary behavior.
- **Public exposure of critical resources:** Windows & Linux VMs, SQL Server, Storage, Key Vault reachable from the internet.  
- **Permissive NSGs:** Broad inbound rules allow scanning, brute force, and lateral probes.  
- **Initial monitoring:** Logs centralized in Log Analytics and surfaced in Sentinel for alerts and investigations.
<div align="center">
  <img src="https://github.com/user-attachments/assets/f5ec8a80-09b3-42a4-ac2b-8f6cfb5d2918" width="70%" />
</div>
> Public-facing VMs & services are  exposed and attract attackers.

### 🔒 **Hardened Azure Architecture** —  After (Secure)
Following the threat analysis, the environment was restructured to align with secure architecture principles and NIST SP 800-53, specifically SC-7(3) for Access Restrictions. Key enhancements included minimizing external exposure, tightening NSG rules, segmenting subnets/VLANs, and securing OS/app configurations. Data now flows into Microsoft Sentinel for improved correlation, alerts, and investigations.
- **Restricted access:** NSGs allow only trusted source IPs; deny all else.  
- **Private Endpoints:** Storage and Key Vault move behind Private Endpoints (no public exposure).  
- **Platform controls:** Azure Firewall/Defender policies enforce standardized guardrails and continuous compliance.
<div align="center">
  <img src="https://github.com/user-attachments/assets/a8eeaf5e-f941-4db5-9a1c-dfd87f05b160" width="70%" />
</div>
> NSGs tightened, firewalls tuned, public endpoints replaced by private endpoints, controls aligned to NIST SC-7(3).

---

## **NIST Overview**
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

## **Setup & Baseline** (How the Lab Works)
### **Methodology** (What you’ll see and why)
We intentionally expose prevalent services to capture genuine attack behaviors, such as scans, credential stuffing, and brute force attempts. Signals are transmitted to Sentinel; subsequently, we engage in a cycle of observation, detection, fortification, and re-evaluation.
**observe → detect → harden → re-test**.

### Starting Baseline (Deliberately Vulnerable)
Adopting a permissive security posture produces immediate indicators, such as significant increases in failed SSH and RDP login attempts, which contribute to measurable enhancements in security protocols.

Initial Attack Surface (What’s Exposed)
- SSH (22/tcp), RDP/SMB (3389/445), SQL (1433) initially reachable  
- NSGs broadly allow inbound to capture noise  
- Goal: establish a worst-case baseline before adding controls

---

## Conclusion
The honeynet deployed in the Microsoft Azure environment simulated a high-risk scenario exposed to modern cyberattacks via misconfigured virtual machines. Utilizing Azure Log Analytics and Microsoft Sentinel for centralized logging enabled real-time threat alerts and visualization, supporting structured triage workflows akin to a SOC.

After a baseline threat analysis, the environment was fortified with Azure-native security controls based on NIST SP 800-53, leading to a notable decrease in unauthorized access attempts and brute-force attacks. This highlights the importance of layered security and continuous monitoring in strengthening cloud security.

---
