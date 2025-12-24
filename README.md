# 🛡️ Phishing Threat Intelligence & IOC Analysis Project

> **Portfolio Project | SOC & Threat Intelligence**

![Splunk Dashboard Overview](screenshots/splunk_dashboard_overview.png)

---

## 📖 Overview
This project investigates a real-world **phishing email** impersonating a Google security alert. It demonstrates an end-to-end **SOC analyst workflow** including email analysis, IOC extraction, threat intelligence enrichment, MITRE ATT&CK mapping, and Splunk dashboard visualization.

The phishing campaign abused a **URL shortener (Bitly)** and a **trusted hosting platform (GitHub Pages)** to harvest user credentials while bypassing traditional email authentication controls.

---

## 🎯 Objectives
- Detect and analyze a phishing email
- Extract and validate Indicators of Compromise (IOCs)
- Enrich findings using threat intelligence platforms
- Map attacker behavior to MITRE ATT&CK
- Visualize threats using a SOC-style Splunk dashboard
- Produce professional, portfolio-ready documentation

---

## 🧰 Technologies & Tools
- **ANY.RUN** — Email and URL sandbox analysis  
- **VirusTotal** — Threat intelligence and reputation analysis  
- **Splunk Enterprise** — SOC dashboards and visualization  
- **WHOIS / DNS tools** — Infrastructure enrichment  
- **GitHub Pages** — Observed phishing hosting platform  

---

## 📌 Attack Summary

| Attribute | Details |
|---------|--------|
| **Attack Type** | Phishing (Credential Harvesting) |
| **Impersonated Brand** | Google |
| **Delivery Vector** | Email |
| **Obfuscation Technique** | URL Shortener (Bitly) |
| **Final Hosting Platform** | GitHub Pages |
| **Overall Risk Level** | High |

---

## 🔍 Methodology

### 1. Email Analysis
- Reviewed sender, subject, and message content
- Analyzed email authentication headers  
- **SPF, DKIM, and DMARC checks passed**, indicating abuse of a **legitimate Gmail account**
- Identified urgency-based social engineering techniques

### 2. URL & Infrastructure Analysis
- Extracted shortened URL from the email
- Resolved the full redirection chain
- Identified a fake Google login page hosted on GitHub Pages
- Collected hosting IP, server headers, and SSL details

### 3. Threat Intelligence Enrichment
- VirusTotal analysis of the final phishing URL
- **6 / 98 security vendors flagged the URL as malicious**
- First-seen timestamp confirmed recent malicious activity
- Confirmed abuse of trusted infrastructure to evade detection

### 4. MITRE ATT&CK Mapping
Observed attacker behavior was mapped to the MITRE ATT&CK framework to align detection and response strategies.

## 🧩 MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|----------|-------------|
| Initial Access | T1566.002 | Spearphishing Link |
| Credential Access | T1598.003 | Credential Harvesting |
| Execution | T1204 | User Execution |

---

## 📊 Splunk Dashboard Overview

![Splunk Dashboard Panels](screenshots/splunk_dashboard_panels.png)

### Panels & Purpose

- **Threat Intelligence Summary (Single Value Panels)**  
  Displays the total number of extracted IOCs, confirmed malicious URLs, and credential-harvesting attempts to provide rapid situational awareness.

- **URL & Redirect Overview (Table Panel)**  
  Shows shortened URLs, redirection chains, final destinations, hosting IP addresses, and VirusTotal detection ratios to support analyst triage and investigation.

- **MITRE Technique Distribution (Chart)**  
  Visualizes attacker techniques mapped to the MITRE ATT&CK framework, helping analysts understand adversary behavior patterns.

- **High-Risk IOC Table**  
  Lists high-risk indicators (URLs, domains, IPs) with contextual risk information for immediate SOC response actions.

---

## 🔑 Key Findings
- The phishing email impersonated Google and used urgency-based social engineering to prompt user interaction.
- Email authentication mechanisms (SPF, DKIM, and DMARC) **passed**, indicating abuse of a legitimate Gmail account rather than traditional spoofing.
- A URL shortener (Bitly) was used to obscure the final phishing destination.
- The final phishing page was hosted on a **trusted platform (GitHub Pages)** to evade detection.
- VirusTotal analysis showed **6 out of 98 security vendors** flagged the phishing URL as malicious.
- The landing page convincingly mimicked a Google login page and attempted to harvest user credentials.

---

## ⭐ Why This Project Matters
This project demonstrates how modern phishing campaigns bypass traditional security controls by abusing legitimate services and trusted infrastructure. It highlights the importance of:

- Behavioral-based phishing detection
- Threat intelligence enrichment
- MITRE ATT&CK–aligned analysis
- SOC-focused visualization and reporting

The project reflects real-world SOC workflows and showcases practical skills required for entry-level and junior SOC analyst roles.

---

## 👤 Author
**Ibrahim Idris**  
Cybersecurity Analyst | SOC & Threat Intelligence  

[![LinkedIn](https://img.shields.io/badge/-LinkedIn-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/ibrahim-idris-b5712a371/)


---

## 🧠 Analysis Workflow

```mermaid
flowchart LR
    A[Phishing Email Received] --> B[Email Header & Content Analysis]
    B --> C[URL Extraction]
    C --> D[ANY.RUN & VirusTotal Analysis]
    D --> E[IOC Extraction]
    E --> F[MITRE ATT&CK Mapping]
    F --> G[Splunk Dashboard Visualization]


