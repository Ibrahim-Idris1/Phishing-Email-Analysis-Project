# Detection & Response

This directory demonstrates how findings from the phishing investigation were operationalized into actionable SOC detections and response procedures.

The objective is to show the full security lifecycle:
**Analysis → Detection → Response**

---

## Scope
- Detect phishing-related indicators extracted during analysis
- Identify credential-harvesting activity
- Monitor abuse of URL shortening services
- Provide structured incident response playbooks

---

## Detection Logic
Detections are based on:
- Extracted Indicators of Compromise (IOCs)
- MITRE ATT&CK mappings
- Threat intelligence enrichment (VirusTotal)
- IOC risk classification

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Description |
|------|----------|------------|
| Initial Access | T1566.002 | Phishing via malicious link |
| Credential Access | T1598.003 | Credential harvesting |
| Resource Development | T1583.001 | Abuse of legitimate infrastructure |

---

## Contents
- **splunk_detections/** – SPL-based detection logic
- **response_playbooks/** – Incident response procedures
- **validation/** – Detection testing and validation notes

