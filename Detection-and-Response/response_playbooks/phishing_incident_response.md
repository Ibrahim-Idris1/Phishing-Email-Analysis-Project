# Phishing Incident Response Playbook

## Purpose
Provide a structured response to phishing incidents involving malicious links and credential harvesting.

---

## Detection Triggers
- High-risk URL detected
- VirusTotal detection threshold exceeded
- Credential harvesting technique identified

---

## Response Workflow

### 1. Triage
- Validate IOC accuracy
- Confirm phishing classification
- Identify affected users

---

### 2. Containment
- Block malicious URLs and domains
- Remove phishing emails from mailboxes
- Isolate impacted user accounts if necessary

---

### 3. Eradication
- Reset compromised credentials
- Revoke active sessions
- Remove persistence mechanisms if present

---

### 4. Recovery
- Restore account access
- Monitor for suspicious logins
- Validate detection controls

---

### 5. Lessons Learned
- Improve phishing detection rules
- Update user awareness guidance
