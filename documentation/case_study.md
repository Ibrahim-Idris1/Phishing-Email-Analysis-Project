# Phishing Case Study: Google Account Security Alert Credential Harvesting

## Executive Summary
This case study documents the investigation of a phishing email impersonating a Google Security Alert. The email leveraged social engineering techniques to induce urgency and redirect the victim to a credential-harvesting website through a shortened URL. Although initial sandbox analysis suggested suspicious behavior, deeper investigation confirmed that the threat was purely phishing-based with no associated malware payload. The incident highlights how attackers abuse legitimate infrastructure and how analysts must interpret sandbox results critically.

---

## Incident Overview
- **Attack Type:** Phishing (Credential Harvesting)
- **Impersonated Brand:** Google Security
- **Delivery Method:** Email
- **Objective:** Steal Google account credentials
- **Threat Classification:** High-risk phishing, no malware payload

---

## Initial Detection
The phishing email claimed that a “security issue” had been detected on the recipient’s Google account and urged immediate action to “check activity.” The message contained a shortened URL embedded within the body, directing the user to a fake Google login page designed to harvest credentials.

---

## Analysis Methodology

### 1. Email Examination
- Reviewed sender address, subject, and metadata
- Extracted embedded URL from the email body
- Analyzed authentication results (SPF, DKIM, DMARC)

**Key Insight:**  
SPF and DKIM checks passed, indicating the email was likely sent from a legitimate Gmail account. This suggests possible abuse of a compromised or throwaway account rather than spoofing.

---

### 2. Sandbox Analysis (ANY.RUN)
The `.eml` email file was uploaded to ANY.RUN as a precautionary measure to identify any potential malware attachments or hidden execution behavior.

**Observed Behavior:**
- ANY.RUN flagged suspicious activity when the file triggered Microsoft Outlook upon opening.
- This behavior was initially interpreted as malicious by the sandbox.

**Analyst Assessment:**
- The behavior was expected, as `.eml` files open in an email client by default.
- No malicious payloads, exploit attempts, or secondary malware execution were observed.

**Conclusion:**  
The sandbox alert represented a **false positive**, and the threat was confirmed to be phishing-only.

---

### 3. Threat Intelligence & URL Analysis
After ruling out malware, analysis pivoted to threat intelligence.

- Uploaded the email and extracted URLs to VirusTotal
- Investigated the shortened Bitly link
- Followed the redirect chain to the final destination

**Findings:**
- Bitly URL redirected to a GitHub Pages-hosted website
- The final page impersonated a Google login portal
- VirusTotal flagged the URL as malicious (6/98 vendors)
- The site was hosted on legitimate cloud infrastructure

---

## Technical Findings

| Indicator | Value |
|--------|------|
| Initial URL |https://bit.ly/4oMx5xM?rid=ubi9ih8 |
| Final URL | https://cyberkid001.github.io/site/index.html" |
| Hosting IP | 67.199.248.11 |
| VT Detections | 4/98 vendors |
| Credential Harvesting | Yes |
| Malware Payload | None |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Description |
|------|---------|------------|
| Initial Access | T1566.002 | Phishing via malicious link |
| Credential Access | T1598.003 | Credential harvesting |
| Resource Development | T1583.001 | Abuse of legitimate infrastructure |

---

## Attack Flow
1. Victim receives phishing email impersonating Google
2. User is urged to check account activity
3. Click on shortened URL
4. Redirect to fake Google login page
5. Credentials submitted to attacker-controlled infrastructure

---

## Key Findings
- Phishing email passed SPF/DKIM checks, increasing legitimacy
- URL shortening used to obscure malicious destination
- GitHub Pages abused to host phishing infrastructure
- Sandbox alert was a false positive caused by expected email client behavior
- No malware was involved; threat relied entirely on social engineering

---

## Recommendations
- Enforce phishing-resistant MFA
- Increase user awareness of URL shorteners
- Implement email security rules for brand impersonation
- Monitor abuse of trusted cloud hosting platforms

---

## Conclusion
This investigation demonstrates the importance of analyst judgment when interpreting automated sandbox results. While sandbox tools are valuable for malware detection, phishing investigations often require pivoting to threat intelligence and infrastructure analysis to accurately classify threats.
