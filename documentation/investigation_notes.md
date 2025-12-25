# Investigation Notes – Phishing Email Analysis

## Objective
Determine whether the suspicious email contained malware or was part of a phishing campaign and assess overall risk.

---

## Step-by-Step Notes

### Step 1: Sandbox First Approach
- Uploaded `.eml` file to ANY.RUN to detect potential malware
- Goal: Validate whether email contained malicious attachments or execution logic

### Step 2: Sandbox Interpretation
- ANY.RUN flagged the email as malicious due to Outlook execution
- Determined this was expected behavior for `.eml` files
- No malicious child processes or payloads observed

**Decision:**  
Classified sandbox finding as a false positive.

---

### Step 3: Pivot to Threat Intelligence
- Extracted shortened URL from email
- Uploaded URL and email file to VirusTotal
- Followed redirect chain manually

---

### Step 4: URL Intelligence Findings
- Bitly URL redirected to GitHub Pages
- Page impersonated Google login
- VT showed 6/98 detections
- Page hosted on legitimate infrastructure

---

## Analyst Judgement
- No malware present
- High-confidence phishing attack
- Credential harvesting confirmed
- Infrastructure abuse rather than exploit-based delivery

---

## Lessons Learned
- Sandbox alerts require contextual interpretation
- Phishing analysis often depends more on TI than dynamic execution
- Legitimate services are frequently abused by attackers
