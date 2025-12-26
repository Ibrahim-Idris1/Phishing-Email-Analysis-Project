# Detection Validation Notes

## Objective
Validate that Splunk detections correctly identify phishing-related activity using the generated IOC dataset.

---

## Test Methodology
- Uploaded final_analysis_report.csv into Splunk
- Executed all detection SPL queries
- Verified expected matches

---

## Results

| Detection | Result |
|-------|-------|
| Phishing URL Detection | Successful |
| Credential Harvesting Detection | Successful |
| URL Shortener Abuse Detection | Successful |

---

## Observations
- Detections correctly matched extracted IOCs
- No false positives observed within dataset
- Sandbox false positives were excluded by design

---

## Limitations
- No endpoint or email gateway logs available
- Detections are IOC-based rather than behavioral

---

## Future Improvements
- Integrate email gateway telemetry
- Add anomaly-based detections
