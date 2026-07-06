# How It Works

The IOC Extractor & Threat Intelligence Analyzer simulates a Security Operations Center (SOC) workflow by analyzing security-related text, extracting Indicators of Compromise (IOCs), evaluating risk, and enriching findings with threat intelligence.

## Workflow

### 1. Input Collection

The tool receives security-related text samples, including:

- Phishing emails
- Malware alerts
- Authentication logs
- Suspicious activity reports

The collected data is analyzed to identify potential security threats.

---

### 2. IOC Extraction

The tool uses regular expressions to automatically identify and extract Indicators of Compromise (IOCs), including:

- IP addresses
- URLs
- Domains
- Email addresses
- File hashes (MD5, SHA1, SHA256)

These indicators are collected for further analysis and enrichment.

---

### 3. Risk Classification

The tool analyzes extracted indicators and security-related keywords to calculate the risk level of the input.

The classification process considers:

- Suspicious keywords
- Extracted IOCs
- URL reputation
- File hashes
- Authentication activities

### Risk Categories

| Category | Description |
|----------|-------------|
| CLEAN | No suspicious activity detected |
| SUSPICIOUS | Requires further investigation |
| PHISHING | Possible credential theft or social engineering attack |
| MALWARE | Malicious files or infrastructure indicators detected |

---

### 4. Threat Intelligence Enrichment

Extracted indicators are analyzed using the **VirusTotal API** to obtain reputation information.

The enrichment process provides additional context, including:

- Malicious detection results
- Reputation scores
- Security vendor analysis
- Indicator classification

---

### 5. Investigation Output

The analysis results are exported as JSON reports containing:

- Risk classification
- Extracted IOCs
- Threat intelligence enrichment results
- Investigation details

Example output:

```json
{
  "classification": "PHISHING",
  "risk_score": 85,
  "iocs": {
    "emails": ["example@domain.com"],
    "urls": ["http://suspicious-site.com"],
    "ips": ["192.168.1.10"]
  },
  "threat_intelligence": {
    "malicious": true,
    "source": "VirusTotal"
  }
}
```

---

# SOC Workflow Mapping

The tool follows a simplified Security Operations Center investigation workflow:

1. **Alert Ingestion**  
   Collect security alerts, emails, and logs.

2. **IOC Extraction**  
   Identify and extract potential indicators of compromise.

3. **Threat Intelligence Enrichment**  
   Query external intelligence sources to analyze indicators.

4. **Risk Assessment**  
   Evaluate the severity and classify the security event.

5. **Investigation Reporting**  
   Generate structured reports for analyst review.

---

This workflow demonstrates how SOC analysts automate early-stage threat detection and investigation processes.