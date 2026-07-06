# IOC Extractor & Threat Intelligence Analyzer

## Overview

A lightweight SOC automation tool developed to extract **Indicators of Compromise (IOCs)** from security-related text samples and enrich them using threat intelligence sources.

The project simulates a **Security Operations Center (SOC)** workflow by analyzing different security scenarios:

- Phishing emails
- Malware alerts
- Suspicious login activities
- Clean business emails

The tool extracts security indicators, performs risk classification, and integrates with VirusTotal for threat intelligence enrichment.

---

# Features

## IOC Extraction

Automatically extracts:

- IP addresses
- URLs
- Domains
- Email addresses
- File hashes:
  - MD5
  - SHA1
  - SHA256

---

## Threat Classification

The tool classifies security events into different categories:

- CLEAN
- SUSPICIOUS
- PHISHING
- MALWARE

The classification is based on detected indicators and security-related patterns.

---

## VirusTotal API Enrichment

The tool integrates with the VirusTotal API to enrich extracted indicators with external threat intelligence.

Features include:

- IP reputation lookup
- Malware hash reputation validation

API credentials are securely handled using environment variables.

---

# Workflow

```
Security Sample
        |
        v
IOC Extraction
        |
        v
Risk Classification
        |
        v
VirusTotal Enrichment
        |
        v
JSON Investigation Report
```

---

# Installation

## Install Dependencies

Run:

```bash
pip install -r requirements.txt
```

---

# Configuration

Create a `.env` file in the project directory:

```env
VT_API_KEY=your_virustotal_api_key
```

The API key is loaded securely during execution and is not stored inside the source code.

---

# Usage

Run the analyzer against a security sample:

```bash
python ioc_tool.py samples/sample_01_phishing.txt
```

Example:

```bash
python ioc_tool.py samples/sample_02_malware.txt
```

The tool generates a JSON investigation report containing:

- Classification result
- Extracted IOCs
- VirusTotal enrichment results

---

# Security Practices

The project follows secure development practices:

- API keys stored outside source code
- Environment variable configuration
- No malware samples uploaded to the repository
- Only IOC information and analysis results are stored

---

# Future Improvements

Planned enhancements:

- URL reputation checking
- Domain reputation checking
- Automated email (`.eml`) parsing
- CSV report generation
- MITRE ATT&CK mapping
- SIEM integration
- Automated alert prioritization

---

# Technologies Used

- Python
- Regular Expressions
- VirusTotal API
- JSON
- Threat Intelligence concepts
- SOC investigation methodology

---

# Author

**Hiba Adil**

Cybersecurity / SOC Analyst Portfolio Project