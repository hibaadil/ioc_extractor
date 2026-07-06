import re
import json
import sys
import os
import requests
from dotenv import load_dotenv

# -----------------------------
#  API key secured
# -----------------------------
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

# -----------------------------
# IOC Patterns
# -----------------------------
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
URL_REGEX = r"https?://[^\s]+"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
EMAIL_REGEX = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"
SHA1_REGEX = r"\b[a-fA-F0-9]{40}\b"
SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"


# -----------------------------
# IOC Extraction
# -----------------------------
def extract_iocs(text):
    return {
        "ips": list(set(re.findall(IP_REGEX, text))),
        "urls": list(set(re.findall(URL_REGEX, text))),
        "domains": list(set(re.findall(DOMAIN_REGEX, text))),
        "emails": list(set(re.findall(EMAIL_REGEX, text))),
        "hashes": {
            "md5": list(set(re.findall(MD5_REGEX, text))),
            "sha1": list(set(re.findall(SHA1_REGEX, text))),
            "sha256": list(set(re.findall(SHA256_REGEX, text)))
        }
    }


# -----------------------------
# Auto Labeling Engine
# -----------------------------
def auto_label(iocs, text):
    score = 0
    text_lower = text.lower()

    phishing_keywords = ["urgent", "verify", "suspended", "login", "password", "account"]
    malware_keywords = ["exe", "file", "blocked", "malicious", "execution"]

    if any(k in text_lower for k in phishing_keywords):
        score += 2

    if any(k in text_lower for k in malware_keywords):
        score += 3

    if iocs["urls"]:
        score += 2
    if iocs["ips"]:
        score += 2
    if iocs["hashes"]["md5"] or iocs["hashes"]["sha256"]:
        score += 3

    if score <= 2:
        label = "CLEAN"
    elif score <= 5:
        label = "SUSPICIOUS"
    elif score <= 8:
        label = "PHISHING"
    else:
        label = "MALWARE"

    return {
        "score": score,
        "label": label
    }


# -----------------------------
# VirusTotal Check (IP example)
# -----------------------------
def check_virustotal_ip(ip):
    if not VT_API_KEY:
        return {"error": "Missing VT API key"}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }

    except Exception as e:
        return {"error": str(e)}


# -----------------------------
# Main Function
# -----------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python ioc_tool.py <file.txt>")
        sys.exit(1)

    file_path = sys.argv[1]

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Extract IOCs
    iocs = extract_iocs(content)

    # Classification
    classification = auto_label(iocs, content)

    # VirusTotal enrichment
    vt_results = {}
    for ip in iocs["ips"]:
        vt_results[ip] = check_virustotal_ip(ip)

    # Final output
    result = {
        "classification": classification,
        "ioc_results": iocs,
        "virustotal": vt_results
    }

    # Print result
    print(json.dumps(result, indent=4))

    # Save result
    with open("output.json", "w") as f:
        json.dump(result, f, indent=4)

    print("\n[+] Analysis complete. Output saved to output.json")


if __name__ == "__main__":
    main()