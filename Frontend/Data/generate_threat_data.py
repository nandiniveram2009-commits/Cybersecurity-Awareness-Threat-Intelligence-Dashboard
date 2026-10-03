import os
import csv
import random
from datetime import datetime, timedelta

CATEGORIES = [
    "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS", 
    "WEB THREATS", "NETWORK THREATS", "VULNERABILITY EXPOSURE", 
    "SOCIAL ENGINEERING", "DATA EXPOSURE", "ACCOUNT SECURITY"
]

INDICATOR_TYPES = ["IP ADDRESS", "DOMAIN", "URL", "FILE HASH", "EMAIL/SENDER DOMAIN", "CVE ID"]

SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]

SOURCES = [
    ("Internal SOC", "A"), ("Security Vendor", "A"), 
    ("Public Threat Feed", "B"), ("Research Report", "B"), 
    ("Community Submission", "C"), ("Unknown Source", "D")
]

MITRE_TACTICS = [
    ("Initial Access", "T1566", "Phishing"),
    ("Execution", "T1204", "User Execution"),
    ("Credential Access", "T1003", "OS Credential Dumping"),
    ("Defense Evasion", "T1070", "Indicator Removal"),
    ("Discovery", "T1082", "System Information Discovery"),
    ("Command and Control", "T1071", "Application Layer Protocol"),
    ("Exfiltration", "T1041", "Exfiltration Over C2 Channel")
]

CVES = [
    ("CVE-2026-1001", "Web Server RCE", "CRITICAL", 9.8),
    ("CVE-2026-1024", "Authentication Bypass", "CRITICAL", 9.1),
    ("CVE-2026-2055", "Privilege Escalation", "HIGH", 7.8),
    ("CVE-2026-3012", "Cross-Site Scripting", "MEDIUM", 6.1),
    ("CVE-2026-4409", "Information Disclosure", "LOW", 3.3)
]

def generate_indicator(ind_type):
    if ind_type == "IP ADDRESS":
        return f"198.51.100.{random.randint(1, 254)}"
    elif ind_type == "DOMAIN":
        return f"phish-domain-{random.randint(1000, 9999)}.invalid"
    elif ind_type == "URL":
        return f"https://example.com/auth/verify?token={random.randint(100000, 999999)}"
    elif ind_type == "FILE HASH":
        return "".join(random.choices("0123456789abcdef", k=64))
    elif ind_type == "EMAIL/SENDER DOMAIN":
        return f"support-secure-{random.randint(10, 99)}.example.org"
    elif ind_type == "CVE ID":
        return random.choice(CVES)[0]
    return "192.0.2.1"

def generate_dataset(num_records=2000):
    os.makedirs("data", exist_ok=True)
    file_path = "data/threat_intelligence_dataset.csv"
    
    headers = [
        "threat_id", "timestamp", "threat_name", "threat_category",
        "indicator_type", "indicator_value", "source_name", "confidence_score",
        "severity", "risk_score", "status", "first_seen", "last_seen",
        "country_or_region", "description", "mitre_tactic", "mitre_technique",
        "cve_id"
    ]
    
    with open(file_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        base_time = datetime.utcnow() - timedelta(days=90)
        
        for i in range(1, num_records + 1):
            threat_id = f"THR-2026-{i:04d}"
            category = random.choice(CATEGORIES)
            ind_type = random.choice(INDICATOR_TYPES)
            indicator = generate_indicator(ind_type)
            source, _ = random.choice(SOURCES)
            
            confidence = random.randint(30, 100)
            severity = random.choice(SEVERITIES)
            
            # Risk scoring heuristics
            sev_multiplier = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 95}
            risk_score = min(100, max(5, int(sev_multiplier[severity] * (confidence / 100) + random.randint(-5, 10))))
            
            status = random.choice(STATUSES)
            first_seen = (base_time + timedelta(days=random.randint(0, 80))).isoformat()
            last_seen = (datetime.fromisoformat(first_seen) + timedelta(days=random.randint(0, 10))).isoformat()
            
            country = random.choice(["US", "DE", "NL", "SG", "BR", "JP", "RU (Synthetic)", "CN (Synthetic)", "Unknown"])
            description = f"Synthetic defensive threat record regarding {category.lower()} utilizing indicator {indicator} [DEMO ONLY]."
            
            tactic_info = random.choice(MITRE_TACTICS)
            tactic = tactic_info[0]
            technique = f"{tactic_info[1]} - {tactic_info[2]}"
            
            cve = random.choice(CVES)[0] if category == "VULNERABILITY EXPOSURE" or random.random() > 0.7 else ""
            
            writer.writerow([
                threat_id, first_seen, f"{category.title()} Campaign #{i}", category,
                ind_type, indicator, source, confidence, severity, risk_score,
                status, first_seen, last_seen, country, description, tactic, technique, cve
            ])
            
    print(f"[+] Successfully generated {num_records} synthetic threat records at '{file_path}'.")

if __name__ == "__main__":
    generate_dataset()
