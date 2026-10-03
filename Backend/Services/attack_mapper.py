def map_to_attack(category):
    mapping_db = {
        "PHISHING": {"tactic": "Initial Access", "technique_id": "T1566", "technique": "Phishing"},
        "MALWARE": {"tactic": "Execution", "technique_id": "T1204", "technique": "User Execution"},
        "Ransomware": {"tactic": "Impact", "technique_id": "T1486", "technique": "Data Encrypted for Impact"},
        "CREDENTIAL THREATS": {"tactic": "Credential Access", "technique_id": "T1003", "technique": "OS Credential Dumping"},
        "WEB THREATS": {"tactic": "Initial Access", "technique_id": "T1190", "technique": "Exploit Public-Facing Application"}
    }
    return mapping_db.get(category, {"tactic": "Discovery", "technique_id": "T1082", "technique": "System Information Discovery"})
