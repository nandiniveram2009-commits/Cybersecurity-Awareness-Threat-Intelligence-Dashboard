import re
import ipaddress

def validate_indicator(indicator_type, value):
    """
    Validates whether the provided indicator value matches its expected syntax.
    Returns: dict(valid=bool, indicator_type=str, normalized_value=str, notes=str)
    """
    value = value.strip()
    notes = "Valid syntax."
    valid = False
    
    if indicator_type == "IP ADDRESS":
        try:
            ip_obj = ipaddress.ip_address(value)
            normalized = str(ip_obj)
            valid = True
            if ip_obj.is_private or ip_obj.is_loopback:
                notes = "Valid IP address, but belongs to private/loopback space."
        except ValueError:
            notes = "Invalid IPv4 or IPv6 address format."
            return {"valid": False, "indicator_type": indicator_type, "normalized_value": value, "validation_notes": notes}
            
    elif indicator_type == "DOMAIN" or indicator_type == "EMAIL/SENDER DOMAIN":
        domain_regex = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
        )
        if domain_regex.match(value) or value.endswith(".invalid"):
            valid = True
            normalized = value.lower()
        else:
            notes = "Invalid domain syntax structure."
            return {"valid": False, "indicator_type": indicator_type, "normalized_value": value, "validation_notes": notes}
            
    elif indicator_type == "URL":
        url_regex = re.compile(
            r"^https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
        )
        if url_regex.match(value):
            valid = True
            normalized = value
        else:
            notes = "Invalid URL protocol or structure."
            return {"valid": False, "indicator_type": indicator_type, "normalized_value": value, "validation_notes": notes}
            
    elif indicator_type == "FILE HASH":
        clean_val = value.lower()
        if len(clean_val) == 32 and re.match(r"^[0-9a-f]{32}$", clean_val):
            valid = True
            normalized = clean_val
            notes = "Valid MD5 hash format."
        elif len(clean_val) == 40 and re.match(r"^[0-9a-f]{40}$", clean_val):
            valid = True
            normalized = clean_val
            notes = "Valid SHA-1 hash format."
        elif len(clean_val) == 64 and re.match(r"^[0-9a-f]{64}$", clean_val):
            valid = True
            normalized = clean_val
            notes = "Valid SHA-256 hash format."
        else:
            notes = "Invalid file hash length or character set."
            return {"valid": False, "indicator_type": indicator_type, "normalized_value": value, "validation_notes": notes}
            
    elif indicator_type == "CVE ID":
        cve_regex = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
        if cve_regex.match(value):
            valid = True
            normalized = value.upper()
        else:
            notes = "Invalid CVE ID formatting (Expected CVE-YYYY-NNNN)."
            return {"valid": False, "indicator_type": indicator_type, "normalized_value": value, "validation_notes": notes}
    else:
        normalized = value
        notes = "Unknown indicator type."
        
    return {
        "valid": valid,
        "indicator_type": indicator_type,
        "normalized_value": normalized,
        "validation_notes": notes
          }
