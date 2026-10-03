from backend.services.threat_service import search_indicator_in_db

def enrich_indicator(indicator_value):
    """
    Enriches an indicator using local synthetic threat intelligence records.
    """
    search_res = search_indicator_in_db(indicator_value)
    
    if not search_res.get("found"):
        return {
            "indicator": indicator_value,
            "enrichment_status": "No local intelligence found",
            "risk_score": 0,
            "confidence_score": 0,
            "analyst_notes": "No sightings recorded in local threat store."
        }
        
    primary_record = search_res["records"][0]
    
    enriched_data = {
        "indicator": indicator_value,
        "indicator_type": primary_record["indicator_type"],
        "enrichment_status": "Enriched via Local CTI Store",
        "first_seen": primary_record["first_seen"],
        "last_seen": primary_record["last_seen"],
        "associated_categories": list(set(r["threat_category"] for r in search_res["records"])),
        "confidence_score": int(primary_record["confidence_score"]),
        "severity": primary_record["severity"],
        "risk_score": int(primary_record["risk_score"]),
        "source": primary_record["source_name"],
        "mitre_tactic": primary_record["mitre_tactic"],
        "mitre_technique": primary_record["mitre_technique"],
        "observation_count": search_res["matches_count"],
        "analyst_notes": f"Auto-enriched. Associated with {search_res['matches_count']} synthetic observation events."
    }
    
    return enriched_data
