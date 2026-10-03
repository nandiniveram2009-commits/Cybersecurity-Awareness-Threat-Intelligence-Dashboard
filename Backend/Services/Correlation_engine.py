def correlate_threats(records):
    """
    Correlates multiple threat records sharing indicators or categories into clusters.
    """
    clusters = {}
    for rec in records:
        cat = rec["threat_category"]
        if cat not in clusters:
            clusters[cat] = {
                "category": cat,
                "total_observations": 0,
                "indicators": [],
                "max_risk": 0
            }
        clusters[cat]["total_observations"] += 1
        clusters[cat]["indicators"].append(rec["indicator_value"])
        clusters[cat]["max_risk"] = max(clusters[cat]["max_risk"], float(rec["risk_score"]))
        
    return list(clusters.values())
