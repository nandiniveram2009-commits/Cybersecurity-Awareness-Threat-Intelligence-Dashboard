def calculate_threat_risk(severity, confidence, observation_frequency, source_reliability_weight=1.0):
    """
    Computes numerical risk score (0-100) and severity classification.
    Weighting formula:
      - Severity: 30%
      - Confidence: 25%
      - Recency/Frequency: 25%
      - Source Reliability: 20%
    """
    sev_map = {"INFORMATIONAL": 10, "LOW": 35, "MEDIUM": 60, "HIGH": 80, "CRITICAL": 100}
    base_sev = sev_map.get(severity.upper(), 30)
    
    freq_score = min(100, observation_frequency * 10)
    
    risk_score = (
        (base_sev * 0.30) +
        (confidence * 0.25) +
        (freq_score * 0.25) +
        (100 * source_reliability_weight * 0.20)
    )
    
    risk_score = round(min(100, max(0, risk_score)), 2)
    
    if risk_score <= 20:
        classification = "INFORMATIONAL"
    elif risk_score <= 40:
        classification = "LOW"
    elif risk_score <= 60:
        classification = "MEDIUM"
    elif risk_score <= 80:
        classification = "HIGH"
    else:
        classification = "CRITICAL"
        
    return {
        "risk_score": risk_score,
        "risk_classification": classification,
        "confidence_score": confidence
    }
