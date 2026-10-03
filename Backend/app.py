import csv
import os
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from backend.services.ioc_validator import validate_indicator
from backend.services.enrichment_engine import enrich_indicator
from backend.services.risk_engine import calculate_threat_risk
from backend.services.correlation_engine import correlate_threats
from backend.services.vulnerability_service import calculate_vulnerability_priority

app = Flask(__name__, template_folder="../frontend", static_folder="../frontend")
CORS(app)

DATA_PATH = os.path.join(os.path.dirname(__file__), "../data/threat_intelligence_dataset.csv")

def load_dataset():
    if not os.path.exists(DATA_PATH):
        return []
    records = []
    with open(DATA_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)
    return records

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/dashboard/stats", methods=["GET"])
def get_dashboard_stats():
    records = load_dataset()
    if not records:
        return jsonify({"error": "Dataset not found. Run generator."}), 404
        
    total_threats = len(records)
    critical_count = sum(1 for r in records if r["severity"] == "CRITICAL")
    high_count = sum(1 for r in records if r["severity"] == "HIGH")
    avg_confidence = round(sum(int(r["confidence_score"]) for r in records) / total_threats, 1)
    
    categories = {}
    for r in records:
        cat = r["threat_category"]
        categories[cat] = categories.get(cat, 0) + 1
        
    return jsonify({
        "total_threats": total_threats,
        "critical_threats": critical_count,
        "high_threats": high_count,
        "average_confidence": avg_confidence,
        "categories_breakdown": categories
    })

@app.route("/api/threats", methods=["GET"])
def get_threats():
    records = load_dataset()
    severity = request.args.get("severity")
    category = request.args.get("category")
    
    if severity:
        records = [r for r in records if r["severity"].upper() == severity.upper()]
    if category:
        records = [r for r in records if r["threat_category"].upper() == category.upper()]
        
    return jsonify(records[:100]) # Return top 100 for performance

@app.route("/api/indicators/search", methods=["GET"])
def search_indicator():
    value = request.args.get("value", "")
    ind_type = request.args.get("type", "IP ADDRESS")
    
    validation = validate_indicator(ind_type, value)
    if not validation["valid"]:
        return jsonify({"valid": False, "note": validation["validation_notes"]})
        
    enrichment = enrich_indicator(validation["normalized_value"])
    return jsonify({"valid": True, "validation": validation, "enrichment": enrichment})

@app.route("/api/vulnerabilities", methods=["GET"])
def get_vulnerabilities():
    sample_vulnerabilities = [
        {"cve_id": "CVE-2026-1001", "product": "Enterprise Gateway", "severity": "CRITICAL", "cvss": 9.8, "patch": True, "priority": calculate_vulnerability_priority(9.8, 5, True, True)},
        {"cve_id": "CVE-2026-1024", "product": "Auth Portal", "severity": "CRITICAL", "cvss": 9.1, "patch": True, "priority": calculate_vulnerability_priority(9.1, 5, True, True)},
        {"cve_id": "CVE-2026-2055", "product": "Internal Database", "severity": "HIGH", "cvss": 7.8, "patch": False, "priority": calculate_vulnerability_priority(7.8, 4, False, True)}
    ]
    return jsonify(sample_vulnerabilities)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
