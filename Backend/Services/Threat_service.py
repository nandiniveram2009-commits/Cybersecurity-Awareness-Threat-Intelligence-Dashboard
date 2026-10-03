import csv
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "../../data/threat_intelligence_dataset.csv")

def search_indicator_in_db(indicator_value):
    """
    Searches the synthetic dataset for an indicator match.
    Performs local lookup ONLY without querying external servers.
    """
    if not os.path.exists(DATA_PATH):
        return {"error": "Dataset not found. Please run generate_threat_data.py"}
        
    results = []
    with open(DATA_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["indicator_value"].lower() == indicator_value.lower():
                results.append(row)
                
    if not results:
        return {"found": False, "indicator": indicator_value, "message": "Indicator not present in local demo dataset."}
        
    return {
        "found": True,
        "indicator": indicator_value,
        "matches_count": len(results),
        "records": results
    }
