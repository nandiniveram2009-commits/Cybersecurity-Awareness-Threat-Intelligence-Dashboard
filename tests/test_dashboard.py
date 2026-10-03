import unittest
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk
from backend.services.vulnerability_service import calculate_vulnerability_priority

class CyberDashboardTestCase(unittest.TestCase):
    
    def test_valid_ipv4(self):
        res = validate_indicator("IP ADDRESS", "198.51.100.25")
        self.assertTrue(res["valid"])
        
    def test_invalid_ipv4(self):
        res = validate_indicator("IP ADDRESS", "999.999.999.999")
        self.assertFalse(res["valid"])
        
    def test_risk_scoring(self):
        risk = calculate_threat_risk("HIGH", 85, 3)
        self.assertGreaterEqual(risk["risk_score"], 0)
        self.assertLessEqual(risk["risk_score"], 100)
        
    def test_vulnerability_priority(self):
        priority = calculate_vulnerability_priority(9.8, 5, True, True)
        self.assertGreater(priority, 50)

if __name__ == "__main__":
    unittest.main()
