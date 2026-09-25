import os
import sys
import numpy as np
from datetime import datetime, timedelta, timezone

# Ensure we can import modules from the project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.risk.feature_extractor import extract_features
from core.risk import formula
from core.risk.classifier import risk_classifier

def main():
    print("--- 1. Testing extract_features ---")
    now_utc = datetime.now(timezone.utc)
    old_date = (now_utc - timedelta(days=120)).isoformat()
    ssl_date = (now_utc - timedelta(days=90)).isoformat()
    
    # Canonical OSINT bundle shape
    mock_bundle = {
        "domain_forensics": {
            "creation_date": old_date,
            "ssl_issued_on": ssl_date,
            "registrar": "Mock Registrar"
        },
        "url_trail": {
            "hops": ["http://a.com", "http://b.com", "http://c.com", "http://d.com"]
        },
        "typosquat": {
            "is_typosquat": True,
            "closest_legit": "phonepe.com",
            "distance": 1,
            "match": "phonep3.com"
        },
        "ip_analysis": {
            "is_known_bulletproof": True,
            "asn": "AS9009"
        },
        "vpa": {
            "mismatch": False
        },
        "is_blacklisted": True
    }
    
    features = extract_features(mock_bundle)
    assert isinstance(features, np.ndarray), "Features must be a numpy array"
    assert len(features) == 8, f"Expected 8 features, got {len(features)}"
    print("extract_features OK.")
    
    print("\n--- 2. Testing formula.calculate_risk (High Fraud) ---")
    # domain_age=0, redirect=4, typo=1, bullet=1, ssl_age=0, vpa_mis=1, black=1, typo_dist=1
    high_fraud = np.array([0, 4, 1, 1, 0, 1, 1, 1], dtype=float)
    fraud_risk = formula.calculate_risk(high_fraud)
    assert fraud_risk["risk_score"] > 60, f"Expected score > 60, got {fraud_risk['risk_score']}"
    assert fraud_risk["threat_level"] in ["HIGH", "CRITICAL"], f"Got {fraud_risk['threat_level']}"
    print("formula.calculate_risk (High Fraud) OK.")
    
    print("\n--- 3. Testing formula.calculate_risk (Clean) ---")
    # domain_age=800, redirect=0, typo=0, bullet=0, ssl_age=365, vpa_mis=0, black=0, typo_dist=0
    clean_vector = np.array([800, 0, 0, 0, 365, 0, 0, 0], dtype=float)
    clean_risk = formula.calculate_risk(clean_vector)
    assert clean_risk["risk_score"] < 30, f"Expected score < 30, got {clean_risk['risk_score']}"
    assert clean_risk["threat_level"] in ["SAFE", "LOW"], f"Got {clean_risk['threat_level']}"
    print("formula.calculate_risk (Clean) OK.")
    
    print("\n--- 4. Testing risk_classifier.predict ---")
    required_keys = {"risk_score", "confidence_interval", "threat_level", "score_source"}
    
    res_fraud = risk_classifier.predict(high_fraud)
    assert required_keys.issubset(res_fraud.keys()), "Missing keys in classifier output"
    assert 2 <= res_fraud["confidence_interval"] <= 18, f"CI {res_fraud['confidence_interval']} out of bounds"
    
    res_clean = risk_classifier.predict(clean_vector)
    assert required_keys.issubset(res_clean.keys()), "Missing keys in classifier output"
    assert 2 <= res_clean["confidence_interval"] <= 18, f"CI {res_clean['confidence_interval']} out of bounds"
    print("risk_classifier.predict OK.")
    
    print("\nPHASE 4 VERIFIED")

if __name__ == "__main__":
    main()
