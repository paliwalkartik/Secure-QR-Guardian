"""
Tests for ML risk classification and feature extraction.
"""
import pytest
import numpy as np
from core.risk.feature_extractor import extract_features
from core.risk.formula import calculate_risk
from core.risk.classifier import RiskClassifier

@pytest.fixture
def dummy_osint():
    return {
        "domain_forensics": {"creation_date": "2025-01-01T00:00:00Z"},
        "url_trail": {"hops": ["hop1", "hop2"]},
        "typosquat": {"is_typosquat": True, "distance": 1},
        "ip_analysis": {"is_known_bulletproof": True},
        "vpa": {"mismatch": True},
        "is_blacklisted": False
    }

def test_extract_features_valid(dummy_osint):
    """Test feature extractor maps dict OSINT bundle into strict numeric array."""
    features = extract_features(dummy_osint)
    assert len(features) == 11
    assert features[1] == 2  # redirects
    assert features[2] == 1  # typosquat
    assert features[3] == 1  # bulletproof

def test_extract_features_empty():
    """Test feature extractor handles empty OSINT gracefully."""
    features = extract_features({})
    assert len(features) == 11
    assert np.all(features >= 0)

def test_calculate_risk_formula():
    """Test deterministic fallback formula assigns risk correctly."""
    features = np.array([5, 1, 0, 0, 90, 0, 0, 0, 0, 0, 0], dtype=float)
    res = calculate_risk(features)
    assert "risk_score" in res
    assert "threat_level" in res
    assert res["score_source"] == "formula"

def test_calculate_risk_high_threat():
    """Test formula detects extreme fraud features (blacklisted, bulletproof)."""
    # 6: is_blacklisted = 1, 3: bulletproof = 1
    features = np.array([1, 4, 1, 1, 10, 1, 1, 2, 0, 0, 0], dtype=float)
    res = calculate_risk(features)
    assert res["risk_score"] > 80
    assert res["threat_level"] in ["HIGH", "CRITICAL"]

def test_classifier_fallback():
    """Test classifier smoothly falls back to formula if model is absent."""
    classifier = RiskClassifier()
    # Force no model
    classifier.model = None
    
    features = np.array([5, 1, 0, 0, 90, 0, 0, 0, 0, 0, 0], dtype=float)
    res = classifier.predict(features)
    assert res["score_source"] == "formula"
