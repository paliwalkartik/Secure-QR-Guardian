"""
Fallback risk scoring formula. Used when ML classifier model is not available.
Less accurate than classifier. confidence_interval is fixed at 15.
"""

import numpy as np
from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)

def calculate_risk(features: np.ndarray) -> dict:
    if len(features) < 8:
        logger.error("Invalid feature array length passed to formula. Expected 8.")
        return {
            "risk_score": 0,
            "threat_level": "SAFE",
            "score_source": "formula",
            "confidence_interval": 15
        }
        
    domain_age_days = features[0]
    is_typosquat = features[2]
    vpa_mismatch = features[5]
    is_blacklisted = features[6]
    
    danger_age = getattr(settings, "DOMAIN_DANGER_AGE_DAYS", 7)
    safe_age = getattr(settings, "DOMAIN_SAFE_AGE_DAYS", 730)
    
    # 1. Calculate domain_age_factor
    if domain_age_days == 0:
        domain_age_factor = 0.5  # Unknown age
    elif domain_age_days < danger_age:
        domain_age_factor = 1.0  # Highly dangerous
    elif domain_age_days > safe_age:
        domain_age_factor = 0.0  # Generally safe
    else:
        # Linear interpolation between 0 and 1
        if safe_age > danger_age:
            domain_age_factor = 1.0 - ((domain_age_days - danger_age) / float(safe_age - danger_age))
        else:
            domain_age_factor = 0.0
            
    # 2. Extract and cast boolean flags
    mismatch_flag = float(max(is_typosquat, vpa_mismatch))
    blacklist_status = float(is_blacklisted)
    
    # 3. Compute raw score and final risk score
    raw_score = (0.6 * mismatch_flag) + (0.3 * domain_age_factor) + (0.1 * blacklist_status)
    risk_score = int(raw_score * 100)
    
    # Clamp the risk score to 0-100 just in case
    risk_score = max(0, min(100, risk_score))
    
    # 4. Map risk score to threat level
    if risk_score <= 25:
        threat_level = "SAFE"
    elif risk_score <= 50:
        threat_level = "LOW"
    elif risk_score <= 70:
        threat_level = "MEDIUM"
    elif risk_score <= 85:
        threat_level = "HIGH"
    else:
        threat_level = "CRITICAL"
        
    return {
        "risk_score": risk_score,
        "threat_level": threat_level,
        "score_source": "formula",
        "confidence_interval": 15
    }
