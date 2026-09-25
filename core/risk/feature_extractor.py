"""
Converts osint_bundle dict into a fixed-length numpy feature vector of length 10.
Feature order is fixed. Do not change order without retraining the classifier.
Does NOT perform any network calls or OSINT lookups — purely a transformation layer.
"""

import numpy as np
from datetime import datetime, timezone
from utils.logger import get_logger

logger = get_logger(__name__)

FEATURE_NAMES = [
    "domain_age_days",           # 0
    "redirect_count",            # 1
    "is_typosquat",              # 2
    "is_known_bulletproof_asn",  # 3
    "ssl_age_days",              # 4
    "vpa_mismatch",              # 5
    "is_blacklisted",            # 6
    "typosquat_distance",        # 7
    "cloaking_detected",         # 8
    "punycode_detected",         # 9
]

def _calculate_days_since(iso_date_str: str) -> int:
    """Helper to safely parse ISO dates and compute days elapsed."""
    if not iso_date_str:
        return 0
    try:
        # Normalize date-only strings to full ISO for parsing
        if "T" not in iso_date_str and " " not in iso_date_str:
            iso_date_str = iso_date_str + "T00:00:00"
            
        # Handle 'Z' suffix typically found in JS/JSON standard ISO dates
        if iso_date_str.endswith('Z'):
            iso_date_str = iso_date_str[:-1] + '+00:00'
            
        dt = datetime.fromisoformat(iso_date_str)
        
        # Calculate delta based on whether parsed date is timezone-aware
        if dt.tzinfo is not None:
            now = datetime.now(timezone.utc)
        else:
            now = datetime.utcnow()
            
        delta = now - dt
        return max(0, delta.days)
    except Exception as e:
        logger.warning(f"Failed to parse date '{iso_date_str}' for feature extraction: {e}")
        return 0

def extract_features(osint_bundle: dict) -> np.ndarray:
    if not osint_bundle:
        osint_bundle = {}
        
    domain_forensics = osint_bundle.get("domain_forensics", {})
    url_trail = osint_bundle.get("url_trail", {})
    typosquat = osint_bundle.get("typosquat", {})
    ip_analysis = osint_bundle.get("ip_analysis", {})
    vpa = osint_bundle.get("vpa", {})
    
    # 0: domain_age_days
    creation_date = domain_forensics.get("creation_date", "")
    domain_age_days = _calculate_days_since(creation_date)
    
    # 1: redirect_count
    # As explicitly requested, use len(url_trail.hops)
    redirect_count = len(url_trail.get("hops", []))
    
    # 2: is_typosquat
    is_typosquat = 1 if typosquat.get("is_typosquat") else 0
    
    # 3: is_known_bulletproof_asn
    is_bulletproof = 1 if ip_analysis.get("is_known_bulletproof") else 0
    
    # 4: ssl_age_days
    ssl_issued_on = domain_forensics.get("ssl_issued_on", "")
    ssl_age_days = _calculate_days_since(ssl_issued_on)
    
    # 5: vpa_mismatch
    vpa_mismatch = 1 if vpa.get("mismatch") else 0
    
    # 6: is_blacklisted
    is_blacklisted = 1 if osint_bundle.get("is_blacklisted") else 0
    
    # 7: typosquat_distance
    distance = typosquat.get("distance", 0)
    typosquat_distance = distance if is_typosquat else 0

    # 8: cloaking_detected — set by url_tracer when divergent destinations are observed
    cloaking_detected = 1.0 if url_trail.get("cloaking_detected") else 0.0

    # 9: punycode_detected — set by typosquat_detector when any xn-- label is found
    punycode_detected = 1.0 if typosquat.get("punycode_detected") else 0.0

    # Assemble feature vector in strict index order (length must stay 10)
    features = [
        domain_age_days,
        redirect_count,
        is_typosquat,
        is_bulletproof,
        ssl_age_days,
        vpa_mismatch,
        is_blacklisted,
        typosquat_distance,
        cloaking_detected,
        punycode_detected,
    ]

    return np.array(features, dtype=float)
