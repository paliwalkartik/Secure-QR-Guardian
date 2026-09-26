"""
Fallback risk scoring formula. Used when ML classifier model is not available.
Less accurate than classifier. confidence_interval is fixed at 15.
Weights are dynamic: _calculate_dynamic_weights inspects the feature vector and
shifts emphasis to whichever signal is most dominant. Default weights match the
original blueprint (0.6 mismatch, 0.3 domain_age, 0.1 blacklist).
In addition to reweighting, cloaking_detected and punycode_detected each add a
flat ADDITIVE bonus (CLOAKING_BONUS=0.35, PUNYCODE_BONUS=0.30) that is applied
ON TOP of the weighted sub-score and clamped to [0, 100]. This ensures these
attack signals raise the score even when mismatch/age/blacklist are all low.
Does NOT make network calls or import from core/osint/.
"""

import numpy as np
from config.settings import settings
from utils.logger import get_logger

logger = get_logger(__name__)


def _calculate_dynamic_weights(features: np.ndarray) -> tuple:
    """
    Return (w_mismatch, w_domain_age, w_blacklist) based on the dominant signal.

    Conditions are evaluated in strict priority order — first match wins.
    Caller is responsible for ensuring len(features) >= 10 before calling this.

    Priority table:
      1. cloaking_detected  (features[8] == 1.0) → blacklist-heavy  (0.25, 0.25, 0.50)
      2. punycode_detected  (features[9] == 1.0) → mismatch-heavy   (0.50, 0.40, 0.10)
      3. very fresh domain  (features[0] < DOMAIN_DANGER_AGE_DAYS)  (0.30, 0.60, 0.10)
      4. redirect chain     (features[1] >= 3)   → blacklist-heavy  (0.35, 0.25, 0.40)
      5. default            (original blueprint)                     (0.60, 0.30, 0.10)

    Private — only called by calculate_risk. Never raises.
    Returns a 3-tuple of floats that sum to 1.0.
    """
    danger_age = getattr(settings, "DOMAIN_DANGER_AGE_DAYS", 7)

    if features[8] == 1.0:
        return (0.25, 0.25, 0.50), "cloaking detected"

    if features[9] == 1.0:
        return (0.50, 0.40, 0.10), "homograph or Punycode attack detected"

    if features[0] < danger_age:
        return (0.30, 0.60, 0.10), "very fresh domain"

    if features[1] >= 3:
        return (0.35, 0.25, 0.40), "long redirect chain"

    return (0.60, 0.30, 0.10), "default"


# Flat additive bonus constants applied on top of the weighted sub-score.
# Module-level so they can be tuned without touching calculate_risk logic.
# These are NOT normalised against the weight budget — they are independent
# signal penalties that raise the score even when mismatch/age/blacklist are low.
CLOAKING_BONUS: float = 0.35
PUNYCODE_BONUS: float = 0.30


def calculate_risk(features: np.ndarray) -> dict:
    """
    Compute a 0-100 risk score from the feature vector using dynamic weights
    plus flat additive bonuses for cloaking and Punycode attack signals.

    Returns a dict with keys: risk_score, threat_level, score_source,
    confidence_interval, weights_used, weight_reason,
    cloaking_bonus_applied, punycode_bonus_applied.
    Falls back to a zero-risk safe default on invalid input.
    Never raises.
    """
    if len(features) < 10:
        logger.error(
            "Invalid feature array length passed to formula.",
            extra={"expected": 10, "got": len(features)},
        )
        return {
            "risk_score": 0,
            "threat_level": "SAFE",
            "score_source": "formula",
            "confidence_interval": 15,
            "weights_used": {"mismatch": 0.60, "domain_age": 0.30, "blacklist": 0.10},
            "weight_reason": "default (invalid input length)",
            "cloaking_bonus_applied": False,
            "punycode_bonus_applied": False,
        }

    domain_age_days   = features[0]
    is_typosquat      = features[2]
    vpa_mismatch      = features[5]
    is_blacklisted    = features[6]
    cloaking_detected = features[8]
    punycode_detected = features[9]

    danger_age = getattr(settings, "DOMAIN_DANGER_AGE_DAYS", 7)
    safe_age   = getattr(settings, "DOMAIN_SAFE_AGE_DAYS", 730)

    # 1. Domain age factor (0.0 = safe, 1.0 = highly dangerous)
    if domain_age_days == 0:
        domain_age_factor = 0.5          # unknown age — treat as moderately suspicious
    elif domain_age_days < danger_age:
        domain_age_factor = 1.0          # fresh domain — maximum danger
    elif domain_age_days > safe_age:
        domain_age_factor = 0.0          # well-established domain
    else:
        domain_age_factor = (
            1.0 - ((domain_age_days - danger_age) / float(safe_age - danger_age))
            if safe_age > danger_age else 0.0
        )

    # 2. Boolean flags — take worst of is_typosquat vs vpa_mismatch for mismatch signal
    mismatch_flag    = float(max(is_typosquat, vpa_mismatch))
    blacklist_status = float(is_blacklisted)

    # 3. Determine dynamic weights based on dominant signal
    (w_mismatch, w_domain_age, w_blacklist), weight_reason = _calculate_dynamic_weights(features)

    # 4. Direct additive terms — NOT reweighted, flat bonuses applied on top.
    # Ensures cloaking and Punycode attacks raise risk even when
    # mismatch/age/blacklist are all low (e.g. aged, non-typosquatting,
    # not-yet-blacklisted domain used in a cloaking campaign).
    cloaking_term = CLOAKING_BONUS if cloaking_detected == 1.0 else 0.0
    punycode_term = PUNYCODE_BONUS if punycode_detected == 1.0 else 0.0

    logger.debug(
        "Dynamic weights and additive terms selected",
        extra={
            "reason": weight_reason,
            "weights": (w_mismatch, w_domain_age, w_blacklist),
            "cloaking_term": cloaking_term,
            "punycode_term": punycode_term,
        },
    )

    # 5. Weighted sub-score + additive bonuses → 0-100 integer
    raw_score = (
        (w_mismatch  * mismatch_flag)
        + (w_domain_age * domain_age_factor)
        + (w_blacklist  * blacklist_status)
        + cloaking_term
        + punycode_term
    )
    risk_score = int(raw_score * 100)
    risk_score = max(0, min(100, risk_score))

    # 6. Threat level bands
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
        "risk_score":             risk_score,
        "threat_level":           threat_level,
        "score_source":           "formula",
        "confidence_interval":    15,
        "weights_used": {
            "mismatch":   w_mismatch,
            "domain_age": w_domain_age,
            "blacklist":  w_blacklist,
        },
        "weight_reason":          weight_reason,
        "cloaking_bonus_applied": cloaking_term > 0,
        "punycode_bonus_applied": punycode_term > 0,
    }
