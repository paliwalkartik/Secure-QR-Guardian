"""
Risk classifier. Uses sklearn model if available, falls back to formula.py.
Import risk_classifier instance. Do not instantiate RiskClassifier directly.
"""

import os
import joblib
import numpy as np

from core.risk import formula
from utils.logger import get_logger

logger = get_logger(__name__)

class RiskClassifier:
    def __init__(self):
        self.model = None
        
        # Path to the serialized model
        model_path = os.path.join(
            os.path.dirname(__file__), 
            'models', 
            'risk_classifier.pkl'
        )
        
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
                logger.info("Successfully loaded ML risk classifier model.")
            except Exception as e:
                logger.warning(f"Failed to load classifier model from {model_path}: {e}")
        else:
            logger.warning(f"Classifier model file not found at {model_path}. Will fall back to formula.")
            
    def _calculate_ci(self, proba: np.ndarray) -> int:
        """
        Calculates confidence interval margin.
        Narrower for decisive predictions, wider for uncertain ones.
        """
        diff = abs(proba[1] - proba[0])
        ci = int((1 - diff) * 20)
        
        # Clamp between 2 and 18
        if ci < 2:
            return 2
        if ci > 18:
            return 18
        return ci

    def predict(self, features: np.ndarray) -> dict:
        if self.model is None:
            result = formula.calculate_risk(features)
        else:
            try:
                proba = self.model.predict_proba([features])[0]

                risk_score = int(proba[1] * 100)
                risk_score = max(0, min(100, risk_score))

                confidence_interval = self._calculate_ci(proba)

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

                result = {
                    "risk_score": risk_score,
                    "confidence_interval": confidence_interval,
                    "threat_level": threat_level,
                    "score_source": "classifier",
                }
            except Exception as e:
                logger.error(f"Error during ML prediction: {e}. Falling back to formula.")
                result = formula.calculate_risk(features)

        # ── Injection-in-URL floor override — applies regardless of which
        # scoring path produced `result`. An embedded prompt-injection payload
        # in a URL is near-unambiguous evidence of malicious intent; do not
        # rely solely on the ML model having learned this from synthetic
        # training data.
        if len(features) > 10 and features[10] == 1.0:
            if result.get("risk_score", 0) < 90:
                result["risk_score"] = 90
                result["threat_level"] = "CRITICAL"
            result["injection_override_applied"] = True
        else:
            result.setdefault("injection_override_applied", False)

        return result

# Export a single module-level instance
risk_classifier = RiskClassifier()
