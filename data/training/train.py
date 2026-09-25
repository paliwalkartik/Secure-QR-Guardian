"""
Synthetic data generator and trainer for the risk classifier.
Generates labelled samples covering all 10 features and trains a LogisticRegression model.
Does NOT connect to any external network. Writes output only to core/risk/models/.
Run directly: python data/training/train.py
"""

import os
import sys
import numpy as np
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# Ensure project root is importable when running this script directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from core.risk.feature_extractor import FEATURE_NAMES


def generate_synthetic_data(n_samples: int = 300):
    """
    Build a labelled synthetic dataset covering all 10 features.

    Feature index mapping (must stay in sync with FEATURE_NAMES):
      0: domain_age_days
      1: redirect_count
      2: is_typosquat
      3: is_known_bulletproof_asn
      4: ssl_age_days
      5: vpa_mismatch
      6: is_blacklisted
      7: typosquat_distance
      8: cloaking_detected       (SEC-4)
      9: punycode_detected       (SEC-5) <- NEW

    Fraud prior:  ~30% cloaking=1, ~10% punycode=1.
    Legit prior:  cloaking=0 and punycode=0 always.

    Returns X (float ndarray shape [n_samples, 10]), y (int ndarray shape [n_samples]).
    """
    assert len(FEATURE_NAMES) == 10, (
        f"FEATURE_NAMES length mismatch: expected 10, got {len(FEATURE_NAMES)}. "
        "Re-sync train.py with feature_extractor.py."
    )

    np.random.seed(42)
    X = []
    y = []

    n_fraud = int(n_samples * 0.4)
    n_legit = n_samples - n_fraud

    # ── Legit samples (label = 0) ──────────────────────────────────────────────
    for _ in range(n_legit):
        domain_age     = np.random.randint(730, 3650)   # established domains
        redirect_count = np.random.randint(0, 2)
        is_typo        = 0
        bulletproof    = 0
        ssl_age        = np.random.randint(30, 365)
        vpa_mismatch   = 0
        blacklisted    = 0
        typo_dist      = 0
        cloaking  = 0   # legit sites never cloak
        punycode  = 0   # legit UPI domains never use IDN

        X.append([domain_age, redirect_count, is_typo, bulletproof,
                  ssl_age, vpa_mismatch, blacklisted, typo_dist, cloaking, punycode])
        y.append(0)

    # ── Fraud samples (label = 1) ──────────────────────────────────────────────
    for _ in range(n_fraud):
        domain_age     = np.random.randint(0, 10)        # fresh domains
        redirect_count = np.random.randint(0, 5)

        # At least one major structural red flag per sample
        if np.random.rand() > 0.5:
            is_typo      = 1
            vpa_mismatch = 0
            typo_dist    = np.random.randint(1, 3)
        else:
            is_typo      = 0
            vpa_mismatch = 1
            typo_dist    = 0

        bulletproof = np.random.choice([0, 1], p=[0.7, 0.3])
        ssl_age     = np.random.randint(0, 10)
        blacklisted = np.random.choice([0, 1], p=[0.8, 0.2])
        # ~30% of fraud samples use conditional-redirect cloaking
        cloaking    = np.random.choice([0, 1], p=[0.7, 0.3])
        # ~10% of fraud samples use Punycode homograph attacks
        punycode    = np.random.choice([0, 1], p=[0.9, 0.1])

        X.append([domain_age, redirect_count, is_typo, bulletproof,
                  ssl_age, vpa_mismatch, blacklisted, typo_dist, cloaking, punycode])
        y.append(1)

    return np.array(X, dtype=float), np.array(y, dtype=int)


def main() -> None:
    """Train and persist the risk classifier with 10 features."""
    X, y = generate_synthetic_data(300)

    assert X.shape[1] == 10, f"Feature vector width mismatch: expected 10, got {X.shape[1]}"

    # 80 / 20 train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = LogisticRegression(class_weight="balanced", random_state=42, max_iter=1000)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    print("\n--- Classification Report -----------------------------------")
    print(classification_report(y_test, y_pred, target_names=["legit", "fraud"]))
    print(f"Features ({len(FEATURE_NAMES)}): {FEATURE_NAMES}")
    print(f"Accuracy: {acc:.2f}")

    models_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..', 'core', 'risk', 'models')
    )
    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, 'risk_classifier.pkl')
    joblib.dump(model, model_path)
    print(f"Model saved -> {model_path}")


if __name__ == "__main__":
    main()
