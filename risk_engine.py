"""
risk_engine.py
----------------
Combines three signals into one final phishing risk percentage:

  1. Random Forest probability   (weight 0.4)
  2. Character-CNN probability   (weight 0.4)
  3. Rule-based heuristic score  (weight 0.2)

Also returns a verdict label and the top contributing "red flag"
features (for explainability), plus a "SECURE PLATFORM" badge when
the URL is very clearly safe.
"""

import sys
import os
import joblib
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences

from feature_extraction import (
    extract_features, features_to_vector, FEATURE_ORDER,
    detect_brand_impersonation,
)

MAX_LEN = 200


def resource_path(relative_path: str) -> str:
    """Resolves a file path that works both when running as a normal
    Python script AND when bundled into a standalone .exe/.app via
    PyInstaller (which unpacks bundled files into a temp folder at
    sys._MEIPASS)."""
    base_path = getattr(sys, "_MEIPASS", os.path.abspath("."))
    return os.path.join(base_path, relative_path)


class PhishingRiskEngine:
    def __init__(self, rf_path=None, cnn_path=None, tokenizer_path=None):
        rf_path = rf_path or resource_path("rf_model.pkl")
        cnn_path = cnn_path or resource_path("char_cnn_model.keras")
        tokenizer_path = tokenizer_path or resource_path("char_tokenizer.pkl")

        self.rf = joblib.load(rf_path)
        self.cnn = tf.keras.models.load_model(cnn_path)
        self.tokenizer = joblib.load(tokenizer_path)

    def _rf_probability(self, feat_vector) -> float:
        proba = self.rf.predict_proba([feat_vector])[0]
        return float(proba[1])  # class 1 = phishing

    def _cnn_probability(self, url: str) -> float:
        seq = self.tokenizer.texts_to_sequences([url])
        padded = pad_sequences(seq, maxlen=MAX_LEN, padding="post", truncating="post")
        return float(self.cnn.predict(padded, verbose=0)[0][0])

    @staticmethod
    def _heuristic_score(feat: dict) -> float:
        red_flags = [
            feat["has_ip"], feat["has_at_symbol"], feat["is_shortened"],
            feat["suspicious_tld"], feat["prefix_suffix_hyphen"],
            feat["https_in_domain_token"], feat["many_subdomains"],
            feat["long_url"], feat["double_slash_redirect"],
            int(feat["domain_entropy"] > 3.5),
            int(feat["has_https_scheme"] == 0),
        ]
        return sum(red_flags) / len(red_flags)

    def _top_reasons(self, feat: dict, n=3):
        importances = self.rf.feature_importances_
        contrib = []
        for name, imp in zip(FEATURE_ORDER, importances):
            val = feat[name]
            if val:  # only "active" red-flag features
                contrib.append((name, imp * (val if isinstance(val, (int, float)) else 1)))
        contrib.sort(key=lambda x: x[1], reverse=True)
        return [c[0] for c in contrib[:n]]

    def analyze(self, url: str) -> dict:
        feat = extract_features(url)
        vector = features_to_vector(feat)

        rf_prob = self._rf_probability(vector)
        cnn_prob = self._cnn_probability(url)
        heuristic = self._heuristic_score(feat)

        final_score = 0.4 * rf_prob + 0.4 * cnn_prob + 0.2 * heuristic
        risk_percentage = round(final_score * 100, 2)

        # --- Hard override: brand impersonation (e.g. instagram.login.com) ---
        # This is checked independently of the ML models. HTTPS, a clean
        # RF score, or a clean CNN score cannot override this — mimicking
        # a real brand's name on a domain that brand does not own is
        # treated as a confirmed red flag, not a probability.
        impersonation = detect_brand_impersonation(url)
        impersonation_note = None
        if impersonation:
            brand, registered_domain = impersonation
            risk_percentage = max(risk_percentage, 92.0)
            impersonation_note = (
                f"This link uses '{brand}' in its address, but the actual "
                f"website you would land on is '{registered_domain}' — not "
                f"the real {brand}.com. Attackers do this because HTTPS "
                f"only encrypts the connection; it never confirms who "
                f"actually owns the domain."
            )

        if impersonation:
            verdict = "HIGH RISK / LIKELY PHISHING"
        elif (risk_percentage < 15 and feat["has_https_scheme"]
                and not feat["has_ip"] and not feat["is_shortened"]):
            verdict = "SECURE PLATFORM"
        elif risk_percentage < 30:
            verdict = "LOW RISK"
        elif risk_percentage < 60:
            verdict = "SUSPICIOUS"
        else:
            verdict = "HIGH RISK / LIKELY PHISHING"

        return {
            "url": url,
            "risk_percentage": risk_percentage,
            "verdict": verdict,
            "rf_probability": round(rf_prob * 100, 2),
            "cnn_probability": round(cnn_prob * 100, 2),
            "heuristic_score": round(heuristic * 100, 2),
            "top_reasons": self._top_reasons(feat),
            "features": feat,
            "impersonation_note": impersonation_note,
        }
