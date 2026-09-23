import os
import joblib
import numpy as np
import pandas as pd
import shap
from ml.src.feature_extractor import FEATURE_NAMES, FEATURE_DESCRIPTIONS

class PhishExplainer:
    def __init__(self, artifacts_dir: str = "ml/artifacts"):
        self.artifacts_dir = artifacts_dir
        self.bundle_path = os.path.join(artifacts_dir, "phishguard_ensemble.joblib")
        self.shap_bg_path = os.path.join(artifacts_dir, "shap_background.joblib")
        
        self.ensemble = None
        self.lgb_model = None
        self.tree_explainer = None
        self.background_data = None
        self._is_loaded = False

    def load(self):
        """Lazy load models and SHAP explainer."""
        if self._is_loaded:
            return

        if not os.path.exists(self.bundle_path):
            raise FileNotFoundError(f"Model artifacts not found at {self.bundle_path}. Please train the pipeline first.")

        bundle = joblib.load(self.bundle_path)
        self.ensemble = bundle["ensemble"]
        self.lgb_model = bundle["lgb"]
        self.xgb_model = bundle.get("xgb")
        self.rf_model = bundle.get("rf")
        
        # Load background data if available
        if os.path.exists(self.shap_bg_path):
            self.background_data = joblib.load(self.shap_bg_path)
            self.tree_explainer = shap.TreeExplainer(self.lgb_model, data=self.background_data)
        else:
            self.tree_explainer = shap.TreeExplainer(self.lgb_model)

        self._is_loaded = True

    def explain_url_features(self, feature_dict: dict, top_k: int = 10) -> dict:
        """
        Compute probability prediction and SHAP feature attributions for a single sample.
        """
        self.load()

        df_row = pd.DataFrame([feature_dict])[FEATURE_NAMES]
        
        # Ensemble predictions
        probabilities = self.ensemble.predict_proba(df_row)[0]
        phishing_prob = float(probabilities[1])
        legit_prob = float(probabilities[0])

        # Individual model breakdown
        lgb_prob = float(self.lgb_model.predict_proba(df_row)[0][1])
        xgb_prob = float(self.xgb_model.predict_proba(df_row)[0][1]) if self.xgb_model else lgb_prob
        rf_prob = float(self.rf_model.predict_proba(df_row)[0][1]) if self.rf_model else lgb_prob

        # SHAP attribution
        shap_raw = self.tree_explainer.shap_values(df_row)
        
        # Handle SHAP output shapes
        if isinstance(shap_raw, list):
            sv = shap_raw[1][0]
        elif len(np.shape(shap_raw)) == 2:
            sv = shap_raw[0]
        elif len(np.shape(shap_raw)) == 3:
            sv = shap_raw[0][:, 1]
        else:
            sv = shap_raw

        base_val = getattr(self.tree_explainer, "expected_value", 0.0)
        if isinstance(base_val, (list, np.ndarray)):
            base_val = float(base_val[-1])
        else:
            base_val = float(base_val)

        # Build feature attribution records
        attributions = []
        for i, name in enumerate(FEATURE_NAMES):
            val = float(df_row.iloc[0][name])
            attribution_score = float(sv[i])
            
            # Formulate intuitive security explanation
            direction = "increases_risk" if attribution_score > 0 else "decreases_risk"
            explanation = self._generate_feature_comment(name, val, attribution_score)

            attributions.append({
                "feature": name,
                "value": val,
                "shap_value": round(attribution_score, 4),
                "direction": direction,
                "importance": abs(round(attribution_score, 4)),
                "description": FEATURE_DESCRIPTIONS.get(name, ""),
                "explanation": explanation
            })

        # Sort by absolute SHAP impact
        attributions.sort(key=lambda x: x["importance"], reverse=True)

        # Risk classification level
        if phishing_prob >= 0.85:
            risk_level = "CRITICAL_PHISHING"
            status_text = "Severe Phishing Threat Detected"
            color = "rose"
        elif phishing_prob >= 0.65:
            risk_level = "HIGH_RISK"
            status_text = "Probable Phishing Campaign"
            color = "orange"
        elif phishing_prob >= 0.40:
            risk_level = "SUSPICIOUS"
            status_text = "Suspicious URL Structure"
            color = "amber"
        elif phishing_prob >= 0.20:
            risk_level = "LOW_RISK"
            status_text = "Low Risk / Likely Legitimate"
            color = "blue"
        else:
            risk_level = "SAFE"
            status_text = "Verified Benign Pattern"
            color = "emerald"

        return {
            "phishing_probability": round(phishing_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "risk_score_percent": round(phishing_prob * 100, 1),
            "risk_level": risk_level,
            "status_text": status_text,
            "color": color,
            "base_value": round(base_val, 4),
            "model_breakdown": {
                "ensemble": round(phishing_prob, 4),
                "lightgbm": round(lgb_prob, 4),
                "xgboost": round(xgb_prob, 4),
                "random_forest": round(rf_prob, 4)
            },
            "top_attributions": attributions[:top_k],
            "all_attributions": attributions
        }

    def _generate_feature_comment(self, feat: str, val: float, shap_val: float) -> str:
        """Produce human-centric security reasoning for feature impact."""
        if shap_val > 0:
            if feat == "has_ip" and val == 1:
                return "Direct IP address used as hostname, a hallmark of evasion and illicit hosting."
            elif feat == "brand_impersonation" and val == 1:
                return "Typosquatting or spoofing pattern matching high-value target brand detected."
            elif feat == "suspicious_tld" and val == 1:
                return "Domain registered under a high-abuse TLD known for malicious disposable campaigns."
            elif feat == "sensitive_keywords_count" and val > 0:
                return f"Contains {int(val)} high-risk authentication/banking keywords (e.g. login, verify, account)."
            elif feat == "tld_in_subdomain" and val == 1:
                return "Deceptive secondary domain structure mimicking authentic TLD in subdomain."
            elif feat == "url_entropy" and val > 4.2:
                return f"High Shannon entropy ({val:.2f}) indicates potential token masking or obfuscation."
            elif feat == "is_https" and val == 0:
                return "Unencrypted HTTP scheme exposes connection and is common in quick-deploy phishing."
            elif feat == "has_shortener" and val == 1:
                return "URL shortener detected, concealing final landing destination."
            elif feat == "has_punycode" and val == 1:
                return "Internationalized Domain Name (IDN) Punycode detected, vulnerable to visual homograph spoofing."
            else:
                return f"Feature value ({val}) contributed +{shap_val:.3f} toward malicious classification."
        else:
            if feat == "is_https" and val == 1:
                return "TLS/HTTPS protocol observed, consistent with established web services."
            elif feat == "brand_impersonation" and val == 0:
                return "No deceptive brand impersonation or typosquatting markers identified."
            elif feat == "suspicious_tld" and val == 0:
                return "Reputable standard top-level domain (TLD) utilized."
            elif feat == "sensitive_keywords_count" and val == 0:
                return "No high-risk credential harvesting keywords found in URL path."
            elif feat == "has_ip" and val == 0:
                return "Properly resolved domain name rather than raw IP address."
            else:
                return f"Standard pattern ({val}) supported legitimate URL classification."
