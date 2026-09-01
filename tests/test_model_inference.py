import pytest
from backend.app.services.predictor import predict_and_explain, get_explainer


class TestModelInference:
    def test_explainer_singleton_loading(self):
        explainer = get_explainer()
        assert explainer._is_loaded is True
        assert explainer.ensemble is not None
        assert explainer.lgb_model is not None

    def test_phishing_detection_high_confidence(self):
        phish_url = "http://paypa1-security-verification.xyz/login.php?user=victim"
        res = predict_and_explain(phish_url)
        assert res["is_phishing"] is True
        assert res["risk_score"] > 80.0
        assert res["risk_level"] in ["CRITICAL_PHISHING", "HIGH_RISK"]
        assert "Paypal" in res["brand_analysis"]["assessment"] or res["brand_analysis"]["is_spoofed"] is True
        assert len(res["top_shap_attributions"]) > 0

    def test_legitimate_detection_low_confidence(self):
        legit_url = "https://en.wikipedia.org/wiki/Phishing"
        res = predict_and_explain(legit_url)
        assert res["is_phishing"] is False
        assert res["risk_score"] < 25.0
        assert res["risk_level"] in ["SAFE", "LOW_RISK"]

    def test_model_breakdown_consistency(self):
        res = predict_and_explain("https://github.com/torvalds/linux")
        mb = res["model_breakdown"]
        assert "ensemble" in mb
        assert "lightgbm" in mb
        assert "xgboost" in mb
        assert "random_forest" in mb
        for val in mb.values():
            assert 0.0 <= val <= 1.0

    def test_shap_attribution_properties(self):
        res = predict_and_explain("http://192.168.1.105:8080/secure/login")
        top_shap = res["top_shap_attributions"]
        assert len(top_shap) <= 10
        for attr in top_shap:
            assert "feature" in attr
            assert "shap_value" in attr
            assert "direction" in attr
            assert "explanation" in attr
