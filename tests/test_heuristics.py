import pytest
from ml.src.feature_extractor import extract_features
from backend.app.services.heuristics import evaluate_heuristics


class TestSecurityHeuristics:
    def test_ip_heuristic_detected(self):
        f = extract_features("http://192.168.1.1/admin")
        h = evaluate_heuristics(f, "http://192.168.1.1/admin")
        ip_check = next(item for item in h if item["id"] == "ip_host")
        assert ip_check["detected"] is True
        assert ip_check["severity"] == "critical"

    def test_suspicious_tld_heuristic(self):
        f = extract_features("http://phish-secure.xyz")
        h = evaluate_heuristics(f, "http://phish-secure.xyz")
        tld_check = next(item for item in h if item["id"] == "suspicious_tld")
        assert tld_check["detected"] is True

    def test_insecure_transport_heuristic(self):
        f = extract_features("http://example.com")
        h = evaluate_heuristics(f, "http://example.com")
        ssl_check = next(item for item in h if item["id"] == "transport_security")
        assert ssl_check["detected"] is True  # Detected lack of HTTPS

    def test_secure_transport_clean(self):
        f = extract_features("https://example.com")
        h = evaluate_heuristics(f, "https://example.com")
        ssl_check = next(item for item in h if item["id"] == "transport_security")
        assert ssl_check["detected"] is False

    def test_sensitive_keywords_heuristic(self):
        f = extract_features("http://test.com/login/verify/update")
        h = evaluate_heuristics(f, "http://test.com/login/verify/update")
        kw_check = next(item for item in h if item["id"] == "sensitive_keywords")
        assert kw_check["detected"] is True
        assert kw_check["severity"] == "critical"

    def test_url_shortener_heuristic(self):
        f = extract_features("http://bit.ly/3x8AbCd")
        h = evaluate_heuristics(f, "http://bit.ly/3x8AbCd")
        short_check = next(item for item in h if item["id"] == "url_shortener")
        assert short_check["detected"] is True
