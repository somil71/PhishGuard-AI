import pytest
import math
from ml.src.feature_extractor import (
    extract_features, calculate_entropy, levenshtein_distance,
    is_ip_address, FEATURE_NAMES, SUSPICIOUS_TLDS, SHORTENER_DOMAINS
)


class TestFeatureExtractor:
    def test_extract_features_keys(self):
        url = "https://example.com/test"
        features = extract_features(url)
        assert len(features) == len(FEATURE_NAMES)
        for name in FEATURE_NAMES:
            assert name in features

    def test_entropy_calculation(self):
        assert calculate_entropy("") == 0.0
        assert calculate_entropy("aaaa") == 0.0
        # High entropy string
        h = calculate_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
        assert h > 4.5

    def test_levenshtein_distance(self):
        assert levenshtein_distance("paypal", "paypal") == 0
        assert levenshtein_distance("paypal", "paypa1") == 1
        assert levenshtein_distance("apple", "appl") == 1
        assert levenshtein_distance("google", "microsoft") > 4

    def test_ip_address_detection(self):
        assert is_ip_address("192.168.1.1") == 1
        assert is_ip_address("10.0.0.1:8080") == 1
        assert is_ip_address("google.com") == 0
        assert is_ip_address("example.org:443") == 0
        assert is_ip_address("0x7f000001") == 1

    def test_https_detection(self):
        f_https = extract_features("https://secure.example.com")
        f_http = extract_features("http://insecure.example.com")
        assert f_https["is_https"] == 1
        assert f_http["is_https"] == 0

    def test_tld_in_subdomain(self):
        f = extract_features("http://paypal.com.account-update.xyz/login")
        assert f["tld_in_subdomain"] == 1

    def test_punycode_detection(self):
        f = extract_features("http://xn--appl-35a.com/login")
        assert f["has_punycode"] == 1

    def test_shortener_detection(self):
        f = extract_features("http://bit.ly/3x8AbCd")
        assert f["has_shortener"] == 1

    def test_sensitive_keywords_count(self):
        f = extract_features("http://example.com/login/verify/update/banking")
        assert f["sensitive_keywords_count"] >= 4

    def test_suspicious_tld(self):
        f = extract_features("http://malicious-tracker.xyz")
        assert f["suspicious_tld"] == 1
        f_clean = extract_features("https://github.com")
        assert f_clean["suspicious_tld"] == 0

    def test_delimiters_counts(self):
        url = "http://test.com/a/b?x=1&y=2@attacker"
        f = extract_features(url)
        assert f["num_dots"] == 1
        assert f["num_slashes"] == 4
        assert f["num_question_marks"] == 1
        assert f["num_equals"] == 2
        assert f["num_ampersands"] == 1
        assert f["num_at_symbols"] == 1
