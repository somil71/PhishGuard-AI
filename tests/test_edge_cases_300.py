import pytest
import math
from ml.src.feature_extractor import extract_features, FEATURE_NAMES
from backend.app.services.predictor import predict_and_explain

# -------------------------------------------------------------
# 1. Obfuscated & Unusual IP Vectors (50 test cases)
# -------------------------------------------------------------
IP_EDGE_CASES = [
    f"http://192.168.{i}.{i+1}:8080/secure/login" for i in range(1, 26)
] + [
    f"http://10.0.{i}.{i+5}:3000/auth/checkpoint" for i in range(1, 26)
]

# -------------------------------------------------------------
# 2. IDN Homograph & Punycode Vectors (50 test cases)
# -------------------------------------------------------------
PUNYCODE_EDGE_CASES = [
    f"http://xn--appl-{i}a.com/account/security" for i in range(10, 35)
] + [
    f"http://xn--paypa-{i}b.xyz/verify/wallet" for i in range(10, 35)
]

# -------------------------------------------------------------
# 3. Deceptive Subdomain Masquerading Vectors (50 test cases)
# -------------------------------------------------------------
SUBDOMAIN_EDGE_CASES = [
    f"http://paypal.com.sub{i}.account-verification-alert.xyz/signin.php" for i in range(1, 26)
] + [
    f"http://appleid.apple.com.node{i}.security-update-center.cfd/auth" for i in range(1, 26)
]

# -------------------------------------------------------------
# 4. Open Redirect, Double Slash & Parameter Injection (50 test cases)
# -------------------------------------------------------------
REDIRECT_AND_INJECTION_EDGE_CASES = [
    f"https://google.com/url?q=http://malicious-harvest-{i}.xyz/login" for i in range(1, 26)
] + [
    f"http://attacker-host-{i}.top//redirect/paypal//verify?token={hex(i*1000)}" for i in range(1, 26)
]

# -------------------------------------------------------------
# 5. Typosquatting Brand Variants (50 test cases)
# -------------------------------------------------------------
TYPOSQUAT_EDGE_CASES = [
    f"http://paypa1-security-{i}.xyz/login.php" for i in range(1, 11)
] + [
    f"http://micros0ft-support-center-{i}.top/verify" for i in range(1, 11)
] + [
    f"http://netflx-billing-update-{i}.buzz/session" for i in range(1, 11)
] + [
    f"http://amaz0n-prime-renewal-{i}.click/account" for i in range(1, 11)
] + [
    f"http://chas0nline-banking-{i}.cam/auth" for i in range(1, 11)
]

# -------------------------------------------------------------
# 6. Abusive TLD & Credential Keyword Combos (40 test cases)
# -------------------------------------------------------------
ABUSE_TLD_EDGE_CASES = [
    f"http://secure-banking-verification-notice-{i}.xyz/login.aspx" for i in range(1, 11)
] + [
    f"http://account-suspended-recover-id{i}.top/unlock.php" for i in range(1, 11)
] + [
    f"http://crypto-wallet-connect-resolver-{i}.buzz/import" for i in range(1, 11)
] + [
    f"http://invoice-payment-review-portal-{i}.sbs/download" for i in range(1, 11)
]

# -------------------------------------------------------------
# 7. Complex Legitimate URLs (40 test cases)
# -------------------------------------------------------------
LEGIT_COMPLEX_EDGE_CASES = [
    f"https://github.com/torvalds/linux/commit/{'a'*i}{'b'*(40-i)}" for i in range(1, 11)
] + [
    f"https://en.wikipedia.org/wiki/Machine_learning#Section_{i}_Algorithms" for i in range(1, 11)
] + [
    f"https://aws.amazon.com/s3/pricing/?nc1=h_ls&region=us-east-{i}" for i in range(1, 11)
] + [
    f"https://docs.python.org/3/library/urllib.parse.html?highlight=urlparse#ref-{i}" for i in range(1, 11)
]

# Aggregated 330 Edge Cases
ALL_EDGE_CASES = (
    [(url, "PHISHING") for url in IP_EDGE_CASES] +
    [(url, "PHISHING") for url in PUNYCODE_EDGE_CASES] +
    [(url, "PHISHING") for url in SUBDOMAIN_EDGE_CASES] +
    [(url, "PHISHING") for url in REDIRECT_AND_INJECTION_EDGE_CASES] +
    [(url, "PHISHING") for url in TYPOSQUAT_EDGE_CASES] +
    [(url, "PHISHING") for url in ABUSE_TLD_EDGE_CASES] +
    [(url, "LEGIT") for url in LEGIT_COMPLEX_EDGE_CASES]
)


class TestEdgeCases300:
    @pytest.mark.parametrize("url,expected_type", ALL_EDGE_CASES)
    def test_individual_edge_case(self, url, expected_type):
        """
        Test each of the 330 edge cases:
        - Feature extraction must succeed with all 34 features
        - All feature values must be finite numbers
        - Predictor inference must execute cleanly without NaN or exceptions
        - Classification should conform to expected bounds
        """
        features = extract_features(url)
        assert len(features) == len(FEATURE_NAMES)
        
        # Verify no NaN or infinite values
        for k, v in features.items():
            assert not math.isnan(v), f"Feature {k} returned NaN for URL: {url}"
            assert not math.isinf(v), f"Feature {k} returned Inf for URL: {url}"

        # Inference verification
        result = predict_and_explain(url, include_shap=False)
        assert "risk_score" in result
        assert 0.0 <= result["risk_score"] <= 100.0
        assert "risk_level" in result
        assert "heuristics" in result
        assert "brand_analysis" in result

        if expected_type == "PHISHING":
            # Phishing attacks should register as elevated threat
            assert result["risk_score"] >= 35.0, (
                f"Phishing edge case false negative on {url}: score was {result['risk_score']}"
            )
        else:
            # Legitimate edge cases should remain low risk
            assert result["risk_score"] <= 45.0, (
                f"Legitimate edge case false positive on {url}: score was {result['risk_score']}"
            )
