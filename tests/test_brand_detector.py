import pytest
from backend.app.services.brand_detector import analyze_brand_spoofing


class TestBrandDetector:
    def test_legitimate_brand_domain(self):
        res = analyze_brand_spoofing("https://www.paypal.com/signin")
        assert res["target_brand"] == "Paypal"
        assert res["is_spoofed"] is False
        assert res["technique"] == "legitimate_domain"

    def test_subdomain_spoofing(self):
        res = analyze_brand_spoofing("http://paypal.com.account-update.xyz/login.php")
        assert res["target_brand"] == "Paypal"
        assert res["is_spoofed"] is True
        assert res["technique"] == "subdomain_spoofing"

    def test_typosquatting(self):
        res = analyze_brand_spoofing("http://paypa1-security.buzz/verify")
        assert res["target_brand"] == "Paypal"
        assert res["is_spoofed"] is True

    def test_apple_typosquatting(self):
        res = analyze_brand_spoofing("http://app1e-login.cfd/auth")
        assert res["is_spoofed"] is True

    def test_brand_in_path_under_foreign_domain(self):
        res = analyze_brand_spoofing("http://unrelated-domain.com/paypal/login")
        assert res["target_brand"] == "Paypal"
        assert res["is_spoofed"] is True
        assert res["technique"] == "path_credential_harvest"

    def test_clean_neutral_domain(self):
        res = analyze_brand_spoofing("https://en.wikipedia.org/wiki/Machine_learning")
        assert res["is_spoofed"] is False
        assert res["technique"] == "none"
