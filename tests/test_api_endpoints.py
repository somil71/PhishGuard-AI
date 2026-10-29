import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


class TestAPIEndpoints:
    def test_health_endpoint(self):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "online"
        assert data["model_loaded"] is True
        assert "version" in data

    def test_samples_endpoint(self):
        response = client.get("/api/samples")
        assert response.status_code == 200
        data = response.json()
        assert "samples" in data
        assert len(data["samples"]) >= 5

    def test_metrics_endpoint(self):
        response = client.get("/api/metrics")
        assert response.status_code == 200
        data = response.json()
        assert "primary_metrics" in data
        assert data["primary_metrics"]["accuracy"] > 0.90
        assert "model_comparison" in data
        assert "global_importance" in data

    def test_features_metadata_endpoint(self):
        response = client.get("/api/features")
        assert response.status_code == 200
        data = response.json()
        assert "features" in data
        assert "descriptions" in data
        assert len(data["features"]) == 34

    def test_analyze_valid_phishing_url(self):
        payload = {
            "url": "http://paypa1-security-verification.xyz/login.php",
            "include_shap": True
        }
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["is_phishing"] is True
        assert data["risk_score"] > 70.0
        assert len(data["top_shap_attributions"]) > 0

    def test_analyze_valid_legit_url(self):
        payload = {
            "url": "https://www.google.com/search?q=machine+learning",
            "include_shap": True
        }
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["is_phishing"] is False
        assert data["risk_score"] < 40.0

    def test_analyze_empty_url_error(self):
        payload = {"url": "   ", "include_shap": True}
        response = client.post("/api/analyze", json=payload)
        assert response.status_code == 400

    def test_batch_analyze_endpoint(self):
        payload = {
            "urls": [
                "http://paypa1-security-verification.xyz/login.php",
                "https://github.com/torvalds/linux",
                "http://appleid.apple.com.verify-account-security.cfd/signin",
                "https://en.wikipedia.org/wiki/Phishing"
            ]
        }
        response = client.post("/api/batch-analyze", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert "results" in data
        assert len(data["results"]) == 4
        summary = data["summary"]
        assert summary["total_scanned"] == 4
        assert summary["phishing_count"] >= 2
        assert summary["safe_count"] >= 2

    def test_batch_empty_list_error(self):
        payload = {"urls": []}
        response = client.post("/api/batch-analyze", json=payload)
        assert response.status_code == 400
