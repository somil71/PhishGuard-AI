import os
import sys
import argparse
import subprocess
import time
import webbrowser
import uvicorn

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "ml", "artifacts")
REQUIRED_ARTIFACT = os.path.join(ARTIFACTS_DIR, "phishguard_ensemble.joblib")
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")
FRONTEND_DIST = os.path.join(FRONTEND_DIR, "dist")


def ensure_model_trained():
    """Ensure ML model artifacts exist, otherwise trigger pipeline training."""
    if not os.path.exists(REQUIRED_ARTIFACT):
        print("[*] Model artifacts not found. Starting training pipeline...")
        from ml.src.trainer import train_phishguard_pipeline
        train_phishguard_pipeline()
    else:
        print("[+] ML Ensemble artifacts verified.")


def ensure_frontend_built():
    """Build frontend dist if not already built."""
    if not os.path.exists(FRONTEND_DIST) and os.path.exists(FRONTEND_DIR):
        print("[*] Building frontend for production deployment...")
        try:
            subprocess.run("npm run build", cwd=FRONTEND_DIR, shell=True, check=True)
            print("[+] Frontend build completed successfully.")
        except Exception as e:
            print(f"[!] Warning: Frontend build failed ({e}). Backend will run API endpoints.")


def run_tests():
    """Run verification checks on feature extraction and inference."""
    print("=" * 60)
    print("Running PhishGuard-AI Verification Tests...")
    print("=" * 60)
    
    from backend.app.services.predictor import predict_and_explain
    
    test_cases = [
        ("http://paypa1-security-verification.xyz/login.php", "CRITICAL_PHISHING"),
        ("http://appleid.apple.com.verify-account-security.cfd/signin", "CRITICAL_PHISHING"),
        ("http://192.168.1.105:8080/secure/login", "CRITICAL_PHISHING"),
        ("https://en.wikipedia.org/wiki/Phishing", "SAFE"),
        ("https://github.com/torvalds/linux", "SAFE"),
    ]
    
    passed = 0
    for url, expected in test_cases:
        res = predict_and_explain(url)
        level = res["risk_level"]
        ok = (level == expected) or (expected == "CRITICAL_PHISHING" and level in ["CRITICAL_PHISHING", "HIGH_RISK"])
        status = "PASS" if ok else "WARN"
        if ok:
            passed += 1
        print(f"[{status}] URL: {url[:55]:<55} | Score: {res['risk_score']:>5.1f}% | Verdict: {level}")

    print("-" * 60)
    print(f"Test Suite Summary: {passed}/{len(test_cases)} test cases passed.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="PhishGuard-AI Master Server")
    parser.add_argument("--train", action="store_true", help="Force retrain ML pipeline")
    parser.add_argument("--test", action="store_true", help="Run verification tests and exit")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch browser")
    parser.add_argument("--reload", action="store_true", help="Enable uvicorn hot reloading")
    
    args = parser.parse_args()

    if args.train:
        print("[*] Retraining PhishGuard ML Pipeline...")
        from ml.src.trainer import train_phishguard_pipeline
        train_phishguard_pipeline()
        return

    ensure_model_trained()

    if args.test:
        run_tests()
        return

    ensure_frontend_built()

    server_url = f"http://{args.host}:{args.port}"
    print("\n" + "=" * 65)
    print("   PhishGuard-AI: Intelligent Phishing URL Detection & XAI")
    print("=" * 65)
    print(f"[*] Core Web & API Server starting on: {server_url}")
    print(f"[*] Interactive API Documentation:     {server_url}/docs")
    print(f"[*] Health Check Endpoint:             {server_url}/api/health")
    print("=" * 65 + "\n")

    if not args.no_browser:
        def open_browser():
            time.sleep(1.2)
            try:
                webbrowser.open(server_url)
            except Exception:
                pass
        
        import threading
        threading.Thread(target=open_browser, daemon=True).start()

    from backend.app.main import app
    uvicorn.run("backend.app.main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
