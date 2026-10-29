import urllib.request
import csv
import json
import time
from backend.app.services.predictor import predict_and_explain

def run_real_world_test():
    print("=================================================================")
    print("       PHISHGUARD-AI REAL-WORLD THREAT INTELLIGENCE TEST        ")
    print("=================================================================\n")

    # 1. Fetch fresh live phishing URLs from OpenPhish
    print("[*] Fetching live active zero-day phishing feeds from OpenPhish...")
    live_phish = []
    try:
        req = urllib.request.Request("https://openphish.com/feed.txt", headers={"User-Agent": "Mozilla/5.0 PhishGuard-Test"})
        with urllib.request.urlopen(req, timeout=12) as r:
            lines = r.read().decode("utf-8", errors="ignore").splitlines()
            live_phish = [line.strip() for line in lines if line.strip()][:50]
        print(f"[+] Retrieved {len(live_phish)} live phishing URLs from OpenPhish feed.")
    except Exception as e:
        print(f"[-] OpenPhish error: {e}")

    # 2. Fetch fresh live phishing URLs from PhishTank
    print("[*] Fetching live verified phishing feeds from PhishTank...")
    phishtank_live = []
    try:
        req = urllib.request.Request("http://data.phishtank.com/data/online-valid.csv", headers={"User-Agent": "phishtank/PhishGuard-Live-Test"})
        with urllib.request.urlopen(req, timeout=15) as r:
            lines = [r.readline().decode("utf-8", errors="ignore") for _ in range(60)]
        reader = csv.DictReader(lines)
        phishtank_live = [row["url"] for row in reader if "url" in row and row["url"]][:30]
        print(f"[+] Retrieved {len(phishtank_live)} live phishing URLs from PhishTank.")
    except Exception as e:
        print(f"[-] PhishTank error: {e}")

    all_real_phish = list(dict.fromkeys(live_phish + phishtank_live))[:50]

    # 3. Real-world benign live URLs (search engines, news, social, repos, docs, banks, ecommerce)
    real_legit_urls = [
        "https://www.google.com/search?q=machine+learning+cybersecurity",
        "https://github.com/torvalds/linux/blob/master/README.md",
        "https://en.wikipedia.org/wiki/Zero-day_vulnerability",
        "https://www.nytimes.com/section/technology",
        "https://stackoverflow.com/questions/tagged/python",
        "https://aws.amazon.com/ec2/pricing/on-demand/",
        "https://docs.python.org/3/library/asyncio.html",
        "https://www.microsoft.com/en-us/security/business",
        "https://stripe.com/docs/api/charges/create",
        "https://www.reddit.com/r/netsec/top/?t=month",
        "https://news.ycombinator.com/news",
        "https://www.apple.com/macos/sequoia/",
        "https://netflix.com/browse",
        "https://chase.com/personal/banking",
        "https://spotify.com/us/premium/",
        "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
        "https://store.steampowered.com/specials",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        "https://arxiv.org/abs/2303.08774",
        "https://hub.docker.com/_/python",
        "https://www.bbc.com/news/technology",
        "https://www.linkedin.com/jobs/search/?keywords=software%20engineer",
        "https://pypi.org/project/fastapi/",
        "https://crates.io/crates/tokio",
        "https://fastapi.tiangolo.com/tutorial/bigger-applications/",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://medium.com/tag/machine-learning",
        "https://react.dev/reference/react/useState",
        "https://www.target.com/c/electronics/-/N-5xtg6",
        "https://www.walmart.com/browse/electronics/3944"
    ]

    print(f"\n[*] Evaluating on {len(all_real_phish)} live active PHISHING URLs...")
    phish_results = []
    for u in all_real_phish:
        t0 = time.time()
        res = predict_and_explain(u, include_shap=True)
        t_el = (time.time() - t0) * 1000
        phish_results.append((u, res, t_el))

    phish_detected = sum(1 for _, r, _ in phish_results if r["is_phishing"] or r["risk_score"] >= 50.0)
    print(f"\n>>> LIVE PHISHING DETECTION RATE: {phish_detected}/{len(all_real_phish)} ({phish_detected/len(all_real_phish)*100:.1f}%)")

    print("\n--- Sample Live Phishing Detections ---")
    for u, res, ms in phish_results[:8]:
        top_feature = res["top_shap_attributions"][0]["feature"] if res["top_shap_attributions"] else "N/A"
        heuristics_fired = len(res["heuristics"])
        brand_flag = res["brand_analysis"]["is_spoofed"]
        print(f"[{res['risk_level']:<17}] Score: {res['risk_score']:>5.1f}% | Latency: {ms:>4.1f}ms | Top SHAP: {top_feature:<18} | Spoof: {str(brand_flag):<5} | URL: {u[:65]}")

    print(f"\n[*] Evaluating on {len(real_legit_urls)} live LEGITIMATE URLs...")
    legit_results = []
    for u in real_legit_urls:
        t0 = time.time()
        res = predict_and_explain(u, include_shap=True)
        t_el = (time.time() - t0) * 1000
        legit_results.append((u, res, t_el))

    legit_safe = sum(1 for _, r, _ in legit_results if not r["is_phishing"] and r["risk_score"] < 50.0)
    print(f"\n>>> LIVE BENIGN RECOGNITION RATE: {legit_safe}/{len(real_legit_urls)} ({legit_safe/len(real_legit_urls)*100:.1f}%)")

    print("\n--- Sample Live Legitimate Detections ---")
    for u, res, ms in legit_results[:8]:
        top_feature = res["top_shap_attributions"][0]["feature"] if res["top_shap_attributions"] else "N/A"
        print(f"[{res['risk_level']:<17}] Score: {res['risk_score']:>5.1f}% | Latency: {ms:>4.1f}ms | Top SHAP: {top_feature:<18} | URL: {u[:65]}")

    # Inspect any misses
    phish_misses = [(u, r) for u, r, _ in phish_results if not r["is_phishing"] and r["risk_score"] < 50.0]
    if phish_misses:
        print(f"\n[!] Phishing False Negatives ({len(phish_misses)}):")
        for u, r in phish_misses[:5]:
            print(f"    - URL: {u}")
            print(f"      Risk: {r['risk_score']}%, Level: {r['risk_level']}, Models: {r['model_breakdown']}")

    legit_false_positives = [(u, r) for u, r, _ in legit_results if r["is_phishing"] or r["risk_score"] >= 50.0]
    if legit_false_positives:
        print(f"\n[!] Legitimate False Positives ({len(legit_false_positives)}):")
        for u, r in legit_false_positives[:5]:
            print(f"    - URL: {u}")
            print(f"      Risk: {r['risk_score']}%, Level: {r['risk_level']}, Models: {r['model_breakdown']}")

if __name__ == "__main__":
    run_real_world_test()
