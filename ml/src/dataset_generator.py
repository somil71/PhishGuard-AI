import os
import random
import csv
import io
import urllib.request
import pandas as pd
from ml.src.feature_extractor import extract_features, FEATURE_NAMES

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# Benchmark legitimate domains
LEGIT_DOMAINS = [
    "google.com", "youtube.com", "amazon.com", "wikipedia.org", "facebook.com",
    "twitter.com", "instagram.com", "linkedin.com", "github.com", "microsoft.com",
    "apple.com", "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "nytimes.com", "cnn.com", "bbc.co.uk", "reuters.com", "bloomberg.com",
    "stackoverflow.com", "reddit.com", "medium.com", "quora.com", "spotify.com",
    "dropbox.com", "salesforce.com", "cloudflare.com", "adobe.com", "ebay.com",
    "walmart.com", "target.com", "etsy.com", "zoom.us", "slack.com",
    "paypal.com", "stripe.com", "shopify.com", "wordpress.org", "mozilla.org",
    "nih.gov", "cdc.gov", "harvard.edu", "mit.edu", "stanford.edu",
    "python.org", "rust-lang.org", "golang.org", "developer.mozilla.org", "w3schools.com"
]

# Comprehensive real-world legitimate paths (short, medium, deep, query-rich, code commits, documentation)
RICH_LEGIT_PATHS = [
    "", "/",
    "/about", "/contact", "/products", "/services", "/help", "/documentation",
    "/blog/2026/03/update-notes", "/news/technology/ai-advancements-overview",
    "/item/view?id=49201&category=electronics&sort=price_asc",
    "/search?q=machine+learning+tutorial+for+beginners&source=web",
    "/profile/settings/notifications?view=security&format=json",
    "/docs/api/v2/reference/authentication-guide.html",
    "/support/knowledge-base/article-102-troubleshooting-network",
    "/community/forum/topic/8812-how-to-configure-docker-container",
    "/download/releases/latest/package-x86_64-linux-gnu.tar.gz",
    "/explore/trending/topics/open-source-software",
    "/courses/computer-science-intro/lecture-notes-week-4",
    "/cart/checkout/summary?order_id=987123&payment_method=card",
    "/events/annual-summit-2026/speakers/keynote-schedule",
    "/catalog/books/science-fiction/bestsellers-2026",
    "/investor-relations/quarterly-earnings/q3-report.pdf",
    "/wiki/Phishing", "/wiki/Machine_learning", "/wiki/Deep_learning",
    "/wiki/Convolutional_neural_network", "/wiki/Cybersecurity",
    "/wiki/Transmission_Control_Protocol", "/wiki/Public-key_cryptography",
    "/3/library/urllib.parse.html?highlight=urlparse",
    "/3/library/math.html", "/3/library/os.path.html",
    "/torvalds/linux", "/torvalds/linux/commit/805e2634e9e03d40ec4df6bf538a7c646ef4a896",
    "/facebook/react/blob/main/packages/react/src/React.js",
    "/vercel/next.js/tree/canary/packages/next",
    "/rust-lang/rust/pull/112345",
    "/s3/pricing/?nc1=h_ls&region=us-east-1",
    "/pricing/calculator/?filters=compute",
    "/questions/11227809/why-is-processing-a-sorted-array-faster-than-unsorted",
    "/questions/927358/how-do-i-undo-the-most-recent-local-commits-in-git",
    "/questions/2003505/how-do-i-delete-a-git-branch-locally-and-remotely",
    "/en-US/docs/Web/API/URLSearchParams/get",
    "/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/map",
    "/watch?v=dQw4w9WgXcQ&list=PL1234567890&index=1",
    "/watch?v=aircAruvnKk",
    "/articles/PMC7326442/figure/F1/?report=objectonly",
    "/releases/tag/v2.14.0-rc1"
]

TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "chase",
    "wellsfargo", "bankofamerica", "binance", "coinbase", "metamask", "dhl",
    "usps", "fedex", "instagram", "facebook", "dropbox", "adobe", "steam"
]

ABUSE_TLDS = ["xyz", "top", "work", "buzz", "click", "cam", "monster", "icu", "tk", "ml", "ga", "cf", "sbs", "cfd"]
LEGIT_TLDS = ["com", "net", "org", "co.uk", "io", "gov", "edu", "info"]

PHISH_SUBDOMAINS = [
    "account-verification", "secure-login", "auth-portal", "update-billing",
    "service-alert", "wallet-connect", "security-recovery", "signin-support",
    "webscr-cmd", "myaccount-manage", "confirm-identity", "notice-suspended"
]

PHISH_PATHS = [
    "/login.php", "/signin.aspx", "/verify-account.html", "/webscr?cmd=_login-run",
    "/auth/checkpoint", "/session/expired/re-authenticate", "/secure/update-payment.cgi",
    "/portal/user/validate?token=8f39b20e", "/account/suspended/unlock?id=7721",
    "/wallet/keystore/import", "/billing/invoice/review?ref=992144",
    "/ebayisapi.dll?signin&usingcustompath=true", "/oauth/authorize?client_id=fake_app",
    "/wp-content/plugins/revslider/temp/login.php", "/secured-docs/preview/pdf"
]

TYPO_VARIANTS = {
    "paypal": ["paypa1", "pay-pal-security", "paypal-auth", "peypal", "paypaI"],
    "apple": ["app1e", "appleid-login", "apple-verify-service", "appl-support"],
    "microsoft": ["micros0ft", "micosoft-login", "office365-verify", "ms-account-sec"],
    "amazon": ["amaz0n", "amazon-billing-update", "amzon-security", "prime-renewal-alert"],
    "netflix": ["netflx", "netflix-billing-update", "net-flix-verify", "my-netflix-login"],
    "chase": ["chase-online-verify", "chasebank-security", "chas0nline", "chase-alert"],
    "binance": ["binance-auth", "binance-security-kyc", "binance-us-login", "binance-web3"],
    "coinbase": ["coinbase-pro-security", "coinbase-helpdesk", "coinbase-login-resolver"],
    "dhl": ["dhl-express-tracking-delivery", "dhl-parcel-notification", "dhl-fee-payment"],
    "usps": ["usps-redelivery-notice", "usps-post-track", "usps-address-confirm"]
}


def fetch_phishtank_verified(limit: int = 8000) -> list[str]:
    """Fetch verified live online phishing URLs from PhishTank database."""
    print(f"[*] Fetching real verified phishing URLs from PhishTank...")
    urls = []
    try:
        req = urllib.request.Request(
            "http://data.phishtank.com/data/online-valid.csv",
            headers={"User-Agent": "phishtank/PhishGuard-AI-Training"}
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            chunk = r.read(1024 * 1024 * 6).decode("utf-8", errors="ignore")
            reader = csv.DictReader(chunk.splitlines())
            for row in reader:
                u = row.get("url", "").strip()
                if u and u.startswith(("http://", "https://")):
                    urls.append(u)
                    if len(urls) >= limit:
                        break
        print(f"[+] Downloaded {len(urls)} real phishing URLs from PhishTank.")
    except Exception as e:
        print(f"[-] PhishTank fetch warning: {e}. Falling back to augmented sources.")
    return urls


def fetch_openphish_urls() -> list[str]:
    """Fetch active phishing URLs from OpenPhish community feed."""
    print("[*] Fetching active phishing URLs from OpenPhish...")
    urls = []
    try:
        req = urllib.request.Request(
            "https://openphish.com/feed.txt",
            headers={"User-Agent": "Mozilla/5.0 PhishGuard-AI"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            lines = r.read().decode("utf-8", errors="ignore").splitlines()
            urls = [line.strip() for line in lines if line.strip().startswith(("http://", "https://"))]
        print(f"[+] Downloaded {len(urls)} active phishing URLs from OpenPhish.")
    except Exception as e:
        print(f"[-] OpenPhish fetch warning: {e}")
    return urls


def fetch_opendns_top_domains(limit: int = 10000) -> list[str]:
    """Fetch top benign enterprise and public domains from OpenDNS list."""
    print("[*] Fetching top legitimate domains from OpenDNS...")
    domains = []
    try:
        req = urllib.request.Request(
            "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-top-domains.txt",
            headers={"User-Agent": "Mozilla/5.0 PhishGuard-AI"}
        )
        with urllib.request.urlopen(req, timeout=12) as r:
            for line in r.readlines():
                d = line.decode("utf-8", errors="ignore").strip()
                if d and "." in d and not d.startswith("#"):
                    domains.append(d)
                    if len(domains) >= limit:
                        break
        print(f"[+] Downloaded {len(domains)} top legitimate domains from OpenDNS.")
    except Exception as e:
        print(f"[-] OpenDNS fetch warning: {e}. Falling back to built-in legit domains.")
        domains = LEGIT_DOMAINS.copy()
    return domains


def generate_legitimate_url_from_domain(domain: str) -> str:
    """Generate a realistic legitimate URL using a real top domain with natural path and parameter distribution."""
    scheme = "https://" if random.random() > 0.05 else "http://"
    if random.random() < 0.35 and not domain.startswith("www."):
        sub = random.choice(["www", "blog", "docs", "app", "support", "api", "shop", "news", "m", "developer"])
        host = f"{sub}.{domain}"
    else:
        host = domain

    # Choose from rich natural paths
    path = random.choice(RICH_LEGIT_PATHS)
    
    # Realistic dynamic variations
    choice = random.random()
    if choice < 0.15:
        # Commit hash or identifier path
        hex_hash = "".join(random.choices("0123456789abcdef", k=40))
        path = f"/commit/{hex_hash}"
    elif choice < 0.30:
        # Documentation or knowledgebase path with section anchor
        topic = random.choice(["overview", "getting-started", "api-reference", "configuration", "deployment", "troubleshooting"])
        section_id = random.randint(1, 20)
        path = f"/docs/{topic}/v2.4#section-{section_id}"
    elif choice < 0.45:
        # Standard query search or pagination
        q = random.choice(["machine+learning", "cybersecurity+protocols", "python+programming", "cloud+architecture", "data+analysis"])
        page = random.randint(1, 25)
        path = f"/search?q={q}&page={page}&lang=en"

    return f"{scheme}{host}{path}"


def generate_phishing_url() -> str:
    """Generate an authentic, highly variable phishing attack URL with adversarial vectors."""
    attack_vector = random.choice([
        "subdomain_spoof", "typosquatting", "ip_address", "punycode",
        "suspicious_tld_combo", "shortener", "open_redirect", "credential_harvest"
    ])
    
    brand = random.choice(TARGET_BRANDS)
    scheme = "http://" if random.random() < 0.65 else "https://"

    if attack_vector == "subdomain_spoof":
        sub = f"{brand}.com.{random.choice(PHISH_SUBDOMAINS)}"
        parent_domain = f"server{random.randint(10, 999)}.{random.choice(ABUSE_TLDS)}"
        path = random.choice(PHISH_PATHS)
        return f"{scheme}{sub}.{parent_domain}{path}"

    elif attack_vector == "typosquatting":
        variants = TYPO_VARIANTS.get(brand, [f"{brand}-update", f"verify-{brand}"])
        typo_domain = random.choice(variants)
        tld = random.choice(ABUSE_TLDS if random.random() < 0.7 else LEGIT_TLDS)
        path = random.choice(PHISH_PATHS)
        return f"{scheme}{typo_domain}.{tld}{path}"

    elif attack_vector == "ip_address":
        ip = f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        port = f":{random.choice([8080, 8888, 3000, 8443, 8000])}" if random.random() < 0.4 else ""
        path = f"/{brand}" + random.choice(PHISH_PATHS)
        return f"http://{ip}{port}{path}"

    elif attack_vector == "punycode":
        return f"http://xn--{brand[:3]}-{random.randint(10, 99)}a.{random.choice(ABUSE_TLDS)}{random.choice(PHISH_PATHS)}"

    elif attack_vector == "suspicious_tld_combo":
        kw1 = random.choice(["secure", "portal", "verify", "account", "login", "auth"])
        kw2 = random.choice(["update", "alert", "notice", "recover", "session", "support"])
        tld = random.choice(ABUSE_TLDS)
        query = f"?user_id={random.randint(100000, 999999)}&token={random.getrandbits(32):x}"
        return f"{scheme}{kw1}-{brand}-{kw2}.{tld}{random.choice(PHISH_PATHS)}{query}"

    elif attack_vector == "shortener":
        shortener = random.choice(["bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly"])
        code = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
        return f"http://{shortener}/{code}?{brand}_verify=true"

    elif attack_vector == "open_redirect":
        fake_target = f"http://{brand}-security-checkpoint.{random.choice(ABUSE_TLDS)}/login"
        return f"https://www.google.com/url?q={fake_target}"

    else: # credential_harvest
        host = f"{random.choice(PHISH_SUBDOMAINS)}-{brand}.{random.choice(ABUSE_TLDS)}"
        path = random.choice(PHISH_PATHS)
        sensitive_params = f"?client_id={random.randint(1000, 9999)}&email=victim@user.com&action=re-verify&timestamp={random.randint(1600000000, 1780000000)}"
        return f"{scheme}{host}{path}{sensitive_params}"


def create_dataset(total_samples: int = 18000, data_dir: str = "ml/data") -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Generate and curate balanced dataset of real-world verified legitimate and phishing URLs,
    extract all 34 features, and save to CSV.
    """
    os.makedirs(data_dir, exist_ok=True)
    raw_path = os.path.join(data_dir, "raw_urls.csv")
    features_path = os.path.join(data_dir, "processed_features.csv")

    target_each = total_samples // 2
    print(f"[*] Building benchmark dataset: {target_each} Legitimate and {target_each} Phishing URLs...")

    # 1. Gather Phishing URLs (PhishTank + OpenPhish + adversarial patterns)
    phish_urls = []
    
    # Live verified phishing feeds
    real_phish = fetch_phishtank_verified(limit=target_each)
    openphish_urls = fetch_openphish_urls()
    combined_real_phish = list(dict.fromkeys(real_phish + openphish_urls))
    
    # Take real phishing URLs up to 60-70% of target
    real_quota = min(len(combined_real_phish), int(target_each * 0.65))
    phish_urls.extend(combined_real_phish[:real_quota])
    print(f"[+] Included {len(phish_urls)} verified real-world phishing URLs.")

    # Fill remainder with adversarial synthetic zero-day vectors
    while len(phish_urls) < target_each:
        phish_urls.append(generate_phishing_url())
    phish_urls = phish_urls[:target_each]
    print(f"[+] Total Phishing URLs assembled: {len(phish_urls)}")

    # 2. Gather Legitimate URLs (OpenDNS top enterprise domains + developer/complex URLs)
    legit_domains = fetch_opendns_top_domains(limit=10000)
    legit_urls = []

    # Include explicit developer/complex cases (commit hashes, python docs, wikipedia, aws pricing)
    complex_legit_seeds = [
        f"https://github.com/torvalds/linux/commit/{'a'*i}{'b'*(40-i)}" for i in range(1, 20)
    ] + [
        f"https://en.wikipedia.org/wiki/Machine_learning#Section_{i}_Algorithms" for i in range(1, 20)
    ] + [
        f"https://en.wikipedia.org/wiki/Phishing",
        f"https://en.wikipedia.org/wiki/Computer_security",
        f"https://github.com/torvalds/linux",
        f"https://www.google.com/search?q=machine+learning"
    ] + [
        f"https://aws.amazon.com/s3/pricing/?nc1=h_ls&region=us-east-{i}" for i in range(1, 20)
    ] + [
        f"https://docs.python.org/3/library/urllib.parse.html?highlight=urlparse#ref-{i}" for i in range(1, 20)
    ]
    legit_urls.extend(complex_legit_seeds)

    domain_idx = 0
    while len(legit_urls) < target_each:
        if legit_domains:
            dom = legit_domains[domain_idx % len(legit_domains)]
            domain_idx += 1
            legit_urls.append(generate_legitimate_url_from_domain(dom))
        else:
            dom = random.choice(LEGIT_DOMAINS)
            legit_urls.append(generate_legitimate_url_from_domain(dom))
    
    legit_urls = legit_urls[:target_each]
    print(f"[+] Total Legitimate URLs assembled: {len(legit_urls)}")

    # 3. Create DataFrame and shuffle
    records = []
    for u in legit_urls:
        records.append({"url": u, "label": 0})
    for u in phish_urls:
        records.append({"url": u, "label": 1})

    random.shuffle(records)
    df_raw = pd.DataFrame(records)
    df_raw.drop_duplicates(subset=["url"], inplace=True)
    df_raw.to_csv(raw_path, index=False)
    print(f"[+] Raw URLs dataset saved to {raw_path} ({len(df_raw)} unique records)")

    # 4. Extract 34 numerical features
    print(f"[*] Extracting 34 numerical features for {len(df_raw)} samples...")
    feature_rows = []
    total = len(df_raw)
    for idx, row in df_raw.iterrows():
        feat = extract_features(row["url"])
        feat["label"] = int(row["label"])
        feature_rows.append(feat)
        if (len(feature_rows)) % 3000 == 0 or len(feature_rows) == total:
            print(f"    - Processed {len(feature_rows)}/{total} samples ({len(feature_rows)/total*100:.1f}%)...")

    df_features = pd.DataFrame(feature_rows)
    df_features.to_csv(features_path, index=False)
    print(f"[+] Processed features saved to {features_path} with shape {df_features.shape}")

    return df_raw, df_features


if __name__ == "__main__":
    create_dataset(18000)
