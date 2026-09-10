import os
import random
import pandas as pd
from ml.src.feature_extractor import extract_features, FEATURE_NAMES

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

# Legitimate domain templates
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

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/products", "/services", "/help", "/documentation",
    "/blog/2026/03/update", "/news/technology/ai-advancements", "/articles/overview",
    "/item/view?id=49201&category=electronics", "/search?q=machine+learning+tutorial",
    "/profile/settings", "/docs/api/v2/reference", "/support/knowledge-base/article-102",
    "/community/forum/topic/8812", "/download/releases/latest", "/explore/trending",
    "/courses/computer-science-intro", "/cart/checkout/summary", "/events/annual-summit-2026",
    "/catalog/books/science-fiction", "/investor-relations/quarterly-earnings"
]

# Targeted brands for realistic phishing vectors
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


def generate_legitimate_url() -> str:
    """Generate a high-reputation, realistic legitimate URL."""
    domain = random.choice(LEGIT_DOMAINS)
    scheme = "https://" if random.random() > 0.05 else "http://"
    
    # Subdomain variation for legitimate hosts
    if random.random() < 0.4:
        sub = random.choice(["www", "blog", "docs", "app", "support", "api", "shop", "news", "m", "developer"])
        host = f"{sub}.{domain}"
    else:
        host = domain if domain.startswith("www.") else f"www.{domain}" if random.random() < 0.5 else domain

    path = random.choice(LEGIT_PATHS)
    
    # Optional benign query parameters
    if random.random() < 0.3 and not ("?" in path):
        params = [
            f"?page={random.randint(1, 20)}",
            f"?lang={random.choice(['en', 'fr', 'es', 'de'])}",
            f"?session_id=legit_{random.randint(10000, 99999)}",
            f"?ref={random.choice(['social', 'email', 'partner', 'organic'])}"
        ]
        path = path + random.choice(params)

    return f"{scheme}{host}{path}"


def generate_phishing_url() -> str:
    """Generate an authentic, highly variable phishing attack URL."""
    attack_vector = random.choice([
        "subdomain_spoof", "typosquatting", "ip_address", "punycode",
        "suspicious_tld_combo", "shortener", "open_redirect", "credential_harvest"
    ])
    
    brand = random.choice(TARGET_BRANDS)
    scheme = "http://" if random.random() < 0.6 else "https://"

    if attack_vector == "subdomain_spoof":
        # e.g., paypal.com.account-update.xyz/login.php
        sub = f"{brand}.com.{random.choice(PHISH_SUBDOMAINS)}"
        parent_domain = f"server{random.randint(10, 999)}.{random.choice(ABUSE_TLDS)}"
        path = random.choice(PHISH_PATHS)
        return f"{scheme}{sub}.{parent_domain}{path}"

    elif attack_vector == "typosquatting":
        # e.g., paypa1-security.buzz/verify-account.html
        variants = TYPO_VARIANTS.get(brand, [f"{brand}-update", f"verify-{brand}"])
        typo_domain = random.choice(variants)
        tld = random.choice(ABUSE_TLDS if random.random() < 0.7 else LEGIT_TLDS)
        path = random.choice(PHISH_PATHS)
        return f"{scheme}{typo_domain}.{tld}{path}"

    elif attack_vector == "ip_address":
        # e.g., http://192.168.1.15:8080/secure/paypal/login
        ip = f"{random.randint(11, 220)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        port = f":{random.choice([8080, 8888, 3000, 8443, 8000])}" if random.random() < 0.4 else ""
        path = f"/{brand}" + random.choice(PHISH_PATHS)
        return f"http://{ip}{port}{path}"

    elif attack_vector == "punycode":
        # e.g., http://xn--appl-35a.com/account/login
        return f"http://xn--{brand[:3]}-{random.randint(10, 99)}a.{random.choice(ABUSE_TLDS)}{random.choice(PHISH_PATHS)}"

    elif attack_vector == "suspicious_tld_combo":
        # e.g., http://secure-banking-verification-notice.top/signin.aspx?token=92841
        kw1 = random.choice(["secure", "portal", "verify", "account", "login", "auth"])
        kw2 = random.choice(["update", "alert", "notice", "recover", "session", "support"])
        tld = random.choice(ABUSE_TLDS)
        query = f"?user_id={random.randint(100000, 999999)}&token={random.getrandbits(32):x}"
        return f"{scheme}{kw1}-{brand}-{kw2}.{tld}{random.choice(PHISH_PATHS)}{query}"

    elif attack_vector == "shortener":
        # e.g., http://bit.ly/3xZ1q8?redirect=paypal.com
        shortener = random.choice(["bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly"])
        code = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
        return f"http://{shortener}/{code}?{brand}_verify=true"

    elif attack_vector == "open_redirect":
        # e.g., https://legit-redirector.com/out?url=http://paypa1-fake.xyz
        fake_target = f"http://{brand}-security-checkpoint.{random.choice(ABUSE_TLDS)}/login"
        return f"https://www.google.com/url?q={fake_target}"

    else: # credential_harvest
        host = f"{random.choice(PHISH_SUBDOMAINS)}-{brand}.{random.choice(ABUSE_TLDS)}"
        path = random.choice(PHISH_PATHS)
        sensitive_params = f"?client_id={random.randint(1000, 9999)}&email=victim@user.com&action=re-verify&timestamp={random.randint(1600000000, 1780000000)}"
        return f"{scheme}{host}{path}{sensitive_params}"


def create_dataset(total_samples: int = 12000, data_dir: str = "ml/data") -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Generate balanced dataset of legitimate and phishing URLs,
    extract all 34 features, and save to CSV.
    """
    os.makedirs(data_dir, exist_ok=True)
    raw_path = os.path.join(data_dir, "raw_urls.csv")
    features_path = os.path.join(data_dir, "processed_features.csv")

    half = total_samples // 2
    print(f"[*] Generating {half} Legitimate and {half} Phishing URLs...")

    records = []
    # Generate legitimate URLs
    for _ in range(half):
        records.append({"url": generate_legitimate_url(), "label": 0})
    
    # Generate phishing URLs
    for _ in range(half):
        records.append({"url": generate_phishing_url(), "label": 1})

    random.shuffle(records)
    df_raw = pd.DataFrame(records)
    df_raw.to_csv(raw_path, index=False)
    print(f"[+] Raw URLs dataset saved to {raw_path} ({len(df_raw)} records)")

    print("[*] Extracting 34 numerical features for training...")
    feature_rows = []
    for idx, row in df_raw.iterrows():
        feat = extract_features(row["url"])
        feat["label"] = row["label"]
        feature_rows.append(feat)
        if (idx + 1) % 2000 == 0 or (idx + 1) == len(df_raw):
            print(f"    - Processed {idx + 1}/{len(df_raw)} samples...")

    df_features = pd.DataFrame(feature_rows)
    df_features.to_csv(features_path, index=False)
    print(f"[+] Processed features saved to {features_path} with shape {df_features.shape}")

    return df_raw, df_features


if __name__ == "__main__":
    create_dataset(12000)
