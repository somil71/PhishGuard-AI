import os
import random
import csv
import io
import urllib.request
import pandas as pd
from ml.src.feature_extractor import extract_features, FEATURE_NAMES

RANDOM_SEED = 42
random.seed(RANDOM_SEED)


def fetch_actual_kaggle_unb_dataset(target_legit: int = 12000, target_phish: int = 8000) -> tuple[list[str], list[str]]:
    """
    Download actual real-world benchmark dataset (UNB/Kaggle malicious URL corpus)
    containing genuine historical legitimate web URLs and actual phishing URLs.
    """
    print("[*] Downloading actual benchmark dataset from HuggingFace (alexkstern/phishing_urls)...")
    url = "https://huggingface.co/datasets/alexkstern/phishing_urls/resolve/main/train.csv"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 PhishGuard-AI"})
    
    with urllib.request.urlopen(req, timeout=40) as r:
        # Read ~15MB of actual benchmark data
        data = r.read(1024 * 1024 * 15)

    df = pd.read_csv(io.BytesIO(data), on_bad_lines="skip")
    df = df.dropna().rename(columns={"text": "url"})
    df["label"] = df["label"].astype(int)

    # Clean and filter
    df["url"] = df["url"].astype(str).str.strip().str.strip("'\"")
    df = df[df["url"].str.len() > 7]
    df = df[~df["url"].str.startswith("http\\%3A")]

    legit_df = df[df["label"] == 0]
    phish_df = df[df["label"] == 1]

    def normalize_url(u: str, default_scheme: str = "http://") -> str:
        u = u.strip()
        if not u.startswith(("http://", "https://")):
            return default_scheme + u
        return u

    legit_urls = [normalize_url(u, "https://") for u in legit_df["url"].tolist()]
    phish_urls = [normalize_url(u, "http://") for u in phish_df["url"].tolist()]

    # Shuffle and slice
    random.shuffle(legit_urls)
    random.shuffle(phish_urls)

    selected_legit = legit_urls[:target_legit]
    selected_phish = phish_urls[:target_phish]

    print(f"[+] Loaded {len(selected_legit)} genuine legitimate URLs and {len(selected_phish)} genuine phishing URLs.")
    return selected_legit, selected_phish


def fetch_phishtank_verified_actual(limit: int = 6000) -> list[str]:
    """Fetch live verified real-world phishing URLs directly from PhishTank database."""
    print("[*] Downloading live verified phishing URLs from PhishTank database...")
    urls = []
    try:
        req = urllib.request.Request(
            "http://data.phishtank.com/data/online-valid.csv",
            headers={"User-Agent": "phishtank/PhishGuard-AI-Training"}
        )
        with urllib.request.urlopen(req, timeout=25) as r:
            chunk = r.read(1024 * 1024 * 6).decode("utf-8", errors="ignore")
            reader = csv.DictReader(chunk.splitlines())
            for row in reader:
                u = row.get("url", "").strip()
                if u and u.startswith(("http://", "https://")):
                    urls.append(u)
                    if len(urls) >= limit:
                        break
        print(f"[+] Downloaded {len(urls)} actual live phishing URLs from PhishTank.")
    except Exception as e:
        print(f"[-] PhishTank warning: {e}")
    return urls


def fetch_openphish_actual() -> list[str]:
    """Fetch live active phishing URLs from OpenPhish feed."""
    print("[*] Downloading active phishing URLs from OpenPhish feed...")
    urls = []
    try:
        req = urllib.request.Request(
            "https://openphish.com/feed.txt",
            headers={"User-Agent": "Mozilla/5.0 PhishGuard-AI"}
        )
        with urllib.request.urlopen(req, timeout=12) as r:
            lines = r.read().decode("utf-8", errors="ignore").splitlines()
            urls = [line.strip() for line in lines if line.strip().startswith(("http://", "https://"))]
        print(f"[+] Downloaded {len(urls)} actual live phishing URLs from OpenPhish.")
    except Exception as e:
        print(f"[-] OpenPhish warning: {e}")
    return urls


def create_dataset(total_samples: int = 24000, data_dir: str = "ml/data") -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Construct genuine real-world balanced dataset:
    - 100% actual real URLs from benchmark UNB/Kaggle corpora + PhishTank + OpenPhish
    - Zero synthetic/templated samples
    - Extracts 34 numerical features and persists to CSV
    """
    os.makedirs(data_dir, exist_ok=True)
    raw_path = os.path.join(data_dir, "raw_urls.csv")
    features_path = os.path.join(data_dir, "processed_features.csv")

    target_half = total_samples // 2
    print(f"[*] Assembling actual dataset: target ~{target_half} real legitimate & ~{target_half} real phishing URLs...")

    # 1. Fetch real Kaggle / UNB benchmark URLs
    real_legit, real_phish = fetch_actual_kaggle_unb_dataset(
        target_legit=target_half,
        target_phish=int(target_half * 0.65)
    )

    # 2. Fetch live real verified phishing from PhishTank & OpenPhish
    phishtank_phish = fetch_phishtank_verified_actual(limit=int(target_half * 0.40))
    openphish_urls = fetch_openphish_actual()

    # Combine all actual phishing URLs
    all_phish = list(dict.fromkeys(real_phish + phishtank_phish + openphish_urls))
    random.shuffle(all_phish)
    all_phish = all_phish[:target_half]

    # Combine all actual legitimate URLs
    all_legit = list(dict.fromkeys(real_legit))
    random.shuffle(all_legit)
    all_legit = all_legit[:target_half]

    print(f"[+] Final curated counts: {len(all_legit)} ACTUAL legitimate URLs, {len(all_phish)} ACTUAL phishing URLs.")

    # 3. Create DataFrame and shuffle
    records = []
    for u in all_legit:
        records.append({"url": u, "label": 0})
    for u in all_phish:
        records.append({"url": u, "label": 1})

    random.shuffle(records)
    df_raw = pd.DataFrame(records)
    df_raw.drop_duplicates(subset=["url"], inplace=True)
    df_raw.to_csv(raw_path, index=False)
    print(f"[+] Raw URLs saved to {raw_path} ({len(df_raw)} unique real-world URLs)")

    # 4. Extract 34 numerical features
    print(f"[*] Extracting 34 numerical features for {len(df_raw)} actual URLs...")
    feature_rows = []
    total = len(df_raw)
    for idx, row in df_raw.iterrows():
        try:
            feat = extract_features(row["url"])
            feat["label"] = int(row["label"])
            feature_rows.append(feat)
        except Exception:
            continue

        if (len(feature_rows)) % 3000 == 0 or len(feature_rows) == total:
            print(f"    - Processed {len(feature_rows)}/{total} samples ({len(feature_rows)/total*100:.1f}%)...")

    df_features = pd.DataFrame(feature_rows)
    df_features.to_csv(features_path, index=False)
    print(f"[+] Processed features saved to {features_path} with shape {df_features.shape}")

    return df_raw, df_features


if __name__ == "__main__":
    create_dataset(24000)
