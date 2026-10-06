from urllib.parse import urlparse
import tldextract
from ml.src.feature_extractor import TARGET_BRANDS, levenshtein_distance

def analyze_brand_spoofing(url: str) -> dict:
    """
    Perform deep inspection for brand impersonation and typosquatting attacks.
    """
    extracted = tldextract.extract(url)
    domain = (extracted.domain or "").lower()
    subdomain = (extracted.subdomain or "").lower()
    suffix = (extracted.suffix or "").lower()
    
    parsed = urlparse(url if "://" in url else f"http://{url}")
    path = parsed.path.lower()
    netloc = parsed.netloc.lower()

    # 1. Exact brand in subdomain while main domain belongs to someone else
    # e.g., paypal.com.attacker.xyz
    for brand in TARGET_BRANDS:
        if brand in subdomain:
            if brand != domain:
                return {
                    "target_brand": brand.title(),
                    "is_spoofed": True,
                    "similarity_distance": 0,
                    "technique": "subdomain_spoofing",
                    "assessment": f"Subdomain masquerades as {brand.title()}, while registered domain is '{domain}.{suffix}'."
                }

    # 2. Typosquatting on main registered domain (full domain or hyphen-separated tokens)
    # e.g., paypa1, paypa1-security, micros0ft, amazn, app1e-login
    domain_tokens = [domain] + [t for t in domain.split('-') if len(t) >= 4]

    for brand in TARGET_BRANDS:
        if domain == brand:
            return {
                "target_brand": brand.title(),
                "is_spoofed": False,
                "similarity_distance": 0,
                "technique": "legitimate_domain",
                "assessment": f"Official registered domain for {brand.title()}."
            }

        for token in domain_tokens:
            dist = levenshtein_distance(token, brand)
            if 0 < dist <= 2 and len(token) >= 4:
                return {
                    "target_brand": brand.title(),
                    "is_spoofed": True,
                    "similarity_distance": dist,
                    "technique": "typosquatting",
                    "assessment": f"Typosquatting variant of {brand.title()} detected in domain token '{token}' (Levenshtein edit distance: {dist})."
                }

    # 3. Target brand injected into deep path or query with suspicious host
    for brand in TARGET_BRANDS:
        if brand in path or (parsed.query and brand in parsed.query.lower()):
            if domain != brand:
                return {
                    "target_brand": brand.title(),
                    "is_spoofed": True,
                    "similarity_distance": None,
                    "technique": "path_credential_harvest",
                    "assessment": f"Brand reference to {brand.title()} observed in path or query under unrelated domain '{domain}.{suffix}'."
                }

    return {
        "target_brand": None,
        "is_spoofed": False,
        "similarity_distance": None,
        "technique": "none",
        "assessment": "No overt brand spoofing or typosquatting signatures identified."
    }
