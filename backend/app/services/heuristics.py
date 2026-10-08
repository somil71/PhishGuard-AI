from typing import List, Dict
from ml.src.feature_extractor import SUSPICIOUS_TLDS, SHORTENER_DOMAINS, SENSITIVE_KEYWORDS

def evaluate_heuristics(features: dict, url_str: str) -> List[Dict]:
    """
    Evaluate structural and lexical security rules, returning detected heuristic flags.
    """
    indicators = []

    # 1. IP Host
    has_ip = features.get('has_ip', 0) == 1
    indicators.append({
        "id": "ip_host",
        "name": "Host as Raw IP Address",
        "severity": "critical",
        "detected": has_ip,
        "details": "Direct numerical IP address used as hostname instead of a registered domain, commonly used in short-lived attacks." if has_ip else "Standard domain name resolution utilized."
    })

    # 2. Suspicious TLD
    suspicious_tld = features.get('suspicious_tld', 0) == 1
    indicators.append({
        "id": "suspicious_tld",
        "name": "High-Abuse Top-Level Domain",
        "severity": "critical" if suspicious_tld else "info",
        "detected": suspicious_tld,
        "details": "The domain operates under a TLD heavily exploited for spam and credential harvesting." if suspicious_tld else "Operating under an established top-level domain."
    })

    # 3. HTTPS Encryption
    is_https = features.get('is_https', 0) == 1
    indicators.append({
        "id": "transport_security",
        "name": "HTTPS Transport Encryption",
        "severity": "info" if is_https else "warning",
        "detected": not is_https,
        "details": "Unencrypted HTTP protocol detected, exposing transmission to interception." if not is_https else "Modern HTTPS encryption protocol active."
    })

    # 4. Sensitive Keywords
    kw_count = features.get('sensitive_keywords_count', 0)
    indicators.append({
        "id": "sensitive_keywords",
        "name": "Authentication / Security Keywords",
        "severity": "critical" if kw_count >= 2 else "warning" if kw_count == 1 else "info",
        "detected": kw_count > 0,
        "details": f"Detected {kw_count} security/banking keyword(s) frequently associated with phishing lures." if kw_count > 0 else "No suspicious authentication keyword lures detected."
    })

    # 5. Shannon Entropy Obfuscation
    url_entropy = features.get('url_entropy', 0.0)
    high_entropy = url_entropy > 4.4
    indicators.append({
        "id": "entropy_obfuscation",
        "name": "Shannon Entropy Obfuscation",
        "severity": "warning" if high_entropy else "info",
        "detected": high_entropy,
        "details": f"High character entropy ({url_entropy:.2f}) indicates potential tokenization or payload packing." if high_entropy else f"Normal character entropy distribution ({url_entropy:.2f})."
    })

    # 6. IDN Punycode
    has_puny = features.get('has_punycode', 0) == 1
    indicators.append({
        "id": "idn_punycode",
        "name": "IDN Homograph Punycode",
        "severity": "critical" if has_puny else "info",
        "detected": has_puny,
        "details": "Punycode (xn--) detected; possible Cyrillic or Unicode visual spoofing attack." if has_puny else "Standard ASCII character set used."
    })

    # 7. TLD in Subdomain
    tld_sub = features.get('tld_in_subdomain', 0) == 1
    indicators.append({
        "id": "tld_in_subdomain",
        "name": "Deceptive TLD in Subdomain",
        "severity": "critical" if tld_sub else "info",
        "detected": tld_sub,
        "details": "Common TLD (.com, .org) found inside a subdomain to visually deceive users." if tld_sub else "Hierarchical subdomains appear standard."
    })

    # 8. Shortening Service
    has_short = features.get('has_shortener', 0) == 1
    indicators.append({
        "id": "url_shortener",
        "name": "URL Shortener / Masking",
        "severity": "warning" if has_short else "info",
        "detected": has_short,
        "details": "URL shortener detected, hiding the true destination endpoint." if has_short else "Direct destination domain provided."
    })

    return indicators
