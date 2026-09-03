import re
import math
from urllib.parse import urlparse
import tldextract

# High-risk TLDs frequently abused in phishing campaigns
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'buzz', 'click', 'tk', 'ml', 'ga', 'cf', 'gq',
    'cam', 'monster', 'rest', 'fit', 'club', 'loan', 'racing', 'date',
    'win', 'stream', 'party', 'live', 'support', 'cyou', 'vip', 'quest',
    'icu', 'sbs', 'cfd', 'shop', 'online', 'space', 'site'
}

# Known URL shorteners
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bit.do', 'cutt.ly', 'shorte.st', 'rebrand.ly', 'tiny.cc'
}

# High-value targets for brand impersonation
TARGET_BRANDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'facebook', 'instagram',
    'twitter', 'linkedin', 'binance', 'coinbase', 'metamask', 'dropbox',
    'adobe', 'dhl', 'fedex', 'usps', 'walmart', 'ebay', 'steam'
]

# Sensitive keywords indicating credential harvesting or fraud
SENSITIVE_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification',
    'account', 'update', 'security', 'secure', 'banking', 'wallet',
    'password', 'credential', 'confirm', 'confirmation', 'billing',
    'invoice', 'suspended', 'unlock', 'support', 'webscr', 'ebayisapi',
    'token', 'recovery', 'validate', 'authenticate', 'service-alert'
]

COMMON_TLDS = {'com', 'net', 'org', 'edu', 'gov', 'io', 'co', 'info', 'biz'}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_ip_address(host: str) -> int:
    """Detect IPv4 or IPv6 pattern in host."""
    ipv4_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    ipv6_pattern = r'^\[?[a-fA-F0-9:]+\]?$'
    hex_ip_pattern = r'^0x[0-9a-fA-F]+'
    
    host_clean = host.split(':')[0]
    if re.match(ipv4_pattern, host_clean):
        return 1
    if re.match(hex_ip_pattern, host_clean):
        return 1
    if ':' in host_clean and len(host_clean.split(':')) > 2:
        return 1
    return 0


def extract_features(raw_url: str) -> dict:
    """
    Extract 34 structural, lexical, entropy, and domain-based features from a URL.
    Returns a dictionary of feature names and numerical values.
    """
    url = raw_url.strip()
    if not url.startswith(('http://', 'https://')):
        # Default scheme for parsing if absent
        url_parsed = urlparse('http://' + url)
        has_explicit_scheme = 0
    else:
        url_parsed = urlparse(url)
        has_explicit_scheme = 1

    scheme = url_parsed.scheme.lower()
    netloc = url_parsed.netloc.lower()
    path = url_parsed.path
    query = url_parsed.query
    fragment = url_parsed.fragment

    # Extract domain components via tldextract
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ''
    domain = extracted.domain.lower() if extracted.domain else ''
    suffix = extracted.suffix.lower() if extracted.suffix else ''
    registered_domain = f"{domain}.{suffix}" if suffix else domain

    # 1-4: Length metrics
    url_length = len(url)
    domain_length = len(netloc)
    path_length = len(path)
    query_length = len(query)

    # 5-14: Character counts
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_underscores = url.count('_')
    num_slashes = url.count('/')
    num_question_marks = url.count('?')
    num_equals = url.count('=')
    num_at_symbols = url.count('@')
    num_ampersands = url.count('&')
    num_exclamations = url.count('!')
    num_percent = url.count('%')

    # 15-16: Digit metrics
    num_digits = sum(c.isdigit() for c in url)
    digit_ratio = round(num_digits / max(1, url_length), 4)

    # 17: IP host
    has_ip = is_ip_address(netloc)

    # 18: HTTPS check
    is_https = 1 if scheme == 'https' else 0

    # 19: Subdomains count
    num_subdomains = len(subdomain.split('.')) if subdomain else 0

    # 20-22: Shannon Entropies
    url_entropy = calculate_entropy(url)
    domain_entropy = calculate_entropy(netloc)
    path_entropy = calculate_entropy(path)

    # 23: Shortening service
    has_shortener = 1 if registered_domain in SHORTENER_DOMAINS or netloc in SHORTENER_DOMAINS else 0

    # 24: Suspicious TLD
    suspicious_tld = 1 if suffix in SUSPICIOUS_TLDS else 0

    # 25: Sensitive keywords count in full URL
    url_lower = url.lower()
    sensitive_keywords_count = sum(1 for kw in SENSITIVE_KEYWORDS if kw in url_lower)

    # 26-27: Brand impersonation & min distance
    brand_impersonation = 0
    min_brand_dist = 99
    
    full_host_and_path = (netloc + path).lower()
    for brand in TARGET_BRANDS:
        # Exact match inside subdomain or path when domain is different
        if brand in full_host_and_path and brand != domain:
            brand_impersonation = 1
        
        # Typosquatting distance check on the core registered domain name
        if domain:
            dist = levenshtein_distance(domain, brand)
            if dist < min_brand_dist:
                min_brand_dist = dist
            # 1 or 2 character substitutions/insertions (e.g. paypa1, micros0ft)
            if 0 < dist <= 2 and len(domain) >= 4:
                brand_impersonation = 1

    # Normalize min brand distance
    normalized_brand_dist = round(min(min_brand_dist, 10) / 10.0, 4)

    # 28: Punycode / IDN homograph
    has_punycode = 1 if 'xn--' in netloc else 0

    # 29: Double slash in path redirect
    double_slash_in_path = 1 if '//' in path else 0

    # 30: Port specified in host
    has_port_in_url = 1 if ':' in netloc and not is_ip_address(netloc) else 0

    # 31: Prefix or suffix hyphen in domain
    prefix_suffix_hyphen = 1 if domain.startswith('-') or domain.endswith('-') or '-' in domain else 0

    # 32: Consecutive repeated characters (e.g. 'aaaa', '9999')
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(url)):
        if url[i] == url[i - 1]:
            current_repeat += 1
            if current_repeat > max_repeat:
                max_repeat = current_repeat
        else:
            current_repeat = 1
    consecutive_char_repeat = min(max_repeat, 15)

    # 33: Vowel to consonant ratio in domain
    vowels = sum(1 for c in domain if c in 'aeiou')
    consonants = sum(1 for c in domain if c.isalpha() and c not in 'aeiou')
    vowel_to_consonant_ratio = round(vowels / max(1, consonants), 4)

    # 34: Common TLD in subdomain (e.g. paypal.com.attacker.site)
    tld_in_sub = 0
    for ctld in COMMON_TLDS:
        if f".{ctld}" in subdomain or subdomain.endswith(ctld):
            tld_in_sub = 1
            break

    features = {
        'url_length': url_length,
        'domain_length': domain_length,
        'path_length': path_length,
        'query_length': query_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_underscores': num_underscores,
        'num_slashes': num_slashes,
        'num_question_marks': num_question_marks,
        'num_equals': num_equals,
        'num_at_symbols': num_at_symbols,
        'num_ampersands': num_ampersands,
        'num_exclamations': num_exclamations,
        'num_percent': num_percent,
        'num_digits': num_digits,
        'digit_ratio': digit_ratio,
        'has_ip': has_ip,
        'is_https': is_https,
        'num_subdomains': num_subdomains,
        'url_entropy': url_entropy,
        'domain_entropy': domain_entropy,
        'path_entropy': path_entropy,
        'has_shortener': has_shortener,
        'suspicious_tld': suspicious_tld,
        'sensitive_keywords_count': sensitive_keywords_count,
        'brand_impersonation': brand_impersonation,
        'normalized_brand_dist': normalized_brand_dist,
        'has_punycode': has_punycode,
        'double_slash_in_path': double_slash_in_path,
        'has_port_in_url': has_port_in_url,
        'prefix_suffix_hyphen': prefix_suffix_hyphen,
        'consecutive_char_repeat': consecutive_char_repeat,
        'vowel_to_consonant_ratio': vowel_to_consonant_ratio,
        'tld_in_subdomain': tld_in_sub,
    }

    return features


FEATURE_NAMES = list(extract_features('https://example.com').keys())

FEATURE_DESCRIPTIONS = {
    'url_length': 'Total character count of the URL',
    'domain_length': 'Length of host/netloc component',
    'path_length': 'Length of URL path directory structure',
    'query_length': 'Length of query parameter string',
    'num_dots': 'Count of dot (.) delimiters in URL',
    'num_hyphens': 'Count of hyphen (-) characters',
    'num_underscores': 'Count of underscore (_) characters',
    'num_slashes': 'Count of forward slash (/) characters',
    'num_question_marks': 'Count of question marks (?) in URL',
    'num_equals': 'Count of assignment equals signs (=)',
    'num_at_symbols': 'Presence of userinfo (@) spoofing symbol',
    'num_ampersands': 'Count of query parameter separators (&)',
    'num_exclamations': 'Count of exclamation marks (!)',
    'num_percent': 'Count of percent encoding indicators (%)',
    'num_digits': 'Total count of numeric characters',
    'digit_ratio': 'Ratio of numeric characters to total URL length',
    'has_ip': 'Binary flag: whether host is raw IP address',
    'is_https': 'Binary flag: whether scheme uses TLS/HTTPS',
    'num_subdomains': 'Number of hierarchical subdomain levels',
    'url_entropy': 'Shannon information entropy of the full URL',
    'domain_entropy': 'Shannon information entropy of the domain',
    'path_entropy': 'Shannon information entropy of the path',
    'has_shortener': 'Flag for known URL shortening service',
    'suspicious_tld': 'Flag for top-level domains frequently abused by phishing',
    'sensitive_keywords_count': 'Count of credential/banking keywords in URL',
    'brand_impersonation': 'Flag for spoofing high-value brand names or typosquatting',
    'normalized_brand_dist': 'Normalized Levenshtein distance to closest target brand',
    'has_punycode': 'Flag for IDN Homograph Punycode (xn--) encoding',
    'double_slash_in_path': 'Flag for open redirect bypass syntax (//) in path',
    'has_port_in_url': 'Presence of explicit non-standard port designation',
    'prefix_suffix_hyphen': 'Presence of hyphens in domain name',
    'consecutive_char_repeat': 'Maximum consecutive identical characters',
    'vowel_to_consonant_ratio': 'Vowel to consonant balance in domain',
    'tld_in_subdomain': 'Flag for deceptive TLD placement inside subdomain'
}
