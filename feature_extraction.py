"""
feature_extraction.py
----------------------
Extracts lexical / structural features from a URL string.
These features feed the Random Forest model and the rule-based
heuristic scorer in risk_engine.py.
"""

import re
import math
from urllib.parse import urlparse
import tldextract

SHORTENING_SERVICES = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"tiny\.cc|url4\.eu|short\.to|budurl\.com|rubyurl\.com|wp\.me|kl\.am|bit\.do"
)

SUSPICIOUS_TLDS = {
    "zip", "review", "country", "kim", "cricket", "science", "work",
    "party", "gq", "link", "xyz", "top", "club", "tk"
}

# Well-known brands and their real, registered domain. Used to catch the
# classic "brand-in-subdomain" spoof, e.g. https://instagram.login.com
# (registered domain is login.com; "instagram" is just a free-to-choose
# subdomain label). HTTPS does NOT protect against this attack.
BRAND_DOMAINS = {
    "instagram": "instagram.com", "facebook": "facebook.com",
    "google": "google.com", "paypal": "paypal.com",
    "amazon": "amazon.com", "apple": "apple.com",
    "microsoft": "microsoft.com", "netflix": "netflix.com",
    "linkedin": "linkedin.com", "whatsapp": "whatsapp.com",
    "twitter": "twitter.com", "chase": "chase.com",
    "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com",
    "hdfcbank": "hdfcbank.com", "icicibank": "icicibank.com",
    "flipkart": "flipkart.com", "dropbox": "dropbox.com",
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def has_ip_address(domain: str) -> bool:
    pattern = re.compile(r"^(([0-9]{1,3}\.){3}[0-9]{1,3})$")
    return bool(pattern.match(domain))


def get_registered_domain(url: str) -> str:
    """Returns the actual registered domain (e.g. 'login.com'), ignoring
    any subdomains the attacker is free to name anything they like."""
    test_url = url if re.match(r"^https?://", url, re.I) else "http://" + url
    ext = tldextract.extract(test_url)
    return f"{ext.domain}.{ext.suffix}".lower()


def detect_brand_impersonation(url: str):
    """Checks if a well-known brand name appears in the URL (subdomain,
    domain, or path) while the ACTUAL registered domain does not belong
    to that brand. This catches attacks like https://instagram.login.com
    that a plain 'is it HTTPS' check would wrongly call safe.

    Returns (brand_name, registered_domain) if impersonation is found,
    otherwise None.
    """
    test_url = url if re.match(r"^https?://", url, re.I) else "http://" + url
    ext = tldextract.extract(test_url)
    registered_domain = f"{ext.domain}.{ext.suffix}".lower()
    full_string = f"{ext.subdomain}.{ext.domain}.{ext.suffix}".lower()

    for brand, legit_domain in BRAND_DOMAINS.items():
        if brand in full_string and registered_domain != legit_domain:
            return brand, registered_domain
    return None


def extract_features(url: str) -> dict:
    url = url.strip()
    test_url = url if re.match(r"^https?://", url, re.I) else "http://" + url

    parsed = urlparse(test_url)
    ext = tldextract.extract(test_url)
    domain = parsed.netloc.split(":")[0]
    subdomain = ext.subdomain
    path = parsed.path or ""

    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscore": url.count("_"),
        "num_slash": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special_chars": len(re.findall(r"[@%=&?~#]", url)),
        "has_at_symbol": int("@" in url),
        "has_ip": int(has_ip_address(domain)),
        "is_shortened": int(bool(SHORTENING_SERVICES.search(url))),
        "subdomain_count": 0 if subdomain == "" else len(subdomain.split(".")),
        "has_https_scheme": int(parsed.scheme == "https"),
        "https_in_domain_token": int("https" in domain.lower()),
        "prefix_suffix_hyphen": int("-" in ext.domain),
        "suspicious_tld": int(ext.suffix.lower() in SUSPICIOUS_TLDS),
        "path_length": len(path),
        "double_slash_redirect": int("//" in path),
        "domain_entropy": round(shannon_entropy(domain), 3),
        "long_url": int(len(url) > 75),
    }
    features["many_subdomains"] = int(features["subdomain_count"] > 3)
    return features


FEATURE_ORDER = [
    "url_length", "domain_length", "num_dots", "num_hyphens", "num_underscore",
    "num_slash", "num_digits", "num_special_chars", "has_at_symbol", "has_ip",
    "is_shortened", "subdomain_count", "has_https_scheme", "https_in_domain_token",
    "prefix_suffix_hyphen", "suspicious_tld", "path_length", "double_slash_redirect",
    "domain_entropy", "long_url", "many_subdomains",
]


def features_to_vector(feat: dict):
    return [feat[k] for k in FEATURE_ORDER]
