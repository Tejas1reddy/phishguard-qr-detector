"""
glossary.py
-------------
Plain-English explanations for every technical feature/term used by
the risk engine, so the app can explain WHY a score was given instead
of just showing raw feature names.
"""

FEATURE_GLOSSARY = {
    "has_ip": "Uses a raw numeric IP address instead of a normal domain name — a classic phishing trick.",
    "has_at_symbol": "Contains an '@' symbol in the link. Browsers ignore everything before an '@', so attackers hide the real destination after it.",
    "is_shortened": "Uses a link-shortening service (bit.ly, tinyurl, etc.), which hides the real destination until you click.",
    "suspicious_tld": "Ends in a domain extension often abused for spam or throwaway sites (like .xyz, .top, .club, .tk).",
    "prefix_suffix_hyphen": "The domain name contains a hyphen, often used to imitate a real brand (e.g. 'paypal-secure.com').",
    "https_in_domain_token": "The word 'https' appears inside the domain name itself — a common spoofing trick to look secure without actually being secure.",
    "many_subdomains": "Has an unusually large number of subdomains, sometimes used to bury the real domain deep in the address.",
    "long_url": "The link is unusually long, which can be used to hide malicious parts of the address.",
    "double_slash_redirect": "Contains a double-slash pattern in the path, sometimes used to silently redirect elsewhere.",
    "domain_entropy": "The domain name looks randomly generated (high 'randomness' score), which is common in auto-generated phishing domains.",
    "has_https_scheme": "Does not use HTTPS encryption (secure connection) — legitimate sites almost always use HTTPS today.",
    "url_length": "The overall link is quite long, which slightly raises suspicion in the model.",
    "num_special_chars": "Contains many special characters (@ % = & ?), which can be normal for search links but is also used in obfuscation.",
}

VERDICT_GLOSSARY = {
    "SECURE PLATFORM": "Very low risk AND uses HTTPS AND no IP address AND not a shortened link. The strictest, most confident 'safe' label.",
    "LOW RISK": "Nothing significantly suspicious was found, but it didn't meet every condition for the top 'Secure Platform' badge.",
    "SUSPICIOUS": "Some red flags were found. Worth a second look before entering any personal information or credentials.",
    "HIGH RISK / LIKELY PHISHING": "Multiple strong red flags were found across the models. Avoid entering any information on this link.",
}

MODEL_GLOSSARY = {
    "Random Forest": "A machine-learning model that looks at structural clues in the link (length, hyphens, IP usage, etc.) and votes on how suspicious the pattern looks.",
    "Character-CNN": "A deep-learning model that reads the URL letter by letter, catching sneaky lookalike spellings a rule list would miss (e.g. 'paypa1' vs 'paypal').",
    "Heuristic score": "Simple, transparent yes/no rule checks (Is it HTTPS? Is it a raw IP? etc.) — the most explainable of the three signals.",
}
