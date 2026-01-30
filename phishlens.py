"""
PhishLens
---------

Lightweight phishing URL heuristic analyzer.

Designed for blue-team signal enrichment, SOC triage,
and security automation pipelines.
"""

from urllib.parse import urlparse
import re


SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "country", "stream", "gq", "work", "top"
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "ow.ly",
}


def normalize_for_parse(url: str) -> str:
    """Ensure URL has a scheme so urlparse behaves correctly."""
    if not re.match(r"^[a-zA-Z]+://", url):
        return "http://" + url
    return url


def is_ip_address(hostname: str) -> bool:
    """Detect raw IPv4 addresses used as hostnames."""
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname))


def has_suspicious_tld(hostname: str) -> bool:
    """Check for uncommon or abuse-prone TLDs."""
    parts = hostname.split(".")
    return len(parts) > 1 and parts[-1] in SUSPICIOUS_TLDS


def has_excessive_subdomains(hostname: str, threshold: int = 3) -> bool:
    """Flag domains with unusually deep subdomain nesting."""
    return hostname.count(".") >= threshold


def is_url_shortener(hostname: str) -> bool:
    """Detect known URL shortening services."""
    return hostname.lower() in URL_SHORTENERS


def is_punycode(hostname: str) -> bool:
    """Detect IDN homograph attack indicators."""
    return hostname.startswith("xn--")


def possible_brand_impersonation(hostname: str) -> bool:
    """
    Detect brand impersonation via keywords combined with
    suspicious domain structure.
    """
    brands = {"paypal", "apple", "google", "microsoft", "amazon"}
    for brand in brands:
        if brand in hostname and not hostname.endswith(f"{brand}.com"):
            return True
    return False


def evaluate_indicators(url: str) -> dict:
    """Run all heuristics and return indicator results."""
    parsed = urlparse(normalize_for_parse(url))
    hostname = parsed.hostname or ""

    return {
        "ip_address": is_ip_address(hostname),
        "suspicious_tld": has_suspicious_tld(hostname),
        "excessive_subdomains": has_excessive_subdomains(hostname),
        "url_shortener": is_url_shortener(hostname),
        "punycode": is_punycode(hostname),
        "brand_impersonation": possible_brand_impersonation(hostname),
    }


def analyze_url(url: str) -> dict:
    """
    Primary analysis entrypoint.
    Returns indicators and a simple risk score.
    """
    indicators = evaluate_indicators(url)
    score = sum(indicators.values())

    return {
        "url": url,
        "score": score,
        "indicators": indicators,
    }
