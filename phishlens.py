#!/usr/bin/env python3
"""
PhishLens - Suspicious URL Analyzer (Analyst-friendly)

Static heuristics only. No external lookups.
Input: text file with one URL per line.
Output: console triage table + CSV report.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
from dataclasses import dataclass
from typing import List, Tuple
from urllib.parse import urlsplit


# =============================================================================
# Configuration (tweak here)
# =============================================================================

CONFIG = {
    "suspicious_tlds": {
        ".xyz", ".top", ".click", ".link", ".ru", ".cn", ".tk", ".gq", ".ml", ".cf",
        ".work", ".support", ".zip", ".mov",
    },
    "brand_keywords": {
        "paypal", "bank", "secure", "login", "verify", "account", "meta", "metamask",
    },
    "url_shorteners": {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
    },

    "long_url_threshold": 100,
    "max_domain_labels": 4,

    "score_weights": {
        "SUSPICIOUS_TLD": 25,
        "IP_IN_URL": 35,
        "AT_SYMBOL": 20,
        "EXCESSIVE_SUBDOMAINS": 15,
        "LONG_URL": 10,
        "BRAND_IMPERSONATION": 25,
        "URL_SHORTENER": 15,
        "PUNYCODE_IDN": 15,
        "NO_HTTPS": 5,
    },

    "risk_thresholds": {
        "low_max": 24,
        "medium_max": 59,  # 60+ => high
    },
}

INDICATOR_DESCRIPTIONS = {
    "SUSPICIOUS_TLD": "TLD is in suspicious list",
    "IP_IN_URL": "Hostname is an IP address",
    "AT_SYMBOL": "Contains '@' (possible obfuscation)",
    "EXCESSIVE_SUBDOMAINS": "Excessive subdomain depth",
    "LONG_URL": "URL length exceeds threshold",
    "BRAND_IMPERSONATION": "Possible brand impersonation pattern",
    "URL_SHORTENER": "Known URL shortener domain",
    "PUNYCODE_IDN": "Contains punycode (xn--) / possible IDN trick",
    "NO_HTTPS": "Not using HTTPS scheme",
}


# =============================================================================
# Data model
# =============================================================================

@dataclass
class Finding:
    url: str
    hostname: str
    tld: str
    risk_score: int
    risk_level: str
    indicator_codes: List[str]
    indicator_summaries: List[str]


# =============================================================================
# CLI / IO
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="PhishLens – Suspicious URL Analyzer (static heuristics; no external lookups).",
    )
    parser.add_argument("--input", required=True, help="Path to input text file containing one URL per line.")
    parser.add_argument("--output", default="phishlens_report.csv", help="Path to output CSV report.")
    return parser.parse_args()


def load_urls(path: str) -> Tuple[List[str], int]:
    """Return (urls, junk_count)."""
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    urls: List[str] = []
    junk = 0
    for ln in lines:
        s = ln.strip()
        if not s:
            junk += 1
            continue
        if " " in s or len(s) < 4:
            junk += 1
            continue
        urls.append(s)
    return urls, junk


# =============================================================================
# URL helpers
# =============================================================================

def normalize_for_parse(raw: str) -> str:
    s = raw.strip()
    if not s:
        return s
    parts = urlsplit(s)
    if parts.scheme and (parts.netloc or parts.hostname):
        return s
    return "http://" + s


def get_hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def get_tld(hostname: str) -> str:
    if not hostname or "." not in hostname:
        return ""
    return "." + hostname.rsplit(".", 1)[-1]


def is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def has_excessive_subdomains(hostname: str) -> bool:
    if not hostname or "." not in hostname:
        return False
    labels = [p for p in hostname.split(".") if p]
    return len(labels) > CONFIG["max_domain_labels"]


def has_suspicious_tld(hostname: str) -> bool:
    return any(hostname.endswith(tld) for tld in CONFIG["suspicious_tlds"])


def possible_brand_impersonation(hostname: str) -> bool:
    if not hostname or "." not in hostname:
        return False

    host = hostname[4:] if hostname.startswith("www.") else hostname
    if not any(b in host for b in CONFIG["brand_keywords"]):
        return False

    has_digits = bool(re.search(r"\d", host))
    hyphen_count = host.count("-")
    token_count = len(re.split(r"[-.]", host))
    return has_digits or hyphen_count >= 2 or token_count >= 6


def is_url_shortener(hostname: str) -> bool:
    return hostname in CONFIG["url_shorteners"]


def is_punycode(hostname: str) -> bool:
    return "xn--" in hostname


def is_not_https(normalized_url: str) -> bool:
    parsed = urlsplit(normalized_url)
    return bool(parsed.scheme) and parsed.scheme.lower() != "https"


# =============================================================================
# Analysis + scoring
# =============================================================================

def score_indicators(codes: List[str]) -> int:
    weights = CONFIG["score_weights"]
    return sum(weights.get(c, 0) for c in codes)


def classify_risk(score: int) -> str:
    low_max = CONFIG["risk_thresholds"]["low_max"]
    med_max = CONFIG["risk_thresholds"]["medium_max"]
    if score <= low_max:
        return "low"
    if score <= med_max:
        return "medium"
    return "high"


def analyze_url(raw_url: str) -> Finding:
    codes: List[str] = []
    summaries: List[str] = []

    normalized = normalize_for_parse(raw_url)
    hostname = get_hostname(normalized)
    tld = get_tld(hostname)

    def add(code: str, detail: str | None = None) -> None:
        codes.append(code)
        base = INDICATOR_DESCRIPTIONS.get(code, code)
        summaries.append(f"{base} ({detail})" if detail else base)

    if "@" in raw_url:
        add("AT_SYMBOL")

    if hostname and is_ip_address(hostname):
        add("IP_IN_URL")

    if has_excessive_subdomains(hostname):
        labels = len([p for p in hostname.split(".") if p])
        add("EXCESSIVE_SUBDOMAINS", f"{labels} labels")

    if len(raw_url) > CONFIG["long_url_threshold"]:
        add("LONG_URL", f"len={len(raw_url)}")

    if hostname and has_suspicious_tld(hostname) and tld:
        add("SUSPICIOUS_TLD", tld)

    if hostname and is_url_shortener(hostname):
        add("URL_SHORTENER")

    if hostname and is_punycode(hostname):
        add("PUNYCODE_IDN")

    if is_not_https(normalized):
        add("NO_HTTPS", urlsplit(normalized).scheme.lower())

    if possible_brand_impersonation(hostname):
        add("BRAND_IMPERSONATION")

    score = score_indicators(codes)
    level = classify_risk(score)

    return Finding(
        url=raw_url,
        hostname=hostname,
        tld=tld,
        risk_score=score,
        risk_level=level,
        indicator_codes=codes,
        indicator_summaries=summaries,
    )


# =============================================================================
# Reporting
# =============================================================================

def risk_sort_key(level: str) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(level, 3)


def print_console(findings: List[Finding]) -> None:
    findings = sorted(findings, key=lambda f: (risk_sort_key(f.risk_level), -f.risk_score, f.hostname))

    print("\nPhishLens Report (triage view)\n")
    header = f"{'RISK':<6} {'SCORE':<5} {'URL':<64} INDICATORS"
    print(header)
    print("-" * len(header))

    for f in findings:
        url_disp = (f.url[:63] + "…") if len(f.url) > 64 else f.url
        ind = "; ".join(f.indicator_summaries) if f.indicator_summaries else "-"
        if len(ind) > 70:
            ind = ind[:69] + "…"
        print(f"{f.risk_level:<6} {f.risk_score:<5} {url_disp:<64} {ind}")

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.risk_level] = counts.get(f.risk_level, 0) + 1
    print(f"\nSummary: high={counts['high']} medium={counts['medium']} low={counts['low']}\n")


def write_csv(findings: List[Finding], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["url", "hostname", "tld", "risk_score", "risk_level", "indicator_codes"],
        )
        w.writeheader()
        for fnd in findings:
            w.writerow({
                "url": fnd.url,
                "hostname": fnd.hostname,
                "tld": fnd.tld,
                "risk_score": fnd.risk_score,
                "risk_level": fnd.risk_level,
                "indicator_codes": ",".join(fnd.indicator_codes),
            })


def main() -> int:
    args = parse_args()

    try:
        urls, junk = load_urls(args.input)
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input}")
        return 2

    if not urls:
        msg = "Input file contains no valid URLs."
        if junk:
            msg += f" (Ignored {junk} blank/junk lines.)"
        print(msg)
        return 2

    findings = [analyze_url(u) for u in urls]
    print_console(findings)
    write_csv(findings, args.output)

    if junk:
        print(f"Note: ignored {junk} blank/junk lines from input.")
    print(f"CSV report written to: {args.output}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
