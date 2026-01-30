# PhishLens – Suspicious URL Analyzer

PhishLens is a small, portfolio-ready Python CLI tool that scores URLs for phishing risk using **static, explainable heuristics** (no external lookups). It’s designed to be easy to demo in interviews for **Threat Intelligence / Security Analyst** roles.

> ⚠️ Learning/demo tool: heuristic detection can produce false positives/negatives. Not production-grade.

---

## Features

- Reads a text file of URLs (one per line)
- Applies common phishing indicators (TLDs, IP hostnames, `@` obfuscation, long URLs, lookalike domains, etc.)
- Produces an **analyst-friendly triage table** (high risk first)
- Exports a **CSV report** with machine-friendly indicator codes

---

## What it checks (indicators)

PhishLens uses a transparent scoring model based on indicators such as:

- **Suspicious TLDs** (e.g., `.xyz`, `.top`, `.click`, `.ru`, etc.)
- **IP address in hostname** (e.g., `http://185.199.109.153/login`)
- **`@` in URL** (classic obfuscation trick)
- **Excessive subdomains** (deep nested subdomains)
- **Very long URLs** (over a configurable length)
- **Possible brand impersonation** (brand-like keywords + “junk” patterns)
- **URL shorteners** (e.g., `tinyurl.com`, `bit.ly`)
- **Punycode / IDN hints** (`xn--`)
- **Non-HTTPS scheme** (basic signal)

All lists, weights, and thresholds are configurable at the top of the script.

---

## Installation

### Requirements
- Python 3.x
- Standard library only (no dependencies)

### Get the code
Clone the repo or download it, then run:

~~~bash
python phishlens.py --help
~~~

---

## Usage

### Analyze a URL list (one URL per line)
~~~bash
python phishlens.py --input sample_data/urls.txt
~~~

### Write a CSV report to a custom output path
~~~bash
python phishlens.py --input sample_data/urls.txt --output phishlens_report.csv
~~~

---

## Input format

Input file is plain text with **one URL per line**, for example:

~~~text
https://accounts.google.com/signin/v2/identifier
http://192.168.1.10/login
https://secure-paypal-login.xyz/account/verify
~~~

Notes:
- Blank lines are ignored
- Obvious junk lines are skipped and counted

---

## Example console output

PhishLens prints a “triage view” that groups **high risk first**, then **medium**, then **low**:

~~~text
PhishLens Report (triage view)

RISK   SCORE URL                                                              INDICATORS
----------------------------------------------------------------------------------------
high   65    https://secure-paypal-login.xyz/account/verify                    TLD is in suspicious list (.xyz); Possible brand impersonation pattern
medium 25    https://tinyurl.com/2p8k9m3x                                      Known URL shortener domain
low    0     https://www.google.com/search?q=phishing+indicators               -
~~~

**Fields**
- **RISK**: `high`, `medium`, `low`
- **SCORE**: total points from triggered indicators
- **URL**: original input URL (may be truncated for readability)
- **INDICATORS**: human-readable summaries (console)

---

## CSV report

PhishLens writes a CSV file (default: `phishlens_report.csv`) with columns:

- `url`
- `hostname`
- `tld`
- `risk_score`
- `risk_level`
- `indicator_codes`

`indicator_codes` is a comma-separated list of machine-friendly codes like:
- `SUSPICIOUS_TLD`
- `IP_IN_URL`
- `AT_SYMBOL`
- `EXCESSIVE_SUBDOMAINS`
- `LONG_URL`
- `BRAND_IMPERSONATION`
- `URL_SHORTENER`
- `PUNYCODE_IDN`
- `NO_HTTPS`

---

## Tuning & customization

Open `phishlens.py` and edit the config section at the top:
- suspicious TLD list
- brand keywords
- URL shorteners
- scoring weights
- risk thresholds

This makes it easy to demonstrate “why” a URL scored the way it did.

---

## Limitations

- No real-time OSINT enrichment (no WHOIS, DNS, certificate checks, threat feeds, VirusTotal)
- Static heuristics only
- False positives/negatives are expected

---

## Future improvements

- Add enrichment (WHOIS/domain age, DNS, TLS/cert signals, threat intel feeds)
- Add JSON output (for SIEM pipelines)
- Add allowlists/denylists and deduplication
- Add unit tests + CI (GitHub Actions)
- Optional UI (small web dashboard)

---

## Disclaimer

For educational and portfolio demonstration purposes only. Do not use as the sole basis for security decisions.

