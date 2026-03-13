"""
domain_features.py — PhishVote v8
All 9 domain/external features now REAL (no hardcoded placeholders).

Requires API keys in a config.py file next to this script:
    WHOIS_XML_KEY      = "your_key_here"   # whoisxmlapi.com — 500 free/month
    OPENPAGERANK_KEY   = "your_key_here"   # domcop.com/openpagerank — 1000 free/day
    GOOGLE_CSE_KEY     = "your_key_here"   # googleapis.com — 100 free/day
    GOOGLE_CSE_CX      = "your_cx_here"    # your Custom Search Engine ID
    VIRUSTOTAL_KEY     = "your_key_here"   # virustotal.com — 500 free/day
    TRANCO_CSV_PATH    = "tranco.csv"      # downloaded from tranco-list.eu
"""

import whois
import requests
import csv
import json
import time
import base64
import os
from datetime import datetime
from urllib.parse import urlparse

# ── Load config ───────────────────────────────────────────────────────────────
try:
    from config import (
        WHOIS_XML_KEY, OPENPAGERANK_KEY,
        GOOGLE_CSE_KEY, GOOGLE_CSE_CX,
        VIRUSTOTAL_KEY, TRANCO_CSV_PATH
    )
except ImportError:
    WHOIS_XML_KEY = OPENPAGERANK_KEY = ""
    GOOGLE_CSE_KEY = GOOGLE_CSE_CX = ""
    VIRUSTOTAL_KEY = ""
    TRANCO_CSV_PATH = "tranco.csv"

# ── Tranco rank lookup (loaded once into memory) ──────────────────────────────
_tranco_ranks = None

def _load_tranco():
    global _tranco_ranks
    if _tranco_ranks is not None:
        return _tranco_ranks
    _tranco_ranks = {}
    if not os.path.exists(TRANCO_CSV_PATH):
        print(f"[WARN] Tranco CSV not found at '{TRANCO_CSV_PATH}'. WebsiteTraffic will be neutral.")
        return _tranco_ranks
    with open(TRANCO_CSV_PATH, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                try:
                    _tranco_ranks[row[1].lower().strip()] = int(row[0])
                except ValueError:
                    pass
    print(f"[INFO] Loaded {len(_tranco_ranks):,} domains from Tranco list.")
    return _tranco_ranks


def get_domain(url):
    """Extract clean domain for WHOIS lookups."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc if parsed.netloc else parsed.path.split('/')[0]
        if domain.startswith("www."):
            domain = domain[4:]
        # Strip port if present
        domain = domain.split(':')[0]
        return domain.lower()
    except:
        return ""


def get_root_domain(domain):
    """Extract root domain (last two parts) from a full domain."""
    parts = domain.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else domain


def extract_domain_features(url):
    """
    Returns ordered list of 9 domain/external features matching UCI-2015:
    [age_of_domain, DNSRecord, Domain_registeration_length, Abnormal_URL,
     web_traffic, Page_Rank, Google_Index, Links_pointing_to_page, Statistical_report]

    Values: -1 = phishing signal, 0 = neutral/unknown, 1 = legitimate signal
    """
    domain = get_domain(url)

    # Defaults — neutral (0) if we can't determine, not -1
    # Using 0 so neutral features don't drag the score unfairly
    features = {
        "age_of_domain":            0,
        "DNSRecord":                0,
        "Domain_registeration_length": 0,
        "Abnormal_URL":             0,
        "web_traffic":              0,
        "Page_Rank":                0,
        "Google_Index":             0,
        "Links_pointing_to_page":   0,
        "Statistical_report":       0,
    }

    # ── 1-4: WHOIS XML API ────────────────────────────────────────────────────
    # Covers: age_of_domain, DNSRecord, Domain_registeration_length, Abnormal_URL
    # Free: 500 requests/month — https://www.whoisxmlapi.com
    if WHOIS_XML_KEY:
        try:
            r = requests.get(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    "apiKey":      WHOIS_XML_KEY,
                    "domainName":  domain,
                    "outputFormat":"JSON"
                },
                timeout=7
            )
            d = r.json()
            rec = d.get("WhoisRecord", {})
            reg = rec.get("registryData", rec)

            # 1. DNSRecord — domain exists in WHOIS = legitimate
            features["DNSRecord"] = 1 if rec.get("domainName") else -1

            # 2. AgeofDomain — created >= 6 months ago = legitimate
            created = reg.get("createdDateNormalized") or reg.get("createdDate", "")
            if created:
                age_days = (datetime.now() - datetime.fromisoformat(created[:10])).days
                features["age_of_domain"] = 1 if age_days >= 180 else -1
            else:
                features["age_of_domain"] = -1

            # 3. DomainRegistrationLength — expires > 365 days = legitimate
            expires = reg.get("expiresDateNormalized") or reg.get("expiresDate", "")
            if expires:
                days_left = (datetime.fromisoformat(expires[:10]) - datetime.now()).days
                features["Domain_registeration_length"] = 1 if days_left > 365 else -1
            else:
                features["Domain_registeration_length"] = -1

            # 4. AbnormalURL — WHOIS hostname matches domain in URL = legitimate
            whois_name = (reg.get("domainName") or rec.get("domainName") or "").lower()
            if whois_name:
                root = get_root_domain(domain)
                features["Abnormal_URL"] = 1 if root in whois_name or whois_name in root else -1
            else:
                features["Abnormal_URL"] = -1

        except Exception as e:
            print(f"[WARN] WHOIS XML API error: {e}")
            # Fall back to python-whois as backup
            try:
                info = whois.whois(domain)
                features["DNSRecord"] = 1 if info.domain_name else -1
                cd = info.creation_date
                if isinstance(cd, list): cd = cd[0]
                if cd:
                    age_months = (datetime.now() - cd).days / 30
                    features["age_of_domain"] = 1 if age_months >= 6 else -1
                ed = info.expiration_date
                if isinstance(ed, list): ed = ed[0]
                if ed:
                    days_left = (ed - datetime.now()).days
                    features["Domain_registeration_length"] = 1 if days_left > 365 else -1
                hn = info.domain_name
                if isinstance(hn, list): hn = hn[0]
                if hn:
                    features["Abnormal_URL"] = 1 if hn.lower() in domain else -1
            except:
                pass

    # ── 5: WebsiteTraffic — Tranco top-1M list ───────────────────────────────
    # Free, no API key — download CSV from https://tranco-list.eu
    # Rule: rank <= 100,000 = 1, rank <= 1,000,000 = 0, not listed = -1
    try:
        ranks = _load_tranco()
        root = get_root_domain(domain)
        rank = ranks.get(domain) or ranks.get(root) or None
        if rank is None:
            features["web_traffic"] = -1
        elif rank <= 100000:
            features["web_traffic"] = 1
        else:
            features["web_traffic"] = 0
    except Exception as e:
        print(f"[WARN] Tranco lookup error: {e}")

    # ── 6: PageRank — Open PageRank API ──────────────────────────────────────
    # Free: 1000 requests/day — https://www.domcop.com/openpagerank
    # Rule: page_rank_decimal < 0.2 = -1, else = 1
    if OPENPAGERANK_KEY:
        try:
            r = requests.get(
                "https://openpagerank.com/api/v1.0/getPageRank",
                params={"domains[]": domain},
                headers={"API-OPR": OPENPAGERANK_KEY},
                timeout=5
            )
            data = r.json()
            pr = data.get("response", [{}])[0].get("page_rank_decimal")
            if pr is not None:
                features["Page_Rank"] = 1 if float(pr) >= 0.2 else -1
        except Exception as e:
            print(f"[WARN] Open PageRank API error: {e}")

    # ── 7: GoogleIndex — Google Custom Search API ─────────────────────────────
    # Free: 100 queries/day — https://programmablesearchengine.google.com
    # Rule: site is indexed = 1, not indexed = -1
    if GOOGLE_CSE_KEY and GOOGLE_CSE_CX:
        try:
            r = requests.get(
                "https://www.googleapis.com/customsearch/v1",
                params={
                    "key": GOOGLE_CSE_KEY,
                    "cx":  GOOGLE_CSE_CX,
                    "q":   f"site:{domain}",
                    "num": 1
                },
                timeout=5
            )
            data = r.json()
            total = int(data.get("searchInformation", {}).get("totalResults", "0"))
            features["Google_Index"] = 1 if total > 0 else -1
        except Exception as e:
            print(f"[WARN] Google Index API error: {e}")

    # ── 8: LinksPointingToPage — HackerTarget API ─────────────────────────────
    # Free: 100 requests/day, NO API KEY NEEDED
    # https://hackertarget.com/pagelinks-lookup/
    # Rule: 0 links = -1, 1-2 = 0, >2 = 1
    try:
        r = requests.get(
            f"https://api.hackertarget.com/pagelinks/?q={url}",
            timeout=7
        )
        text = r.text.strip()
        if "error" in text.lower() or "api count exceeded" in text.lower():
            features["Links_pointing_to_page"] = 0  # rate-limited, stay neutral
        else:
            links = [l for l in text.split('\n') if l.strip()]
            if len(links) == 0:
                features["Links_pointing_to_page"] = -1
            elif len(links) <= 2:
                features["Links_pointing_to_page"] = 0
            else:
                features["Links_pointing_to_page"] = 1
    except Exception as e:
        print(f"[WARN] HackerTarget API error: {e}")

    # ── 9: StatsReport — VirusTotal API ──────────────────────────────────────
    # Free: 500 requests/day — https://www.virustotal.com/gui/join-us
    # Rule: any engine flags malicious = -1, clean = 1
    if VIRUSTOTAL_KEY:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VIRUSTOTAL_KEY},
                timeout=8
            )
            if r.status_code == 404:
                # Submit URL for scanning, return neutral this time
                requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": VIRUSTOTAL_KEY},
                    data={"url": url},
                    timeout=5
                )
                features["Statistical_report"] = 0  # pending analysis
            elif r.status_code == 200:
                stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                features["Statistical_report"] = -1 if stats.get("malicious", 0) > 0 else 1
        except Exception as e:
            print(f"[WARN] VirusTotal API error: {e}")

    # Return as ordered list matching UCI-2015 / main.py column order
    return [
        features["age_of_domain"],
        features["DNSRecord"],
        features["Domain_registeration_length"],
        features["Abnormal_URL"],
        features["web_traffic"],
        features["Page_Rank"],
        features["Google_Index"],
        features["Links_pointing_to_page"],
        features["Statistical_report"],
    ]


# ── Test script ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    test_url = "https://www.github.com"
    print(f"\nQuerying all APIs for: {test_url}\n{'='*50}")

    result = extract_domain_features(test_url)

    names = [
        "age_of_domain", "DNSRecord", "Domain_registeration_length", "Abnormal_URL",
        "web_traffic", "Page_Rank", "Google_Index",
        "Links_pointing_to_page", "Statistical_report"
    ]
    labels = { 1: "✅ Legit", 0: "⬜ Neutral", -1: "🚨 Phishing" }

    print(f"\n{'Feature':<30} {'Value':>6}  {'Meaning'}")
    print("-" * 55)
    for name, val in zip(names, result):
        print(f"{name:<30} {val:>6}  {labels.get(val, '?')}")
    print(f"\nOutput array: {result}")
