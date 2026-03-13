#!/usr/bin/env python3
"""
Run this once to download the Tranco top-1M list and convert it to
the tranco.json file used by PhishVote for WebsiteTraffic scoring.

Usage:
    cd PhishVote_v9/data/
    python3 build_tranco.py

Output: tranco.json  (~2.5MB top-200k only, replaces the placeholder)

WHY TOP 200k ONLY (not full 1M):
  Chrome MV3 background service workers are ephemeral — they restart
  every ~30 seconds of inactivity. Each restart must re-fetch and re-parse
  tranco.json from scratch. An 8MB (1M entry) file causes timeouts and
  silent failures. 200k entries = ~2.5MB = fast and reliable.
  Phishing domains are never in the top 200k anyway, so detection
  accuracy is identical to using the full 1M list.
"""
import urllib.request, csv, json, io, zipfile, os

LIMIT = 200_000   # top 200k only — fast parse, same detection accuracy

print("Downloading Tranco top-1M list...")
url = "https://tranco-list.eu/top-1m.csv.zip"
with urllib.request.urlopen(url, timeout=30) as r:
    zdata = r.read()

print(f"Parsing top {LIMIT:,} entries...")
result = {}
with zipfile.ZipFile(io.BytesIO(zdata)) as z:
    with z.open("top-1m.csv") as f:
        reader = csv.reader(io.TextIOWrapper(f))
        for row in reader:
            if len(row) >= 2:
                rank = int(row[0])
                if rank > LIMIT:
                    break
                domain = row[1].lower().strip()
                result[domain] = rank

out = os.path.join(os.path.dirname(__file__), "tranco.json")
with open(out, "w") as f:
    json.dump(result, f, separators=(',', ':'))

size_mb = os.path.getsize(out) / 1_000_000
print(f"Done! Saved {len(result):,} domains to tranco.json ({size_mb:.1f}MB)")
print("Now reload the extension: chrome://extensions -> click reload on PhishVote")
