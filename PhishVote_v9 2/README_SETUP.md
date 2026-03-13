# PhishVote v8 — Setup Guide
## All 30 Features Now Active

---

## ✅ What's New in v8

| Feature | v7 Status | v8 Status | Importance |
|---|---|---|---|
| AgeofDomain | ⬜ Always neutral | ✅ WHOIS XML API | 1.54% |
| DNSRecording | ⬜ Always neutral | ✅ WHOIS XML API | 1.19% |
| DomainRegLen | 🟡 TLD heuristic | ✅ WHOIS XML API (real expiry) | 1.61% |
| AbnormalURL | 🟡 Regex heuristic | ✅ WHOIS XML API (real hostname) | 0.39% |
| **WebsiteTraffic** | ⬜ Always neutral | ✅ **Tranco list (local)** | **8.11%** |
| PageRank | ⬜ Always neutral | ✅ Open PageRank API | 1.15% |
| GoogleIndex | ⬜ Always neutral | ✅ Google Custom Search API | 1.23% |
| LinksPointingToPage | ⬜ Always neutral | ✅ HackerTarget API (free, no key) | 1.96% |
| StatsReport | ⬜ Always neutral | ✅ VirusTotal API | 0.47% |

**Total importance weight now active: ~99.6%** (was ~82% in v7)

---

## 📋 Step-by-Step Setup

### Step 1 — Get Your Free API Keys

You need **4 free accounts**. HackerTarget needs no account at all.

#### A. WHOIS XML API (500 free lookups/month)
1. Go to **https://www.whoisxmlapi.com**
2. Click **Sign Up Free**
3. Verify your email
4. Go to **My Products → API Key**
5. Copy your key → this is your `WHOIS_XML_KEY`

#### B. Open PageRank (1,000 free lookups/day)
1. Go to **https://www.domcop.com/openpagerank**
2. Click **Get Free API Key**
3. Fill in the form, verify email
4. Copy your key → this is your `OPENPAGERANK_KEY`

#### C. Google Custom Search (100 free queries/day)
This one has two parts — an API key and a Search Engine ID (cx).

**Part 1 — API Key:**
1. Go to **https://console.developers.google.com**
2. Create a new project (or use existing)
3. Go to **APIs & Services → Library**
4. Search for **Custom Search API** → Enable it
5. Go to **APIs & Services → Credentials → Create Credentials → API Key**
6. Copy your key → this is your `GOOGLE_CSE_KEY`

**Part 2 — Search Engine ID:**
1. Go to **https://programmablesearchengine.google.com**
2. Click **Add** → Create a new search engine
3. In "Sites to search" type `*.com` (we'll override this with site: queries)
4. Click **Create** → then **Control Panel**
5. Copy the **Search engine ID** → this is your `GOOGLE_CSE_CX`

#### D. VirusTotal (500 free lookups/day)
1. Go to **https://www.virustotal.com/gui/join-us**
2. Register a free account
3. Go to your **profile icon → API Key**
4. Copy your key → this is your `VIRUSTOTAL_KEY`

#### E. HackerTarget (100 free lookups/day)
✅ **No account needed.** Works immediately.

---

### Step 2 — Download the Tranco List (WebsiteTraffic feature)

The Tranco list is a free academic replacement for the defunct Alexa rank.
It's a local file so it works offline and has no rate limit.

**Option A — Automatic (recommended):**
```bash
cd PhishVote_v8/data/
python3 build_tranco.py
```
This downloads and converts the list automatically (~8 MB, takes ~30 seconds).

**Option B — Manual:**
1. Go to **https://tranco-list.eu**
2. Click **Download** → **Top 1 million**
3. Unzip the file — you get `top-1m.csv`
4. Place `top-1m.csv` inside `PhishVote_v8/data/`
5. Run: `python3 build_tranco.py`

After running, you'll see `tranco.json` appear in the `data/` folder (~8 MB).

---

### Step 3 — Enter Your API Keys into the Extension

1. Install the extension (see Step 4 below)
2. Click the PhishVote badge in your toolbar
3. Click the **⚙ Settings** button at the bottom of the popup
4. Enter each API key in the fields provided
5. Click **Save Keys**

Your keys are stored locally in `chrome.storage.local` — never sent anywhere except the respective APIs.

---

### Step 4 — Install the Extension

1. Open Chrome → go to **chrome://extensions**
2. Enable **Developer Mode** (toggle, top right)
3. Click **Load unpacked**
4. Select the **PhishVote_v8** folder
5. Done — the PhishVote badge appears in your toolbar

---

### Step 5 — Update Your Python Script (domain_features.py)

Create a `config.py` file next to `domain_features.py`:

```python
# config.py — place in same folder as domain_features.py
WHOIS_XML_KEY    = "paste_your_key_here"
OPENPAGERANK_KEY = "paste_your_key_here"
GOOGLE_CSE_KEY   = "paste_your_key_here"
GOOGLE_CSE_CX    = "paste_your_cx_here"
VIRUSTOTAL_KEY   = "paste_your_key_here"
TRANCO_CSV_PATH  = "data/tranco.csv"   # path to your downloaded CSV
```

Then test it:
```bash
python3 domain_features.py
```

---

## 📁 Final Folder Structure

```
PhishVote_v8/
├── manifest.json
├── engine.js           ← all 30 features + API fetch logic
├── background.js       ← 3-pass pipeline (URL → DOM → APIs)
├── popup.html / popup.js
├── detail.html / detail.js
├── icons/
├── models/
│   └── phishvote_model_dsbase.json
└── data/
    ├── tranco.json          ← ✅ YOU GENERATE THIS (build_tranco.py)
    ├── build_tranco.py      ← run once to build tranco.json
    └── domain_features.py  ← updated Python script (for your notebook)
```

---

## ⚡ How the 3-Pass Pipeline Works

When you visit a page, PhishVote runs in 3 stages:

| Pass | What runs | Badge |
|---|---|---|
| **Pass 1** (~5ms) | URL analysis only — 13 instant features | Shows immediately |
| **Pass 2** (~1-2s) | DOM scan — 11 page features | Updates badge |
| **Pass 3** (~3-8s) | All 5 API calls in parallel | Final badge + alert banner |

If you have no API keys entered, Pass 3 gracefully skips those features and the extension still works using Passes 1 and 2 (same as v7).

---

## 💡 Daily Limits Summary

| Service | Free Limit | Resets |
|---|---|---|
| WHOIS XML API | 500/month | Monthly |
| Open PageRank | 1,000/day | Daily midnight UTC |
| Google Custom Search | 100/day | Daily midnight PT |
| HackerTarget | 100/day | Daily |
| VirusTotal | 500/day | Daily midnight UTC |
| **Tranco** | **Unlimited** | **Local file, no limit** |

For normal personal use (< 100 sites/day) all free tiers are sufficient.
