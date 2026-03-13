# PhishVote — Browser Extension v7

**Real-time phishing detection powered by the PhishVote research model**
Duhaylungsod & Dumalogdog · University of Mindanao
UCI-2015 Dataset · 30 Heuristic Features · RF + XGBoost + CatBoost + LightGBM + Gradient Boosting

---

## What This Is

PhishVote is a Google Chrome extension that deploys the trained machine learning model from the paper *PhishVote: An Adaptive Soft-Voting Ensemble of Gradient-Boosted Classifiers for Phishing Website Detection*. It runs silently on every webpage you visit, evaluating the same 30 heuristic features used during model training and testing, then classifies the page as phishing or legitimate using the model's threshold of **θ = 0.5**.

Every design decision in this extension — which features are evaluated, the importance weights assigned to each, the classification threshold, the five base classifiers and their contribution weights — comes directly from the paper's trained model and published results.

---

## Quick Stats

| Property | Value |
|---|---|
| Paper accuracy | 97.42% on UCI-2015 held-out test set |
| Dataset | UCI Phishing Websites (Mohammad et al., 2015) — 11,054 records |
| Features | 30 ternary features {−1, 0, +1} |
| Classification threshold | θ = 0.5 |
| Baseline beat | Saeed (2025) Hard Voting at 95.02% |
| Chrome Manifest | Version 3 (MV3) |

---

## Installation

1. Unzip `PhishVote_v7.zip` to a local folder
2. Open Chrome and go to `chrome://extensions`
3. Enable **Developer mode** (toggle top-right)
4. Click **Load unpacked** → select the `PhishVote_v7` folder
5. The 🛡️ PhishVote icon appears in the toolbar — you're done

> **After editing any source file:** click the ↺ refresh icon on the PhishVote card at `chrome://extensions` to reload.

---

## How It Works — The Two-Pass Pipeline

Every time a page finishes loading, the extension runs a two-pass analysis pipeline entirely in the background. No scanning banner appears while analysis is running — the page stays completely undisturbed. An alert only appears **after** the full scan completes, and **only** if the page is flagged.

### Pass 1 — Instant URL Scoring (< 5 ms)

As soon as the tab URL is available, `extractURLFeatures(url)` in `engine.js` evaluates the **13 features computable from the URL string alone**. A preliminary score is calculated immediately and the toolbar badge is updated.

These 13 URL features fire with zero network calls and zero page interaction:

| Feature | What it checks |
|---|---|
| `UsingIP` | Raw IPv4 address in hostname (e.g. `192.168.1.1/login.php`) |
| `LongURL` | URL length — phishing URLs average longer than legitimate ones |
| `ShortURL` | Domain matches known shortener list (bit.ly, t.co, tinyurl, etc.) |
| `Symbol@` | `@` symbol in URL obscures the real destination |
| `Redirecting//` | Double-slash in path triggers redirect tricks |
| `PrefixSuffix-` | Dash in domain name (e.g. `paypal-secure.com`) |
| `SubDomains` | Subdomain depth — 3+ levels is a strong phishing signal |
| **`HTTPS`** | **SSL state — highest-weight feature at 31.38%** |
| `NonStdPort` | Non-standard port in URL (not 80 or 443) |
| `HTTPSDomainURL` | Literal string "https" embedded in the domain name |
| `InfoEmail` | `mailto:` in URL itself |
| `AbnormalURL` | Embedded FQDN in path (e.g. `/paypal.com/login.php`) |
| `DomainRegLen` | Free or abused TLD (.tk, .ml, .xyz, .top, .icu, etc.) |

### Pass 2 — DOM Scan (parallel with model load)

After the URL pass, `extractPageDOM()` is injected into the live page via `chrome.scripting.executeScript`. This function runs inside the page's own JavaScript context and evaluates the **11 DOM-based features**. The model file is fetched in parallel with the DOM scan so neither blocks the other.

| Feature | What it checks |
|---|---|
| `Favicon` | Whether the favicon loads from a different domain than the page host |
| `RequestURL` | Ratio of externally-hosted embedded resources (img, script, form, audio, video) |
| **`AnchorURL`** | **Ratio of `<a>` links pointing to external domains — 2nd highest weight at 24.10%** |
| `LinksInScriptTags` | Ratio of external script/link/meta tag references |
| `ServerFormHandler` | Whether any form submits data to an external domain or via mailto: |
| `InfoEmail` | Form-based mailto: detection (merged with URL result) |
| `WebsiteForwarding` | Number of HTTP redirects before the page loaded |
| `StatusBarCust` | `window.status` modification on mouseover (link text spoofing) |
| `DisableRightClick` | Context menu disabled via JS or `oncontextmenu` (hides page source) |
| `UsingPopupWindow` | `window.open()` call in page scripts (credential-harvesting popups) |
| `IframeRedirection` | Hidden iframe — zero size or `display:none` (invisible redirect) |

### The 6 Neutral Features

Six features from the UCI-2015 dataset require external APIs that are unavailable in a browser extension context. These always return `0` (neutral) and contribute no signal:

| Feature | Requires |
|---|---|
| `AgeofDomain` | WHOIS API |
| `DNSRecording` | DNS lookup API |
| `WebsiteTraffic` | Alexa/traffic ranking API |
| `PageRank` | Google PageRank API |
| `GoogleIndex` | Google Search API |
| `LinksPointingToPage` | Backlink analysis API |

These 6 features together account for **13.10% of total RF importance weight** that is permanently inactive in the extension. The scoring formula compensates for this via confidence scaling (see below).

### Merging and Scoring

After both passes complete, `mergeFeatures(urlFeats, domFeats)` produces a single 30-element feature vector in UCI-2015 order. This vector is passed to `scoreFeatures(features)`, which computes:

```
P(phish) = (Σ wᵢ × contribution(valᵢ)) / Σ wᵢ

where:
  wᵢ               = RF Gini importance for feature i
  contribution(val) = 1.0 if val = −1 (phishing signal)
                      0.0 if val = +1 (safe signal)
  val = 0 features  → excluded from both numerator and denominator
  confidence        = min(1.0, active_signals / 6)
  final score       = raw × confidence + 0.15 × (1 − confidence)
```

The confidence multiplier prevents sparse data from producing overconfident verdicts. If fewer than 6 features fire, the score is pulled toward a neutral baseline of 0.15.

The result is compared against **θ = 0.5** — the same threshold used in the paper's evaluation. Pages scoring ≥ 0.5 are classified as phishing.

---

## Risk Levels

| P(phish) | Risk Level | In-page Banner | Badge |
|---|---|---|---|
| < 20% | ✅ SAFE | None — completely silent | Green, no text |
| 20%–39% | 🟢 LIKELY SAFE | None — completely silent | Green, no text |
| 40%–49% | ⚠️ SUSPICIOUS | Orange alert banner | Orange `?` |
| 50%–81% | 🚨 PHISHING | Red alert banner | Red `!` |
| ≥ 82% | 🔴 HIGH RISK | Deep red alert banner | Dark red `!` |

**Safe and likely-safe pages produce zero visual output.** The extension is intentionally invisible on clean pages — it only speaks up when something is wrong.

---

## User Interface

### Toolbar Badge
Updates twice per page load: once after the instant URL pass, then again after the DOM scan completes. Color and text encode the final risk level.

### In-Page Alert Banner (phishing/suspicious only)
Slides in from the top of the page **only after the full scan finishes** and **only on flagged pages**. Shows the risk level, phishing probability, and a "View Analysis →" button. Includes an × dismiss button. Safe pages never see this banner.

### Toolbar Popup (click the 🛡️ icon)
Opens a 320px panel showing:
- Scanned URL
- DOM scan status (complete or restricted)
- Verdict card with risk level and P(phish)
- Probability bars for phishing and legitimate
- 28 signal dots (red = phish, green = safe, gray = neutral)
- Signal counts out of 30
- Model attribution line
- View Full Analysis / View Report button
- Copy URL button
- Last 4 scans history

If you open the popup while a scan is still in progress, it shows a scanning state and **polls storage every 400 ms**, automatically updating the display the moment the result arrives (up to 8 seconds).

### Full Analysis Detail Page (opens in new tab)
Loaded by clicking "View Analysis" in the popup or banner. Reads entirely from `chrome.storage.local` — no new network calls are made when opening this page. Contains:

- Full URL display
- DOM scan status bar
- Verdict hero card with badge, risk level, exact probability, and model attribution
- **"Why this verdict" explanation** — plain-language summary naming the top 3 highest-importance features that fired
- Signal summary grid (phishing / safe / neutral counts)
- Risk score probability bars
- **Full 30-feature importance chart** — all features ranked by RF Gini importance, bars colored by current signal value
- **Feature breakdown with filter tabs** — All / Phishing / Safe / Neutral, each showing source (URL/DOM), importance %, and signal chip (−1 / 0 / +1)
- Last 5 scans history
- Rescan button (clears storage and reloads source tab)

---

## Connection to the Research Paper

| Extension Component | Paper Section | What It Connects |
|---|---|---|
| 30 UCI-2015 features | §2.3 Data Gathering | Exact same feature set used for training and evaluation |
| `RF_IMPORTANCES` constant | §3.1.5 Feature Importance | RF Gini importances — HTTPS=31.38%, AnchorURL=24.10%, WebsiteTraffic=8.11% |
| `VOTER_WEIGHTS` constant | §2.7.2 Adaptive Soft Voting | Rank-based CV-AUC weights: XGB 0.333, LGBM 0.267, CB 0.200, RF 0.133, GB 0.067 |
| Threshold θ = 0.5 | §2.8 Evaluation | Same binary decision boundary used in the paper's test set evaluation |
| Confidence scaling | §1.4 Scope and Limitation | Compensates for the 6 API-dependent features that are always neutral |
| AnchorURL + HTTPS weighting | §3.1.5 Target Corr. Rank | Two features alone account for 55.48% of total importance weight |
| 97.42% accuracy display | §3.4 Comparative Analysis | From Table 7 — PhishVote vs. Saeed (2025) baseline |
| Full importance chart | §3.1.5 Feature Importance | Visualizes the ranked bar chart described in paper results |
| SMOTE note in footer | §2.5 Preprocessing | Conditional SMOTE on training partition (imbalance ratio threshold 0.80) |
| Stratified 80/20 split | §2.4 Data Splitting | Same split ratio used for model training |

### Why the Extension Uses RF Importances for Scoring (Not Full Ensemble Voting)

The paper's ensemble performs **soft voting** at prediction time — each of the five classifiers outputs a probability, those probabilities are multiplied by their assigned weights, and the weighted average determines the final class. Replicating this at extension runtime would require serializing and loading all five full trained models.

Instead, the extension uses the **Random Forest's Gini importance weights** as a proxy for feature relevance. This approximation is well-grounded: the RF importance values directly reflect each feature's contribution to reducing classification error across all trees in the best-performing individual base learner. The voter weights (XGB=0.333, LGBM=0.267, etc.) are surfaced in the UI for transparency and connect the extension's display to §2.7.2 of the paper, but the real-time scoring formula uses RF importances as described above.

---

## File Architecture

```
PhishVote_v7/
├── manifest.json          Extension config — MV3, permissions, icon paths
├── engine.js              Core detection engine — all 30 features, scoring, DOM extractor
├── background.js          Service worker — two-pass pipeline, badge, banner, storage
├── popup.html             Toolbar popup shell (no inline JS — MV3 CSP compliance)
├── popup.js               Popup logic — polls storage, renders verdict and signals
├── detail.html            Full analysis page shell
├── detail.js              Detail page logic — all 30 features, chart, filter tabs
├── models/
│   └── phishvote_model_dsbase.json   RF importances, voter weights, threshold
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

### Why JS Is in Separate Files (Not Inline in HTML)

Chrome's Manifest Version 3 enforces a strict Content Security Policy that **completely forbids inline `<script>` blocks** inside extension HTML files. Any `<script>...</script>` tag with content inside an extension HTML file will throw a CSP violation and crash the popup or detail page with a blank screen. All JavaScript is therefore in `.js` files referenced via `<script src="...">`.

---

## Known Limitations

**Static dataset.** The model was trained on UCI-2015. Phishing techniques have evolved since 2015; novel evasion patterns may not be represented in the training data. This is acknowledged in §1.4 of the paper.

**6 neutral API features.** AgeofDomain, DNSRecording, WebsiteTraffic, PageRank, GoogleIndex, and LinksPointingToPage always return 0. Together they account for 13.10% of RF importance weight that is permanently inactive.

**HTTPS dominance.** HTTPS carries 31.38% importance weight. Modern phishing sites increasingly use valid HTTPS certificates, which can push a genuinely phishing page toward a safe verdict when other signals are sparse.

**DOM scan restrictions.** Pages with strict Content Security Policies, `chrome://` URLs, and PDF viewers block `chrome.scripting.executeScript`. The extension falls back to URL-only scoring in these cases.

**No real-time learning.** The model weights are static. The extension does not update itself against new phishing campaigns or learn from user feedback.

---

## Citation

> Duhaylungsod, Z. R., & Dumalogdog, A. (2025). *PhishVote: An Adaptive Soft-Voting Ensemble of Gradient-Boosted Classifiers for Phishing Website Detection*. University of Mindanao, Matina, Davao City, Philippines.
>
> Dataset: Mohammad, R. M., Thabtah, F., & McCluskey, L. (2015). UCI Phishing Websites Dataset. UCI Machine Learning Repository.

---

*PhishVote v7.0 · UCI-2015 · 30 Features · θ=0.5 · 97.42% Accuracy · RF+XGB+CB+LGBM+GB*
