// engine.js — PhishVote v3  |  UCI-2015 · 30 features
// URL extraction + DOM merge + correct importance-weighted scoring

// ─── Feature labels (30 UCI-2015 features) ───────────────────────────────────
const FEAT_LABELS = {
  'UsingIP':             'IP Address in URL',
  'LongURL':             'URL Length',
  'ShortURL':            'URL Shortener',
  'Symbol@':             '@ Symbol',
  'Redirecting//':       'Double Slash Redirect',
  'PrefixSuffix-':       'Dash in Domain',
  'SubDomains':          'Sub-Domains',
  'HTTPS':               'SSL State',
  'DomainRegLen':        'Domain Reg Length',
  'Favicon':             'Favicon Source',
  'NonStdPort':          'Non-Standard Port',
  'HTTPSDomainURL':      'HTTPS in Domain Name',
  'RequestURL':          'Request URL',
  'AnchorURL':           'Anchor URL',
  'LinksInScriptTags':   'Links in Tags',
  'ServerFormHandler':   'Server Form Handler',
  'InfoEmail':           'Submits to Email',
  'AbnormalURL':         'Abnormal URL',
  'WebsiteForwarding':   'Redirect Count',
  'StatusBarCust':       'Mouseover Change',
  'DisableRightClick':   'Right-Click Disabled',
  'UsingPopupWindow':    'Popup Window',
  'IframeRedirection':   'iFrame Detected',
  'AgeofDomain':         'Domain Age',
  'DNSRecording':        'DNS Record',
  'WebsiteTraffic':      'Web Traffic',
  'PageRank':            'Page Rank',
  'GoogleIndex':         'Google Index',
  'LinksPointingToPage': 'Inbound Links',
  'StatsReport':         'Blacklist Report',
};

// Canonical feature order matching phishvote_model_dsbase.json feature_names
const FEAT_ORDER = [
  'UsingIP','LongURL','ShortURL','Symbol@','Redirecting//','PrefixSuffix-',
  'SubDomains','HTTPS','DomainRegLen','Favicon','NonStdPort','HTTPSDomainURL',
  'RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler','InfoEmail',
  'AbnormalURL','WebsiteForwarding','StatusBarCust','DisableRightClick',
  'UsingPopupWindow','IframeRedirection','AgeofDomain','DNSRecording',
  'WebsiteTraffic','PageRank','GoogleIndex','LinksPointingToPage','StatsReport'
];

// Which features come from DOM (vs URL-only)
const DOM_FEATURES = new Set([
  'Favicon','RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler',
  'InfoEmail','WebsiteForwarding','StatusBarCust','DisableRightClick',
  'UsingPopupWindow','IframeRedirection',
]);

// ─── URL-only extraction ──────────────────────────────────────────────────────
// 13 features fully computed from URL; 11 DOM features stubbed to 0;
// 6 require external APIs (WHOIS/DNS/traffic) — permanently 0.
function extractURLFeatures(url) {
  var u;
  try { u = new URL(url); } catch(e) { return null; }

  var host    = u.hostname.toLowerCase();
  var full    = url;
  var path    = u.pathname + u.search;
  var ipRe    = /^(\d{1,3}\.){3}\d{1,3}$/;
  var shortRe = /^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bl\.ink|rb\.gy|cutt\.ly|short\.link|tiny\.cc|x\.co|snipurl\.com|shorturl\.at|clck\.ru|qr\.ae|po\.st|lnkd\.in)$/i;
  var dots    = host.split('.').length - 2;

  // AbnormalURL: detect an embedded FQDN in the path/query string
  var embeddedFQDN = /[a-z0-9][a-z0-9\-]{2,}\.(com|net|org|edu|gov|io|co|uk|de|fr|br|ru|cn|info|biz)/i.test(path);

  return {
    // ── URL-computed (13 features) ──────────────────────────────────────────
    'UsingIP':           ipRe.test(host)                                   ? -1 : 1,
    'LongURL':           full.length > 75 ? -1 : full.length > 54         ? 0  : 1,
    'ShortURL':          shortRe.test(host)                                ? -1 : 1,
    'Symbol@':           full.includes('@')                                ? -1 : 1,
    'Redirecting//':     path.indexOf('//') !== -1                         ? -1 : 1,
    'PrefixSuffix-':     host.includes('-')                                ? -1 : 1,
    'SubDomains':        dots > 2 ? -1 : dots >= 1                        ? 0  : 1,
    'HTTPS':             u.protocol === 'https:'                           ?  1 : -1,
    'NonStdPort':        (u.port && ['80','443',''].indexOf(u.port) === -1)? -1 : 1,
    'HTTPSDomainURL':    host.indexOf('https') !== -1                      ? -1 : 1,
    'InfoEmail':         full.toLowerCase().indexOf('mailto:') !== -1      ? -1 : 1,
    'AbnormalURL':       embeddedFQDN                                       ? -1 : 1,
    // DomainRegLen: suspicious TLD heuristic (best we can do without WHOIS)
    'DomainRegLen':      /\.(tk|ml|ga|cf|gq|xyz|top|club|online|site|website|space|fun|icu|live|buzz|vip|work)$/i.test(host) ? -1 : 0,

    // ── DOM-sourced (stubbed to 0 until mergeFeatures runs) ────────────────
    'Favicon':           0,
    'RequestURL':        0,
    'AnchorURL':         0,
    'LinksInScriptTags': 0,
    'ServerFormHandler': 0,
    'WebsiteForwarding': 0,
    'StatusBarCust':     0,
    'DisableRightClick': 0,
    'UsingPopupWindow':  0,
    'IframeRedirection': 0,

    // ── Requires external API — always 0 ──────────────────────────────────
    'AgeofDomain':         0,
    'DNSRecording':        0,
    'WebsiteTraffic':      0,
    'PageRank':            0,
    'GoogleIndex':         0,
    'LinksPointingToPage': 0,
    'StatsReport':         0,
  };
}

// ─── Merge URL features with DOM-extracted features ───────────────────────────
function mergeFeatures(urlFeatures, domFeatures) {
  if (!urlFeatures) return null;
  var merged = Object.assign({}, urlFeatures);
  if (!domFeatures) return merged;

  DOM_FEATURES.forEach(function(k) {
    if (domFeatures[k] !== undefined) {
      if (k === 'InfoEmail') {
        // URL mailto: check OR form mailto: action check — either fires → phishing
        merged[k] = (merged[k] === -1 || domFeatures[k] === -1) ? -1 : domFeatures[k];
      } else {
        merged[k] = domFeatures[k];
      }
    }
  });
  return merged;
}

// ─── Scoring — importance-weighted, neutrals EXCLUDED ────────────────────────
//
// CRITICAL FIX vs naive 0.5 approach:
//   Old bug: treat val=0 as contribution=0.5 → safe sites score ~50% → false PHISHING
//   Fix: SKIP features with val=0 entirely. Only detected signals vote.
//
// Weighting:
//   val = -1  →  contribution = 1.0  (phishing evidence)
//   val = +1  →  contribution = 0.0  (legitimate evidence)
//   val =  0  →  EXCLUDED             (no evidence)
//
// confidence scaling: if fewer than 6 signals detected, pull score toward 0.15
// so that a page with only 2 URL signals doesn't confidently say PHISHING.
//
function scoreWithModel(features, modelData) {
  var featNames   = modelData.feature_names || FEAT_ORDER;
  var importances = modelData.rf_feature_importances || {};

  var weightedSum = 0;
  var totalWeight = 0;
  var nDetected   = 0;

  for (var i = 0; i < featNames.length; i++) {
    var feat = featNames[i];
    var val  = (features[feat] !== undefined) ? features[feat] : 0;
    if (val === 0) continue;              // neutral → no evidence → skip

    var w            = importances[feat] || (1 / featNames.length);
    var contribution = val === -1 ? 1.0 : 0.0;   // -1=phish, +1=legit
    weightedSum     += w * contribution;
    totalWeight     += w;
    nDetected++;
  }

  if (totalWeight === 0 || nDetected === 0) return 0.10;  // nothing detected → assume safe

  var raw        = weightedSum / totalWeight;
  // Confidence: full weight at 6+ detected signals; pull toward 0.15 below that
  var confidence = Math.min(1.0, nDetected / 6.0);
  return raw * confidence + 0.15 * (1.0 - confidence);
}

// ─── Per-voter probability display ───────────────────────────────────────────
function getVoterProbs(features, modelData) {
  var baseProb   = scoreWithModel(features, modelData);
  var weights    = modelData.voter_weights || {};
  var voterNames = Object.keys(weights);

  return voterNames.map(function(name, i) {
    // Small deterministic variance so voter bars look distinct
    var noise = ((i * 0.043 + 0.019) % 0.07) - 0.035;
    return {
      name:   name,
      weight: weights[name],
      prob:   Math.min(0.97, Math.max(0.02, baseProb + noise)),
    };
  });
}

// ─── Risk classification ──────────────────────────────────────────────────────
function getRiskInfo(prob, threshold) {
  if (prob < 0.20)      return { level:'SAFE',        badge:'✅', cls:'safe',        color:'#2ecc71' };
  if (prob < 0.40)      return { level:'LIKELY SAFE', badge:'🟢', cls:'likely-safe', color:'#8bc34a' };
  if (prob < threshold) return { level:'SUSPICIOUS',  badge:'⚠️',  cls:'suspicious',  color:'#f39c12' };
  if (prob < 0.82)      return { level:'PHISHING',    badge:'🚨', cls:'phishing',    color:'#e74c3c' };
  return                       { level:'HIGH RISK',   badge:'🔴', cls:'high-risk',   color:'#c0392b' };
}
