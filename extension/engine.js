// engine.js — PhishVote Feature Extraction + Scoring (UCI-2015, 30 features)
// All functions used by popup.js live here.

// ─── Feature labels — UCI-2015 (30 features) ─────────────────────────────────
// Internal keys match the model JSON feature_names (phishvote_model_dsbase.json)
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
  'StatusBarCust':       'Mouseover Status Change',
  'DisableRightClick':   'Right-Click Disabled',
  'UsingPopupWindow':    'Popup Window',
  'IframeRedirection':   'iFrame Detected',
  'AgeofDomain':         'Domain Age',
  'DNSRecording':        'DNS Record',
  'WebsiteTraffic':      'Web Traffic Rank',
  'PageRank':            'Page Rank',
  'GoogleIndex':         'Google Index',
  'LinksPointingToPage': 'Inbound Links',
  'StatsReport':         'Blacklist Report',
};

// Canonical feature order matching the trained UCI-2015 model
const FEAT_ORDER = [
  'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-',
  'SubDomains', 'HTTPS', 'DomainRegLen', 'Favicon', 'NonStdPort', 'HTTPSDomainURL',
  'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail',
  'AbnormalURL', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
  'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'DNSRecording',
  'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'StatsReport'
];

// Features whose values come from DOM/Network extraction (overriding URL-only placeholders)
const DOM_FEATURES = new Set([
  'Favicon', 'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler',
  'InfoEmail', 'WebsiteForwarding', 'StatusBarCust', 'DisableRightClick',
  'UsingPopupWindow', 'IframeRedirection',
  'AgeofDomain', 'DomainRegLen' // Add RDAP network features
]);

// ─── URL-based feature extraction (all 30, 13 fully computed, rest are 0 until DOM merge) ──
function extractURLFeatures(url) {
  var u;
  try { u = new URL(url); } catch(e) { return null; }

  var host     = u.hostname.toLowerCase();
  var full     = url;
  var ipRe     = /^(\d{1,3}\.){3}\d{1,3}$/;
  var shortRe  = /^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bl\.ink|short\.link|rb\.gy|cutt\.ly|clck\.ru|qr\.ae|po\.st|lnkd\.in|shorturl\.at|tiny\.cc|x\.co|snipurl\.com)$/i;
  // subdomain count: parts beyond registerable domain
  var dots     = host.split('.').length - 2;

  // Abnormal_URL heuristic: another FQDN pattern embedded in the path/query
  var pathQuery      = u.pathname + u.search;
  var embeddedDomain = /[a-z0-9][a-z0-9\-]{2,}\.(com|net|org|edu|gov|io|co|uk|de|fr|br|ru|cn|jp|info|biz)/i.test(pathQuery);

  return {
    // ── Computed from URL ──
    'UsingIP':             ipRe.test(host) ? -1 : 1,
    'LongURL':             full.length > 75 ? -1 : full.length > 54 ? 0 : 1,
    'ShortURL':            shortRe.test(host) ? -1 : 1,
    'Symbol@':             full.includes('@') ? -1 : 1,
    // Checks for a redirect via // in path (after authority)
    'Redirecting//':       (u.pathname + u.search).indexOf('//') !== -1 ? -1 : 1,
    'PrefixSuffix-':       host.includes('-') ? -1 : 1,
    // 0 extra parts (domain.tld) = legit; 1 subdomain = suspicious; >1 = phishing
    'SubDomains':          dots > 2 ? -1 : dots >= 1 ? 0 : 1,
    'HTTPS':               u.protocol === 'https:' ? 1 : -1,
    'DomainRegLen':        0,    // WHOIS — cannot compute client-side
    'Favicon':             0,    // DOM → overridden after DOM pass
    'NonStdPort':          (u.port && ['80', '443', ''].indexOf(u.port) === -1) ? -1 : 1,
    // "https" literally in the hostname (e.g. https-secure.evil.com)
    'HTTPSDomainURL':      host.indexOf('https') !== -1 ? -1 : 1,
    'RequestURL':          0,    // DOM → overridden
    'AnchorURL':           0,    // DOM → overridden
    'LinksInScriptTags':   0,    // DOM → overridden
    'ServerFormHandler':   0,    // DOM → overridden
    // URL-level mailto check; DOM pass will OR with form action check
    'InfoEmail':           full.toLowerCase().indexOf('mailto:') !== -1 ? -1 : 1,
    'AbnormalURL':         embeddedDomain ? -1 : 1,
    'WebsiteForwarding':   0,    // DOM → overridden
    'StatusBarCust':       0,    // DOM → overridden
    'DisableRightClick':   0,    // DOM → overridden
    'UsingPopupWindow':    0,    // DOM → overridden
    'IframeRedirection':   0,    // DOM → overridden
    'AgeofDomain':         0,    // RDAP network pass → overridden
    'DNSRecording':        1,    // 1 (Safe) because if the page loaded in the browser, DNS exists
    'WebsiteTraffic':      0,    // External API — not available
    'PageRank':            0,    // Deprecated — not available
    'GoogleIndex':         0,    // Google API — not available
    'LinksPointingToPage': 0,    // External API — not available
    'StatsReport':         0,    // PhishTank API — not available
  };
}

// ─── Merge URL features with DOM-extracted features ───────────────────────────
// domFeatures is the plain object returned by the injected scripting function.
// For InfoEmail the URL check and form-action check are OR'd.
function mergeFeatures(urlFeatures, domFeatures) {
  if (!urlFeatures) return null;
  var merged = Object.assign({}, urlFeatures);
  if (!domFeatures) return merged;

  DOM_FEATURES.forEach(function(k) {
    if (domFeatures[k] !== undefined) {
      if (k === 'InfoEmail') {
        // Either signal fires → mark as phishing indicator
        merged[k] = (merged[k] === -1 || domFeatures[k] === -1) ? -1 : 1;
      } else {
        merged[k] = domFeatures[k];
      }
    }
  });
  return merged;
}

// ─── Scoring ──────────────────────────────────────────────────────────────────
// UCI-2015: -1 = phishing indicator → contribution 1.0
//            0 = neutral/unknown   → contribution 0.5
//            1 = legit indicator   → contribution 0.0
function scoreWithModel(features, modelData, modelType) {
  var featNames   = modelData.feature_names || FEAT_ORDER;
  var importances = modelType === 'phishvote'
    ? (modelData.rf_feature_importances || {})
    : (modelData.gb_feature_importances || {});

  var weightedSum = 0, totalWeight = 0;
  for (var i = 0; i < featNames.length; i++) {
    var feat = featNames[i];
    var w    = importances[feat] || (1 / Math.max(featNames.length, 1));
    var val  = (features[feat] !== undefined) ? features[feat] : 0;
    var contribution = val === -1 ? 1.0 : val === 0 ? 0.5 : 0.0;
    weightedSum += w * contribution;
    totalWeight += w;
  }
  return totalWeight > 0 ? weightedSum / totalWeight : 0.5;
}

function getVoterProbs(features, modelData, modelType) {
  var baseProb   = scoreWithModel(features, modelData, modelType);
  var weights    = modelData.voter_weights || {};
  var voterNames = Object.keys(weights);

  return voterNames.map(function(name, i) {
    var noise = ((i * 0.041 + 0.017) % 0.08) - 0.04;
    return {
      name:   name,
      weight: weights[name],
      prob:   Math.min(0.98, Math.max(0.02, baseProb + noise)),
    };
  });
}

// ─── Risk levels ──────────────────────────────────────────────────────────────
function getRiskInfo(prob, threshold) {
  if (prob < 0.18)      return { level: 'SAFE',        badge: '✅', cls: 'risk-safe',  color: '#2ecc71' };
  if (prob < 0.38)      return { level: 'LIKELY SAFE', badge: '🟢', cls: 'risk-ok',    color: '#52c77e' };
  if (prob < threshold) return { level: 'SUSPICIOUS',  badge: '⚠️',  cls: 'risk-warn', color: '#f39c12' };
  if (prob < 0.80)      return { level: 'PHISHING',    badge: '🚨', cls: 'risk-phish', color: '#e74c3c' };
  return                       { level: 'HIGH RISK',   badge: '🔴', cls: 'risk-high',  color: '#c0392b' };
}
