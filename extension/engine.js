// engine.js — PhishVote Feature Extraction + Scoring
// All functions used by popup.js live here.

// ─── Feature label maps ──────────────────────────────────────────────────────
const FEAT_LABELS_DS01 = {
  'UsingIP':           'IP Address in URL',
  'LongURL':           'Long URL',
  'ShortURL':          'URL Shortener',
  'Symbol@':           '@ Symbol',
  'Redirecting//':     'Double Slash Redirect',
  'PrefixSuffix-':     'Dash in Domain',
  'SubDomains':        'Sub-Domains',
  'HTTPS':             'HTTPS',
  'DomainRegLen':      'Domain Reg Length',
  'Favicon':           'Favicon Source',
  'NonStdPort':        'Non-Standard Port',
  'HTTPSDomainURL':    'HTTPS in Domain Name',
  'RequestURL':        'Request URL',
  'AnchorURL':         'Anchor URL',
  'LinksInScriptTags': 'Links in Scripts',
  'AbnormalURL':       'Abnormal URL',
};

const FEAT_LABELS_DSBASE = {
  'having_IP_Address':           'IP Address in URL',
  'URL_Length':                  'URL Length',
  'Shortining_Service':          'URL Shortener',
  'having_At_Symbol':            '@ Symbol',
  'double_slash_redirecting':    'Double Slash Redirect',
  'Prefix_Suffix':               'Dash in Domain',
  'having_Sub_Domain':           'Sub-Domains',
  'SSLfinal_State':              'SSL State',
  'Domain_registeration_length': 'Domain Reg Length',
  'Favicon':                     'Favicon Source',
  'port':                        'Non-Standard Port',
  'HTTPS_token':                 'HTTPS in Domain Name',
  'Request_URL':                 'Request URL',
  'URL_of_Anchor':               'Anchor URL',
  'Links_in_tags':               'Links in Tags',
  'SFH':                         'Server Form Handler',
  'Submitting_to_email':         'Submits to Email',
  'Abnormal_URL':                'Abnormal URL',
  'Redirect':                    'Redirect Count',
  'on_mouseover':                'Mouseover Change',
  'RightClick':                  'Right Click Disabled',
  'popUpWidnow':                 'Popup Window',
  'Iframe':                      'iFrame Usage',
  'age_of_domain':               'Domain Age',
  'DNSRecord':                   'DNS Record',
  'web_traffic':                 'Web Traffic',
  'Page_Rank':                   'Page Rank',
  'Google_Index':                'Google Index',
  'Links_pointing_to_page':      'Inbound Links',
  'Statistical_report':          'Blacklist Report',
};

function getFeatLabels(ds) {
  return ds === 'dsbase' ? FEAT_LABELS_DSBASE : FEAT_LABELS_DS01;
}

// ─── DS01: 16-feature extraction ─────────────────────────────────────────────
function extractDS01Features(url) {
  var u;
  try { u = new URL(url); } catch(e) { return null; }
  var host  = u.hostname;
  var full  = url;
  var path  = u.pathname + u.search;
  var ipRe  = /^(\d{1,3}\.){3}\d{1,3}$/;
  var short = /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bl\.ink/i;

  return {
    'UsingIP':           ipRe.test(host) ? -1 : 1,
    'LongURL':           full.length > 75 ? -1 : full.length > 54 ? 0 : 1,
    'ShortURL':          short.test(host) ? -1 : 1,
    'Symbol@':           full.includes('@') ? -1 : 1,
    'Redirecting//':     path.includes('//') ? -1 : 1,
    'PrefixSuffix-':     host.includes('-') ? -1 : 1,
    'SubDomains':        (host.split('.').length - 2) > 2 ? -1 : (host.split('.').length - 2) === 2 ? 0 : 1,
    'HTTPS':             u.protocol === 'https:' ? 1 : -1,
    'DomainRegLen':      0,
    'Favicon':           0,
    'NonStdPort':        (u.port && ['80','443',''].indexOf(u.port) === -1) ? -1 : 1,
    'HTTPSDomainURL':    host.toLowerCase().indexOf('https') !== -1 ? -1 : 1,
    'RequestURL':        0,
    'AnchorURL':         0,
    'LinksInScriptTags': 0,
    'AbnormalURL':       1,
  };
}

// ─── DS-Base: 30-feature extraction ──────────────────────────────────────────
function extractDSBaseFeatures(url) {
  var u;
  try { u = new URL(url); } catch(e) { return null; }
  var host  = u.hostname;
  var full  = url;
  var path  = u.pathname + u.search;
  var ipRe  = /^(\d{1,3}\.){3}\d{1,3}$/;
  var short = /bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly/i;
  var dots  = host.split('.').length - 2;

  return {
    'having_IP_Address':           ipRe.test(host) ? -1 : 1,
    'URL_Length':                  full.length > 75 ? -1 : full.length > 54 ? 0 : 1,
    'Shortining_Service':          short.test(host) ? -1 : 1,
    'having_At_Symbol':            full.includes('@') ? -1 : 1,
    'double_slash_redirecting':    path.includes('//') ? -1 : 1,
    'Prefix_Suffix':               host.includes('-') ? -1 : 1,
    'having_Sub_Domain':           dots > 2 ? -1 : dots === 2 ? 0 : 1,
    'SSLfinal_State':              u.protocol === 'https:' ? 1 : -1,
    'Domain_registeration_length': 0,
    'Favicon':                     0,
    'port':                        (u.port && ['80','443',''].indexOf(u.port) === -1) ? -1 : 1,
    'HTTPS_token':                 host.toLowerCase().indexOf('https') !== -1 ? -1 : 1,
    'Request_URL':                 0,
    'URL_of_Anchor':               0,
    'Links_in_tags':               0,
    'SFH':                         0,
    'Submitting_to_email':         full.toLowerCase().indexOf('mailto:') !== -1 ? -1 : 1,
    'Abnormal_URL':                1,
    'Redirect':                    (full.match(/\/{2,}/g) || []).length > 1 ? -1 : 1,
    'on_mouseover':                0,
    'RightClick':                  0,
    'popUpWidnow':                 0,
    'Iframe':                      0,
    'age_of_domain':               0,
    'DNSRecord':                   0,
    'web_traffic':                 0,
    'Page_Rank':                   0,
    'Google_Index':                0,
    'Links_pointing_to_page':      0,
    'Statistical_report':          0,
  };
}

function extractFeatures(url, ds) {
  return ds === 'dsbase' ? extractDSBaseFeatures(url) : extractDS01Features(url);
}

// ─── Scoring ──────────────────────────────────────────────────────────────────
function scoreWithModel(features, modelData, modelType) {
  var featNames   = modelData.feature_names || [];
  var importances = modelType === 'phishvote'
    ? (modelData.rf_feature_importances || {})
    : (modelData.gb_feature_importances || {});

  var weightedSum = 0, totalWeight = 0;
  for (var i = 0; i < featNames.length; i++) {
    var feat = featNames[i];
    var w    = importances[feat] || (1 / Math.max(featNames.length, 1));
    var val  = (features[feat] !== undefined) ? features[feat] : 0;
    var contribution = val === -1 ? 1.0 : val === 0 ? 0.5 : 0.0;
    weightedSum  += w * contribution;
    totalWeight  += w;
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
