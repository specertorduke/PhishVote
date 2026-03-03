// popup.js — PhishVote UI (UCI-2015 only)
// engine.js is loaded first and provides:
//   extractURLFeatures, mergeFeatures, FEAT_LABELS, FEAT_ORDER, DOM_FEATURES,
//   scoreWithModel, getVoterProbs, getRiskInfo

// ─── State ───────────────────────────────────────────────────────────────────
var STATE = {
  modelType:   'phishvote',   // 'phishvote' | 'baseline'
  url:         '',
  tabId:       null,
  models:      {},
  features:    null,          // merged URL + DOM features
  domFeatures: null,          // raw DOM extraction result
  showCompare: false,
  showFeats:   true,
};

// ─── Model loading (UCI-2015 / dsbase models only) ────────────────────────────
var MODEL_FILES = {
  phishvote: 'models/phishvote_model_dsbase.json',
  baseline:  'models/baseline_model_dsbase.json',
};

async function loadModels() {
  var entries = await Promise.all(
    Object.entries(MODEL_FILES).map(async function([key, path]) {
      try {
        var resp = await fetch(chrome.runtime.getURL(path));
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        var data = await resp.json();
        return [key, data];
      } catch(e) {
        console.warn('PhishVote: could not load', path, e.message);
        return [key, null];
      }
    })
  );
  return Object.fromEntries(entries);
}

// ─── DOM feature extraction (injected into live page via scripting API) ───────
// This function runs INSIDE the page context — must be self-contained.
function extractPageDOMFeatures() {
  var pageUrl = window.location.href;
  var host;
  try { host = new URL(pageUrl).hostname.toLowerCase(); } catch(e) { host = ''; }

  var result = {};

  // ── Favicon ─────────────────────────────────────────────────────────────────
  // -1 if the favicon is served from a different domain, 1 if same, 0 if unknown
  var favEls = Array.from(document.querySelectorAll('link[rel*="icon"]'));
  if (favEls.length === 0) {
    result.Favicon = 0;
  } else {
    var externalFav = favEls.some(function(el) {
      var href = el.getAttribute('href') || '';
      if (!href || href.startsWith('data:')) return false;
      if (href.startsWith('/') && !href.startsWith('//')) return false; // relative same-domain
      try { return new URL(href, pageUrl).hostname.toLowerCase() !== host; } catch(e) { return false; }
    });
    result.Favicon = externalFav ? -1 : 1;
  }

  // ── RequestURL (formerly Request_URL) ────────────────────────────────────────
  // Ratio of img/script/form/audio/video/embed/object resources from external domains
  // <22% → 1 (legit), 22–61% → 0 (suspicious), >61% → -1 (phishing)
  var reqEls = Array.from(document.querySelectorAll(
    'img[src], script[src], form[action], audio[src], video[src], embed[src], object[data]'
  ));
  if (reqEls.length === 0) {
    result.RequestURL = 1;
  } else {
    var extReq = reqEls.filter(function(el) {
      var u = el.getAttribute('src') || el.getAttribute('data') || el.getAttribute('action') || '';
      if (!u || u.startsWith('data:') || u.startsWith('#') || u.startsWith('javascript:')) return false;
      if (u.startsWith('/') && !u.startsWith('//')) return false;
      try { return new URL(u, pageUrl).hostname.toLowerCase() !== host; } catch(e) { return false; }
    }).length;
    var p1 = extReq / reqEls.length;
    result.RequestURL = p1 < 0.22 ? 1 : p1 < 0.61 ? 0 : -1;
  }

  // ── AnchorURL (formerly URL_of_Anchor) ───────────────────────────────────────
  // Ratio of <a> tags pointing to a different domain
  // <31% → 1, 31–67% → 0, >67% → -1
  var anchors = Array.from(document.querySelectorAll('a[href]'));
  if (anchors.length === 0) {
    result.AnchorURL = 1;
  } else {
    var extAnch = anchors.filter(function(el) {
      var h = el.getAttribute('href') || '';
      if (!h || h.startsWith('#') || h.startsWith('javascript:') ||
          h.startsWith('mailto:') || h.startsWith('tel:')) return false;
      if (h.startsWith('/') && !h.startsWith('//')) return false;
      try { return new URL(h, pageUrl).hostname.toLowerCase() !== host; } catch(e) { return false; }
    }).length;
    var p2 = extAnch / anchors.length;
    result.AnchorURL = p2 < 0.31 ? 1 : p2 < 0.67 ? 0 : -1;
  }

  // ── LinksInScriptTags (formerly Links_in_tags) ───────────────────────────────
  // External ratio among <script src>, <link href>, <meta content> with full URL
  // <17% → 1, 17–81% → 0, >81% → -1
  var tagEls = Array.from(document.querySelectorAll('script[src], link[href], meta[content]'));
  if (tagEls.length === 0) {
    result.LinksInScriptTags = 1;
  } else {
    var extTag = tagEls.filter(function(el) {
      var u = el.getAttribute('src') || el.getAttribute('href') || el.getAttribute('content') || '';
      if (!u) return false;
      if (u.startsWith('/') && !u.startsWith('//')) return false;
      try { return new URL(u, pageUrl).hostname.toLowerCase() !== host; } catch(e) { return false; }
    }).length;
    var p3 = extTag / tagEls.length;
    result.LinksInScriptTags = p3 < 0.17 ? 1 : p3 < 0.81 ? 0 : -1;
  }

  // ── ServerFormHandler (formerly SFH) ─────────────────────────────────────────
  // 1 = form submits to same domain, 0 = blank/empty action, -1 = external / mailto
  var forms = Array.from(document.querySelectorAll('form'));
  if (forms.length === 0) {
    result.ServerFormHandler = 1;
  } else {
    var sfhVals = forms.map(function(f) {
      var action = (f.getAttribute('action') || '').trim();
      if (!action || action.toLowerCase() === 'about:blank') return 0;
      if (action.toLowerCase().startsWith('mailto:')) return -1;
      if (action.startsWith('/') && !action.startsWith('//')) return 1; // relative path = same domain
      try {
        return new URL(action, pageUrl).hostname.toLowerCase() === host ? 1 : -1;
      } catch(e) { return 1; }
    });
    result.ServerFormHandler = sfhVals.includes(-1) ? -1 : sfhVals.includes(0) ? 0 : 1;
  }

  // ── InfoEmail (formerly Submitting_to_email) ─────────────────────────────────
  // -1 if any form submits via mailto:, 1 otherwise
  var hasMailtoForm = Array.from(document.querySelectorAll('form')).some(function(f) {
    return (f.getAttribute('action') || '').toLowerCase().startsWith('mailto:');
  });
  result.InfoEmail = hasMailtoForm ? -1 : 1;

  // ── WebsiteForwarding (formerly Redirect) ────────────────────────────────────
  // Uses Navigation Timing API: 0 redirs → 1, 1 → 0, ≥2 → -1
  var redirectCount = 0;
  try {
    var navEntries = performance.getEntriesByType && performance.getEntriesByType('navigation');
    if (navEntries && navEntries.length > 0) {
      redirectCount = navEntries[0].redirectCount || 0;
    } else if (performance.navigation) {
      redirectCount = performance.navigation.redirectCount || 0;
    }
  } catch(e) {}
  result.WebsiteForwarding = redirectCount === 0 ? 1 : redirectCount === 1 ? 0 : -1;

  // ── StatusBarCust (formerly on_mouseover) ────────────────────────────────────
  // -1 if any link/element uses onmouseover to overwrite window.status
  var moEls = Array.from(document.querySelectorAll('[onmouseover]'));
  var hasStatusMod = moEls.some(function(el) {
    var mo = (el.getAttribute('onmouseover') || '').toLowerCase();
    return mo.includes('window.status') || mo.includes('status =') || mo.includes('status=');
  });
  if (!hasStatusMod) {
    hasStatusMod = Array.from(document.querySelectorAll('script:not([src])')).some(function(s) {
      var t = s.textContent || '';
      return t.includes('window.status') && t.includes('mouseover');
    });
  }
  result.StatusBarCust = hasStatusMod ? -1 : 1;

  // ── DisableRightClick (formerly RightClick) ──────────────────────────────────
  // -1 if right-click / contextmenu is disabled anywhere on the page
  var rcDisabled = false;
  [document.body, document.documentElement].forEach(function(el) {
    if (el && (el.getAttribute('oncontextmenu') || '').toLowerCase().includes('return false')) {
      rcDisabled = true;
    }
  });
  if (!rcDisabled) {
    rcDisabled = Array.from(document.querySelectorAll('script:not([src])')).some(function(s) {
      var t = s.textContent || '';
      return t.includes('contextmenu') &&
             (t.includes('return false') || t.includes('preventDefault'));
    });
  }
  result.DisableRightClick = rcDisabled ? -1 : 1;

  // ── UsingPopupWindow (formerly popUpWindow) ──────────────────────────────────
  // -1 if any inline script uses window.open()
  var hasPopup = Array.from(document.querySelectorAll('script:not([src])')).some(function(s) {
    return (s.textContent || '').includes('window.open(');
  });
  result.UsingPopupWindow = hasPopup ? -1 : 1;

  // ── IframeRedirection (formerly Iframe) ──────────────────────────────────────
  // 1 = no iframes, -1 = invisible/hidden iframe present, 0 = visible iframes exist
  var iframes = Array.from(document.querySelectorAll('iframe'));
  var hiddenIframe = iframes.some(function(fr) {
    var w     = fr.getAttribute('width');
    var h     = fr.getAttribute('height');
    var style = (fr.getAttribute('style') || '').replace(/\s/g, '').toLowerCase();
    return (w === '0' || h === '0') ||
           style.includes('display:none') || style.includes('visibility:hidden') ||
           style.includes('width:0') || style.includes('height:0');
  });
  result.IframeRedirection = iframes.length === 0 ? 1 : hiddenIframe ? -1 : 0;

  return result;
}

async function getDOMFeatures(tabId) {
  try {
    var results = await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func:   extractPageDOMFeatures,
    });
    return (results && results[0] && results[0].result) ? results[0].result : {};
  } catch(e) {
    console.warn('PhishVote: DOM extraction failed —', e.message);
    return {};
  }
}

// ─── Render helpers ──────────────────────────────────────────────────────────
function pct(v) { return Math.round(v * 100); }

function featChip(val) {
  if (val === -1) return '<span class="feat-chip p">\u22121 phish</span>';
  if (val ===  1) return '<span class="feat-chip l">+1 safe</span>';
  return                 '<span class="feat-chip n"> 0 neut</span>';
}

function renderVoters(voters, threshold) {
  return voters.map(function(v) {
    var color = v.prob >= threshold ? 'var(--red)' : 'var(--green)';
    return '<div class="voter-card">' +
      '<div class="vc-name">' + v.name + '</div>' +
      '<div class="vc-w">w=' + v.weight.toFixed(3) + '</div>' +
      '<div class="vc-prob" style="color:' + color + '">' + pct(v.prob) + '%</div>' +
      '</div>';
  }).join('');
}

function renderFeatures(features) {
  var entries = FEAT_ORDER.map(function(k) { return [k, features[k] !== undefined ? features[k] : 0]; });
  // Active (non-zero) signals first, then neutral/unknown
  var active  = entries.filter(function(e) { return e[1] !== 0; });
  var neutral = entries.filter(function(e) { return e[1] === 0; });
  var sorted  = active.concat(neutral);

  return sorted.map(function(e) {
    var key = e[0], val = e[1];
    var label    = FEAT_LABELS[key] || key;
    var domClass = ['AgeofDomain', 'DomainRegLen'].includes(key) ? 'net' : DOM_FEATURES.has(key) ? 'dom' : 'url';
    var domTag   = domClass === 'net' ? '<span class="feat-src net">NET</span>' :
                   domClass === 'dom' ? '<span class="feat-src dom">DOM</span>' :
                   '<span class="feat-src url">URL</span>';
    var dimStyle = val === 0 ? 'opacity:0.42' : '';
    return '<div class="feat-row" style="' + dimStyle + '">' +
      '<span class="feat-name">' + label + domTag + '</span>' +
      featChip(val) +
      '</div>';
  }).join('');
}

function renderCompare(models) {
  var pvData = models['phishvote'];
  var blData = models['baseline'];
  if (!pvData || !blData) return '';

  var pvM    = pvData.phishvote_metrics || {};
  var blM    = blData.ensemble_metrics  || {};
  var pvWins = (pvM.accuracy || 0) >= (blM.accuracy || 0);

  return '<div class="compare-section">' +
    '<div class="sect-hdr"><span class="sect-title">\ud83d\udcca PhishVote vs Saeed (2025) \u00b7 UCI-2015</span></div>' +
    '<div class="compare-grid">' +
      '<div class="compare-card' + (pvWins ? ' cc-winner' : '') + '">' +
        '<div class="cc-title">\ud83d\udee1\ufe0f PhishVote' + (pvWins ? ' \ud83c\udfc6' : '') + '</div>' +
        '<div class="cc-metric"><span class="cc-key">Accuracy</span><span class="cc-val">' + (pvM.accuracy ?? '\u2014') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">F1-Score</span><span class="cc-val">' + (pvM.f1 ?? '\u2014') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">Precision</span><span class="cc-val">' + (pvM.precision ?? '\u2014') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">\u03b8*</span><span class="cc-val">' + (pvData.threshold ?? '\u2014') + '</span></div>' +
      '</div>' +
      '<div class="compare-card' + (!pvWins ? ' cc-winner' : '') + '">' +
        '<div class="cc-title">\ud83d\udcca Saeed 2025' + (!pvWins ? ' \ud83c\udfc6' : '') + '</div>' +
        '<div class="cc-metric"><span class="cc-key">Accuracy</span><span class="cc-val">' + (blM.accuracy ?? '\u2014') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">F1-Score</span><span class="cc-val">' + (blM.f1 ?? '\u2014') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">Precision</span><span class="cc-val">' + (blM.precision ?? '\u2014') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">\u03b8*</span><span class="cc-val">' + (blData.threshold ?? '\u2014') + '</span></div>' +
      '</div>' +
    '</div></div>';
}

// ─── Main render ─────────────────────────────────────────────────────────────
function render() {
  var modelType   = STATE.modelType;
  var url         = STATE.url;
  var models      = STATE.models;
  var features    = STATE.features;
  var showCompare = STATE.showCompare;
  var showFeats   = STATE.showFeats;

  var modelData = models[modelType];
  var prob      = (features && modelData) ? scoreWithModel(features, modelData, modelType) : 0.5;
  var voters    = (features && modelData) ? getVoterProbs(features, modelData, modelType)  : [];
  var threshold = (modelData && modelData.threshold) ? modelData.threshold : 0.5;
  var risk      = getRiskInfo(prob, threshold);
  var probPct   = pct(prob);

  var phishSig = features ? Object.values(features).filter(function(v){ return v === -1; }).length : 0;
  var safeSig  = features ? Object.values(features).filter(function(v){ return v ===  1; }).length : 0;
  var neutSig  = features ? Object.values(features).filter(function(v){ return v ===  0; }).length : 0;
  var totalFeat = FEAT_ORDER.length;

  var ensembleName = modelType === 'phishvote' ? 'PhishVote' : 'Saeed (2025)';
  var voterList    = modelType === 'phishvote'
    ? ((modelData && modelData.selected_voters) ? modelData.selected_voters.join(' \u00b7 ') : 'RF \u00b7 XGB \u00b7 CB \u00b7 LGBM \u00b7 GB')
    : 'LR \u00b7 GB \u00b7 KNN';
  var voteType = modelType === 'phishvote' ? 'Soft \u00b7 rank-weighted' : 'Hard \u00b7 majority';

  var loadNote = modelData ? '' : '<div class="model-warn">\u26a0\ufe0f Model file not found \u2014 using heuristic scoring</div>';
  var domNote  = STATE.domFeatures === null
    ? '<div class="dom-note">\u23f3 Analysing page\u2026</div>'
    : (Object.keys(STATE.domFeatures).length === 0
      ? '<div class="dom-note">\u26a0\ufe0f DOM scan limited (restricted page)</div>'
      : '');

  var html =
    loadNote +
    domNote +

    // Model toggle
    '<div class="toggle-wrap">' +
      '<div class="toggle-label">Detection Model \u00b7 UCI-2015</div>' +
      '<div class="toggle-row">' +
        '<button class="toggle-btn' + (modelType === 'phishvote' ? ' active' : '') + '" data-model="phishvote">' +
          '<span class="tb-name">\ud83d\udee1\ufe0f PhishVote</span>' +
          '<span class="tb-sub">RF+XGB+CB+LGBM+GB \u00b7 soft vote</span>' +
        '</button>' +
        '<button class="toggle-btn' + (modelType === 'baseline' ? ' active' : '') + '" data-model="baseline">' +
          '<span class="tb-name">\ud83d\udcca Saeed (2025)</span>' +
          '<span class="tb-sub">LR+GB+KNN \u00b7 hard vote</span>' +
        '</button>' +
      '</div>' +
    '</div>' +

    // URL bar
    '<div class="url-bar">' +
      '<div class="url-tag">Scanning</div>' +
      '<div class="url-val" title="' + url + '">' + url + '</div>' +
    '</div>' +

    // Result
    '<div class="result-section">' +
      '<div class="risk-badge ' + risk.cls + '">' +
        '<span>' + risk.badge + '</span>' +
        '<span>' + risk.level + '</span>' +
      '</div>' +
      '<div class="prob-row">' +
        '<span class="prob-lbl">P(phish)</span>' +
        '<div class="prob-track"><div class="prob-fill" style="width:' + probPct + '%;background:' + risk.color + '"></div></div>' +
        '<span class="prob-num" style="color:' + risk.color + '">' + probPct + '%</span>' +
      '</div>' +
      '<div class="threshold-row">' +
        ensembleName + ' \u00b7 ' + voterList + ' \u00b7 ' + voteType +
        ' \u00b7 \u03b8=' + threshold +
        ' \u00b7 ' + phishSig + '\u26a0 ' + safeSig + '\u2713 ' + neutSig + '\u25a1 / ' + totalFeat +
      '</div>' +
    '</div>' +

    // Voters
    '<div class="voters-row">' + renderVoters(voters, threshold) + '</div>' +

    // Features
    '<div class="feat-section">' +
      '<div class="sect-hdr">' +
        '<span class="sect-title">Feature Analysis (' + totalFeat + ' signals \u00b7 UCI-2015)</span>' +
        '<span class="sect-toggle" id="feat-toggle">' + (showFeats ? '\u25b2 hide' : '\u25bc show') + '</span>' +
      '</div>' +
      '<div class="feat-grid" id="feat-grid" style="display:' + (showFeats ? 'grid' : 'none') + '">' +
        (features ? renderFeatures(features) : '<div style="color:var(--text3);font-size:10px;padding:6px">Could not extract features from this URL</div>') +
      '</div>' +
    '</div>' +

    // Compare toggle
    '<div style="padding:0 14px 8px;border-top:1px solid var(--border)">' +
      '<button class="compare-btn" id="compare-toggle">' +
        (showCompare ? '\u25b2 Hide comparison' : '\u25bc Compare PhishVote vs Saeed (2025)') +
      '</button>' +
    '</div>' +

    (showCompare ? renderCompare(models) : '') +

    // Footer
    '<div class="footer">' +
      '<span class="footer-note">PhishVote v2.0 \u00b7 UCI-2015 \u00b7 Capstone Research</span>' +
      '<button class="rescan-btn" id="rescan-btn">\u27f3 Rescan</button>' +
    '</div>';

  document.getElementById('root').innerHTML = html;
  bindEvents();
}

// ─── Event binding ────────────────────────────────────────────────────────────
function bindEvents() {
  document.querySelectorAll('.toggle-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      STATE.modelType = btn.dataset.model;
      render();
    });
  });

  var ft = document.getElementById('feat-toggle');
  if (ft) ft.addEventListener('click', function() {
    STATE.showFeats = !STATE.showFeats;
    render();
  });

  var ct = document.getElementById('compare-toggle');
  if (ct) ct.addEventListener('click', function() {
    STATE.showCompare = !STATE.showCompare;
    render();
  });

  var rb = document.getElementById('rescan-btn');
  if (rb) rb.addEventListener('click', function() {
    document.getElementById('root').innerHTML =
      '<div class="loading"><div class="spinner"></div><p>Rescanning\u2026</p></div>';
    STATE.features    = null;
    STATE.domFeatures = null;
    analyseTab(STATE.tabId);
  });
}

// ─── Network feature extraction (RDAP API for WHOIS) ──────────────────────────
async function getNetworkFeatures(url) {
  var feats = {};
  var host;
  try { host = new URL(url).hostname; } catch(e) { return feats; }
  
  // Basic root domain heuristic for RDAP lookups
  var parts = host.split('.');
  var root = parts.length > 2 && parts[parts.length-2].length > 3
             ? parts.slice(-2).join('.')
             : parts.length > 2 ? parts.slice(-3).join('.') : host;

  try {
    // Timeout fetch to prevent hanging the network pass if RDAP server is slow
    var controller = new AbortController();
    var id = setTimeout(function(){ controller.abort(); }, 3000);
    var resp = await fetch('https://rdap.org/domain/' + root, { signal: controller.signal });
    clearTimeout(id);
    
    if (resp.ok) {
      var data = await resp.json();
      var events = data.events || [];
      var regEvent = events.find(function(e) { return e.eventAction === 'registration'; });
      var expEvent = events.find(function(e) { return e.eventAction === 'expiration'; });
      var now = new Date();

      if (regEvent && regEvent.eventDate) {
         // Age >= 6 months -> 1 (Safe), else -> -1 (Phish)
         var ageMonths = (now - new Date(regEvent.eventDate)) / (1000 * 60 * 60 * 24 * 30.44);
         feats.AgeofDomain = ageMonths >= 6 ? 1 : -1;
      }
      if (expEvent && expEvent.eventDate) {
         // Expires in > 1 year -> 1 (Safe), <= 1 year -> -1 (Phish)
         var expYears = (new Date(expEvent.eventDate) - now) / (1000 * 60 * 60 * 24 * 365.25);
         feats.DomainRegLen = expYears > 1 ? 1 : -1;
      }
    }
  } catch(e) {
    // Ignore fetch errors (CORS, unhandled TLD, or timeout)
  }
  return feats;
}

// ─── Full analysis pipeline ───────────────────────────────────────────────────
async function analyseTab(tabId) {
  // URL features (synchronous, always available)
  var urlFeatures = extractURLFeatures(STATE.url);

  // Start with URL-only features so UI is responsive immediately
  STATE.features    = urlFeatures;
  STATE.domFeatures = null;
  render();

  // DOM features (async, injected into the live page) + Network (RDAP)
  var domPromise = getDOMFeatures(tabId);
  var netPromise = getNetworkFeatures(STATE.url);
  var results = await Promise.all([domPromise, netPromise]);
  
  // Merge DOM elements and Network elements into one async object
  STATE.domFeatures = Object.assign({}, results[0], results[1]);

  // Merge URL + Async and re-render with complete feature set
  STATE.features = mergeFeatures(urlFeatures, STATE.domFeatures);
  render();
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async function() {
  // Load models in the background
  loadModels().then(function(m) {
    STATE.models = m;
    if (STATE.features !== null) render(); // re-render now that models are ready
  }).catch(function(e) {
    console.warn('PhishVote: loadModels failed', e);
    STATE.models = {};
  });

  chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.url) {
      document.getElementById('root').innerHTML =
        '<div class="err">\u26a0\ufe0f Cannot scan this page.<br><small>chrome:// and edge:// pages are restricted.</small></div>';
      return;
    }
    STATE.url   = tab.url;
    STATE.tabId = tab.id;
    analyseTab(tab.id);
  });
});

