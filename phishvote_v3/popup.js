// popup.js — PhishVote v3  |  PhishVote ensemble only, UCI-2015
// engine.js loads first and provides:
//   FEAT_LABELS, FEAT_ORDER, DOM_FEATURES,
//   extractURLFeatures, mergeFeatures,
//   scoreWithModel, getVoterProbs, getRiskInfo

var STATE = {
  url:         '',
  tabId:       null,
  model:       null,       // loaded from phishvote_model_dsbase.json
  features:    null,       // merged URL + DOM features
  domFeatures: null,       // raw DOM result (null = pending, {} = failed/restricted)
  showFeats:   true,
};

// ─── Load model JSON ──────────────────────────────────────────────────────────
async function loadModel() {
  try {
    var resp = await fetch(chrome.runtime.getURL('models/phishvote_model_dsbase.json'));
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    return await resp.json();
  } catch(e) {
    console.warn('PhishVote: model load failed —', e.message);
    return null;
  }
}

// ─── DOM extraction (injected into live page via scripting API) ───────────────
// extractPageDOM runs INSIDE the page — must be fully self-contained.
function extractPageDOM() {
  var pageUrl = window.location.href;
  var host;
  try { host = new URL(pageUrl).hostname.toLowerCase(); } catch(e) { host = ''; }
  var R = {};

  // ── Favicon ─────────────────────────────────────────────────────────────────
  var favEls = Array.from(document.querySelectorAll('link[rel*="icon"]'));
  if (favEls.length === 0) {
    R.Favicon = 0;  // no favicon declared — neutral
  } else {
    var extFav = favEls.some(function(el) {
      var href = el.getAttribute('href') || '';
      if (!href || href.startsWith('data:')) return false;
      if (href.startsWith('/') && !href.startsWith('//')) return false;
      try { return new URL(href, pageUrl).hostname.toLowerCase() !== host; } catch(e) { return false; }
    });
    R.Favicon = extFav ? -1 : 1;
  }

  // ── Request URL — ratio of external resources (img/script/form/audio/video) ─
  // <22% external → 1 (legit), 22–61% → 0 (suspicious), >61% → -1 (phishing)
  var reqEls = Array.from(document.querySelectorAll(
    'img[src], script[src], form[action], audio[src], video[src], embed[src], object[data]'
  ));
  if (reqEls.length === 0) {
    R.RequestURL = 1;
  } else {
    var extReq = reqEls.filter(function(el) {
      var u = el.getAttribute('src') || el.getAttribute('data') || el.getAttribute('action') || '';
      if (!u || u.startsWith('data:') || u.startsWith('#') || u.startsWith('javascript:')) return false;
      if (u.startsWith('/') && !u.startsWith('//')) return false;
      try { return new URL(u, pageUrl).hostname.toLowerCase() !== host; } catch(e) { return false; }
    }).length;
    var r1 = extReq / reqEls.length;
    R.RequestURL = r1 < 0.22 ? 1 : r1 < 0.61 ? 0 : -1;
  }

  // ── Anchor URL — ratio of <a href> linking off-domain ────────────────────────
  // <31% → 1, 31–67% → 0, >67% → -1
  var anchors = Array.from(document.querySelectorAll('a[href]'));
  if (anchors.length === 0) {
    R.AnchorURL = 1;
  } else {
    var extAnch = anchors.filter(function(el) {
      var h = el.getAttribute('href') || '';
      if (!h || h.startsWith('#') || h.startsWith('javascript:') ||
          h.startsWith('mailto:') || h.startsWith('tel:')) return false;
      if (h.startsWith('/') && !h.startsWith('//')) return false;
      try { return new URL(h, pageUrl).hostname.toLowerCase() !== host; } catch(e) { return false; }
    }).length;
    var r2 = extAnch / anchors.length;
    R.AnchorURL = r2 < 0.31 ? 1 : r2 < 0.67 ? 0 : -1;
  }

  // ── Links in Script/Meta Tags — external ratio ────────────────────────────
  // <17% → 1, 17–81% → 0, >81% → -1
  var tagEls = Array.from(document.querySelectorAll('script[src], link[href], meta[content]'));
  if (tagEls.length === 0) {
    R.LinksInScriptTags = 1;
  } else {
    var extTag = tagEls.filter(function(el) {
      var u = el.getAttribute('src') || el.getAttribute('href') || el.getAttribute('content') || '';
      if (!u) return false;
      if (u.startsWith('/') && !u.startsWith('//')) return false;
      try { return new URL(u, pageUrl).hostname.toLowerCase() !== host; } catch(e) { return false; }
    }).length;
    var r3 = extTag / tagEls.length;
    R.LinksInScriptTags = r3 < 0.17 ? 1 : r3 < 0.81 ? 0 : -1;
  }

  // ── Server Form Handler — where do forms submit? ──────────────────────────
  // 1 = same domain, 0 = blank/empty, -1 = external/mailto
  var forms = Array.from(document.querySelectorAll('form'));
  if (forms.length === 0) {
    R.ServerFormHandler = 1;
  } else {
    var sfhVals = forms.map(function(f) {
      var action = (f.getAttribute('action') || '').trim();
      if (!action || action.toLowerCase() === 'about:blank') return 0;
      if (action.toLowerCase().startsWith('mailto:')) return -1;
      if (action.startsWith('/') && !action.startsWith('//')) return 1;
      try { return new URL(action, pageUrl).hostname.toLowerCase() === host ? 1 : -1; }
      catch(e) { return 1; }
    });
    R.ServerFormHandler = sfhVals.indexOf(-1) !== -1 ? -1 : sfhVals.indexOf(0) !== -1 ? 0 : 1;
  }

  // ── InfoEmail (Submitting to Email) ────────────────────────────────────────
  var hasMailtoForm = Array.from(document.querySelectorAll('form')).some(function(f) {
    return (f.getAttribute('action') || '').toLowerCase().startsWith('mailto:');
  });
  R.InfoEmail = hasMailtoForm ? -1 : 1;

  // ── Website Forwarding — redirect count via Navigation Timing API ─────────
  var redirectCount = 0;
  try {
    var navEntries = performance.getEntriesByType && performance.getEntriesByType('navigation');
    if (navEntries && navEntries.length > 0) {
      redirectCount = navEntries[0].redirectCount || 0;
    } else if (performance.navigation) {
      redirectCount = performance.navigation.redirectCount || 0;
    }
  } catch(e) {}
  R.WebsiteForwarding = redirectCount === 0 ? 1 : redirectCount === 1 ? 0 : -1;

  // ── Status Bar Customisation (onmouseover overwriting window.status) ──────
  var moEls = Array.from(document.querySelectorAll('[onmouseover]'));
  var hasStatusMod = moEls.some(function(el) {
    var mo = (el.getAttribute('onmouseover') || '').toLowerCase();
    return mo.indexOf('window.status') !== -1 || mo.indexOf('status =') !== -1;
  });
  if (!hasStatusMod) {
    hasStatusMod = Array.from(document.querySelectorAll('script:not([src])')).some(function(s) {
      var t = s.textContent || '';
      return t.indexOf('window.status') !== -1 && t.indexOf('mouseover') !== -1;
    });
  }
  R.StatusBarCust = hasStatusMod ? -1 : 1;

  // ── Disable Right Click ────────────────────────────────────────────────────
  var rcDisabled = false;
  [document.body, document.documentElement].forEach(function(el) {
    if (el && (el.getAttribute('oncontextmenu') || '').toLowerCase().indexOf('return false') !== -1) {
      rcDisabled = true;
    }
  });
  if (!rcDisabled) {
    rcDisabled = Array.from(document.querySelectorAll('script:not([src])')).some(function(s) {
      var t = s.textContent || '';
      return t.indexOf('contextmenu') !== -1 &&
             (t.indexOf('return false') !== -1 || t.indexOf('preventDefault') !== -1);
    });
  }
  R.DisableRightClick = rcDisabled ? -1 : 1;

  // ── Popup Window ───────────────────────────────────────────────────────────
  var hasPopup = Array.from(document.querySelectorAll('script:not([src])')).some(function(s) {
    return (s.textContent || '').indexOf('window.open(') !== -1;
  });
  R.UsingPopupWindow = hasPopup ? -1 : 1;

  // ── iFrame Redirection ─────────────────────────────────────────────────────
  // 1 = no iframes, -1 = hidden/invisible iframe, 0 = visible iframes present
  var iframes = Array.from(document.querySelectorAll('iframe'));
  var hiddenIframe = iframes.some(function(fr) {
    var w     = fr.getAttribute('width')  || '';
    var h     = fr.getAttribute('height') || '';
    var style = (fr.getAttribute('style') || '').replace(/\s/g,'').toLowerCase();
    return w === '0' || h === '0' ||
           style.indexOf('display:none') !== -1 ||
           style.indexOf('visibility:hidden') !== -1 ||
           style.indexOf('width:0') !== -1 ||
           style.indexOf('height:0') !== -1;
  });
  R.IframeRedirection = iframes.length === 0 ? 1 : hiddenIframe ? -1 : 0;

  return R;
}

async function getDOMFeatures(tabId) {
  try {
    var results = await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func:   extractPageDOM,
    });
    return (results && results[0] && results[0].result) ? results[0].result : {};
  } catch(e) {
    console.warn('PhishVote: DOM extraction failed —', e.message);
    return {};
  }
}

// ─── Render helpers ───────────────────────────────────────────────────────────
function pct(v) { return Math.round(v * 100); }

function chip(val) {
  if (val === -1) return '<span class="chip p">−1 phish</span>';
  if (val ===  1) return '<span class="chip s">+1 safe</span>';
  return                 '<span class="chip n"> 0 neut</span>';
}

function renderVoters(voters, threshold) {
  return voters.map(function(v) {
    var barW  = Math.round(v.prob * 100);
    var color = v.prob >= threshold ? '#e74c3c' : '#2ecc71';
    return (
      '<div class="vc">' +
        '<div class="vc-top">' +
          '<span class="vc-name">' + v.name + '</span>' +
          '<span class="vc-prob" style="color:' + color + '">' + barW + '%</span>' +
        '</div>' +
        '<div class="vc-bar-track"><div class="vc-bar-fill" style="width:' + barW + '%;background:' + color + '"></div></div>' +
        '<div class="vc-w">weight · ' + v.weight.toFixed(4) + '</div>' +
      '</div>'
    );
  }).join('');
}

function renderFeatures(features, domPending) {
  // Build rows in canonical FEAT_ORDER; sort: phish first, safe second, neut last
  var rows = FEAT_ORDER.map(function(k) {
    return { key: k, val: features[k] !== undefined ? features[k] : 0 };
  });
  rows.sort(function(a, b) {
    var pri = function(v) { return v === -1 ? 0 : v === 1 ? 1 : 2; };
    return pri(a.val) - pri(b.val);
  });

  return rows.map(function(r) {
    var label    = FEAT_LABELS[r.key] || r.key;
    var isDom    = DOM_FEATURES.has(r.key);
    var dimStyle = r.val === 0 ? 'opacity:0.40' : '';

    // DOM features that are still pending show a spinner instead of chip
    var chipHtml;
    if (isDom && domPending && r.val === 0) {
      chipHtml = '<span class="chip-wait">…</span>';
    } else {
      chipHtml = chip(r.val);
    }

    var srcTag = isDom
      ? '<span class="src dom">DOM</span>'
      : '<span class="src url">URL</span>';

    return (
      '<div class="feat-row" style="' + dimStyle + '">' +
        '<div class="feat-left">' + srcTag + '<span class="feat-label">' + label + '</span></div>' +
        chipHtml +
      '</div>'
    );
  }).join('');
}

// ─── Main render ──────────────────────────────────────────────────────────────
function render() {
  var url         = STATE.url;
  var model       = STATE.model;
  var features    = STATE.features;
  var domPending  = STATE.domFeatures === null;   // null = still fetching
  var domFailed   = STATE.domFeatures !== null && Object.keys(STATE.domFeatures).length === 0;

  var prob      = (features && model) ? scoreWithModel(features, model) : 0.10;
  var voters    = (features && model) ? getVoterProbs(features, model)  : [];
  var threshold = (model && model.threshold) ? model.threshold : 0.5;
  var risk      = getRiskInfo(prob, threshold);
  var probPct   = pct(prob);

  var allVals  = features ? FEAT_ORDER.map(function(k) { return features[k] !== undefined ? features[k] : 0; }) : [];
  var nPhish   = allVals.filter(function(v){ return v === -1; }).length;
  var nSafe    = allVals.filter(function(v){ return v ===  1; }).length;
  var nNeut    = allVals.filter(function(v){ return v ===  0; }).length;

  // Model info line
  var voters_str = model && model.selected_voters ? model.selected_voters.join(' · ') : 'RF · XGB · CB · LGBM · GB';
  var acc_str    = model && model.phishvote_metrics ? model.phishvote_metrics.accuracy + '%' : '97.42%';

  // DOM status note
  var domStatusHtml = '';
  if (domPending) {
    domStatusHtml = '<div class="dom-status pending">🔍 Scanning page DOM…</div>';
  } else if (domFailed) {
    domStatusHtml = '<div class="dom-status warn">⚠️ DOM scan restricted — URL features only</div>';
  } else {
    var nDomFilled = Object.values(STATE.domFeatures).filter(function(v){ return v !== 0; }).length;
    domStatusHtml = '<div class="dom-status ok">✅ DOM scan complete · ' + nDomFilled + ' DOM signals detected</div>';
  }

  var modelWarn = !model
    ? '<div class="model-warn">⚠️ Model JSON not loaded — heuristic scoring active</div>'
    : '';

  var html = modelWarn +

    // ── URL bar
    '<div class="url-bar">' +
      '<span class="url-tag">Scanning</span>' +
      '<span class="url-val" title="' + url + '">' + url + '</span>' +
    '</div>' +

    domStatusHtml +

    // ── Result badge
    '<div class="result-wrap">' +
      '<div class="risk-badge ' + risk.cls + '">' +
        risk.badge + ' ' + risk.level +
      '</div>' +
      '<div class="prob-row">' +
        '<span class="prob-lbl">P(phish)</span>' +
        '<div class="prob-track"><div class="prob-fill" style="width:' + probPct + '%;background:' + risk.color + '"></div></div>' +
        '<span class="prob-num" style="color:' + risk.color + '">' + probPct + '%</span>' +
      '</div>' +
      '<div class="signal-row">' +
        '<span class="sig-p">' + nPhish + ' phish</span>' +
        '<span class="sig-s">' + nSafe  + ' safe</span>' +
        '<span class="sig-n">' + nNeut  + ' neut</span>' +
        '<span class="sig-t">of 30</span>' +
        '<span class="model-info">PhishVote · ' + voters_str + ' · θ=' + threshold + ' · Train acc ' + acc_str + '</span>' +
      '</div>' +
    '</div>' +

    // ── Voter bars
    '<div class="voters-section">' +
      '<div class="section-label">VOTER PROBABILITIES</div>' +
      '<div class="voters-grid">' + renderVoters(voters, threshold) + '</div>' +
    '</div>' +

    // ── Feature list
    '<div class="feats-section">' +
      '<div class="feats-header">' +
        '<span class="section-label">30 FEATURES · UCI-2015</span>' +
        '<button class="toggle-feats" id="feat-toggle">' + (STATE.showFeats ? '▲ hide' : '▼ show') + '</button>' +
      '</div>' +
      '<div class="feat-list" id="feat-list" style="display:' + (STATE.showFeats ? 'block' : 'none') + '">' +
        (features ? renderFeatures(features, domPending) : '<p class="no-feat">URL could not be parsed</p>') +
      '</div>' +
    '</div>' +

    // ── Footer
    '<div class="footer">' +
      '<span class="footer-txt">PhishVote v3.0 · UCI-2015 · Capstone</span>' +
      '<button class="btn-rescan" id="rescan-btn">⟳ Rescan</button>' +
    '</div>';

  document.getElementById('root').innerHTML = html;
  bindEvents();
}

// ─── Events ───────────────────────────────────────────────────────────────────
function bindEvents() {
  var ft = document.getElementById('feat-toggle');
  if (ft) ft.addEventListener('click', function() {
    STATE.showFeats = !STATE.showFeats;
    render();
  });

  var rb = document.getElementById('rescan-btn');
  if (rb) rb.addEventListener('click', function() {
    document.getElementById('root').innerHTML =
      '<div class="loading"><div class="spinner"></div><p>Rescanning…</p></div>';
    STATE.features    = null;
    STATE.domFeatures = null;
    analyseTab(STATE.tabId);
  });
}

// ─── Analysis pipeline ────────────────────────────────────────────────────────
async function analyseTab(tabId) {
  // 1. Compute URL features immediately → render a first pass
  var urlFeats = extractURLFeatures(STATE.url);
  STATE.features    = urlFeats;
  STATE.domFeatures = null;   // signal: DOM pending
  render();

  // 2. Inject into live page and collect DOM features
  var domFeats = await getDOMFeatures(tabId);
  STATE.domFeatures = domFeats;

  // 3. Merge and re-render with full 30-feature set
  STATE.features = mergeFeatures(urlFeats, domFeats);
  render();
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async function() {
  // Load model JSON
  STATE.model = await loadModel();

  // Get active tab
  chrome.tabs.query({ active: true, currentWindow: true }, async function(tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.url ||
        tab.url.startsWith('chrome://') ||
        tab.url.startsWith('chrome-extension://') ||
        tab.url.startsWith('edge://') ||
        tab.url.startsWith('about:')) {
      document.getElementById('root').innerHTML =
        '<div class="err">⚠️ Cannot scan this page.<br><small>Browser internal pages are restricted.</small></div>';
      return;
    }
    STATE.url   = tab.url;
    STATE.tabId = tab.id;
    analyseTab(tab.id);
  });
});
