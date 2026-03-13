// detail.js — PhishVote v7 (light mode, no voter weights)

var _tabId  = null;
var _result = null;
var _filter = 'all';

function chip(val) {
  if (val === -1) return '<span class="chip p">−1 phish</span>';
  if (val ===  1) return '<span class="chip s">+1 safe</span>';
  return                 '<span class="chip n"> 0 neut</span>';
}

function pct(v) { return Math.round(v * 100); }

function timeAgo(ts) {
  var s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)   return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  return Math.floor(s / 3600) + 'h ago';
}

function shortURL(url) {
  try {
    var u = new URL(url);
    return u.hostname + (u.pathname.length > 1 ? u.pathname.substring(0, 24) + '…' : '');
  } catch(e) { return url.substring(0, 32) + '…'; }
}

// ── Risk color map (light mode) ───────────────────────────────────────────────
function riskColor(cls) {
  return {
    'safe':        '#16a34a',
    'likely-safe': '#4d7c0f',
    'suspicious':  '#c2410c',
    'phishing':    '#be123c',
    'high-risk':   '#991b1b',
  }[cls] || '#1d4ed8';
}

// ── Plain-language verdict explanation ───────────────────────────────────────
function buildExplanation(result) {
  var prob     = result.prob;
  var risk     = result.risk;
  var nPhish   = result.nPhish || 0;
  var nSafe    = result.nSafe  || 0;
  var topPhish = result.topPhish || [];
  var topSafe  = result.topSafe  || [];
  var probPct  = pct(prob);
  var t        = result.threshold || 0.5;

  if (risk.cls === 'safe' || risk.cls === 'likely-safe') {
    return {
      text: 'This page shows <b>' + nSafe + ' out of 30 legitimate signals</b>. ' +
        (topSafe.length ? 'The strongest safe indicators are <b>' + topSafe.slice(0, 2).join('</b> and <b>') + '</b>. ' : '') +
        'The PhishVote ensemble scored it at <b>' + probPct + '% phishing probability</b>, ' +
        'well below the detection threshold of <b>θ = ' + t + '</b>.',
      phishChips: topPhish, safeChips: topSafe
    };
  }
  if (risk.cls === 'suspicious') {
    return {
      text: 'This page shows <b>mixed signals</b>. The strongest phishing indicators are ' +
        (topPhish.length ? '<b>' + topPhish.join('</b>, <b>') + '</b>' : 'structural URL anomalies') + '. ' +
        'These are partially offset by ' + nSafe + ' safe signals. ' +
        'PhishVote scored this at <b>' + probPct + '%</b> — above the suspicion level ' +
        'but below the <b>θ = ' + t + ' phishing threshold</b>. Proceed with caution.',
      phishChips: topPhish, safeChips: topSafe
    };
  }
  return {
    text: 'This page triggered <b>' + nPhish + ' phishing signals</b>. ' +
      'The highest-importance indicators are ' +
      (topPhish.length ? '<b>' + topPhish.join('</b>, <b>') + '</b>' : 'multiple URL anomalies') + ', ' +
      'which carry the greatest weight in the PhishVote model. ' +
      'The ensemble scored this at <b>' + probPct + '%</b> — ' +
      (prob >= 0.82
        ? 'extremely high confidence of a phishing attack. Do not enter credentials.'
        : 'above the θ = ' + t + ' detection threshold. Do not enter credentials on this page.'),
    phishChips: topPhish, safeChips: topSafe
  };
}

// ── Feature rows builder ──────────────────────────────────────────────────────
function buildFeatRows(features, filter) {
  var rows = FEAT_ORDER.map(function(k) {
    return { key: k, val: features ? (features[k] !== undefined ? features[k] : 0) : 0 };
  });

  if      (filter === 'phish') rows = rows.filter(function(r) { return r.val === -1; });
  else if (filter === 'safe')  rows = rows.filter(function(r) { return r.val ===  1; });
  else if (filter === 'neut')  rows = rows.filter(function(r) { return r.val ===  0; });
  else rows.sort(function(a, b) {
    var p = function(v) { return v === -1 ? 0 : v === 1 ? 1 : 2; };
    return p(a.val) - p(b.val);
  });

  if (!rows.length) return '<div class="no-feats">No features in this category.</div>';

  return '<div class="feat-grid">' + rows.map(function(r) {
    var isDom = typeof DOM_FEATURES !== 'undefined' && DOM_FEATURES.has(r.key);
    var imp   = RF_IMPORTANCES[r.key] ? pct(RF_IMPORTANCES[r.key]) + '%' : '';
    var dim   = r.val === 0 ? 'opacity:0.42' : '';
    return '<div class="feat-row" style="' + dim + '">' +
      '<div class="feat-left">' +
        '<span class="src ' + (isDom ? 'dom' : 'url') + '">' + (isDom ? 'DOM' : 'URL') + '</span>' +
        '<span class="feat-label" title="' + (FEAT_LABELS[r.key] || r.key) + '">' + (FEAT_LABELS[r.key] || r.key) + '</span>' +
      '</div>' +
      '<span class="feat-imp">' + imp + '</span>' +
      chip(r.val) +
    '</div>';
  }).join('') + '</div>';
}

// ── Main render ───────────────────────────────────────────────────────────────
function renderPage(result, history) {
  _result = result;
  var url       = result.url;
  var prob      = result.prob;
  var risk      = result.risk;
  var nPhish    = result.nPhish  || 0;
  var nSafe     = result.nSafe   || 0;
  var nNeut     = result.nNeut   || 0;
  var domSigs   = result.domSigs || 0;
  var features  = result.features || {};
  var threshold = result.threshold || 0.5;

  var probPct  = pct(prob);
  var safePct  = 100 - probPct;
  var barColor = riskColor(risk.cls);

  // Explanation
  var exp = buildExplanation(result);
  var expHTML =
    '<div class="explain-box">' +
      '<div class="explain-title">Why this verdict</div>' +
      '<div class="explain-body">' + exp.text + '</div>' +
      '<div class="explain-chips">' +
        exp.phishChips.map(function(c) { return '<span class="explain-chip p">⚠ ' + c + '</span>'; }).join('') +
        exp.safeChips.map(function(c)  { return '<span class="explain-chip s">✓ ' + c + '</span>';  }).join('') +
      '</div>' +
    '</div>';

  // Full 30-feature importance chart
  var maxImp   = RF_IMPORTANCES['HTTPS']; // 0.3138 = 100% bar width reference
  var impSorted = FEAT_ORDER.slice().sort(function(a, b) {
    return (RF_IMPORTANCES[b] || 0) - (RF_IMPORTANCES[a] || 0);
  });
  var impHTML = impSorted.map(function(k, i) {
    var val    = features[k] !== undefined ? features[k] : 0;
    var imp    = RF_IMPORTANCES[k] || 0;
    var barW   = Math.round((imp / maxImp) * 100);
    var barClr = val === -1 ? '#dc2626' : val === 1 ? '#16a34a' : '#93c5fd';
    var dim    = val === 0 ? 'opacity:0.45' : '';
    return '<div class="imp-row" style="' + dim + '">' +
      '<div class="imp-rank">' + (i + 1) + '</div>' +
      '<div class="imp-name" title="' + (FEAT_LABELS[k] || k) + '">' + (FEAT_LABELS[k] || k) + '</div>' +
      '<div class="imp-trk"><div class="imp-fill" style="width:' + barW + '%;background:' + barClr + '"></div></div>' +
      '<div class="imp-pct">' + pct(imp) + '%</div>' +
      '<div class="imp-chip2 ' + (val === -1 ? 'p' : val === 1 ? 's' : 'n') + '">' +
        (val === -1 ? 'phish' : val === 1 ? 'safe' : 'neut') + '</div>' +
    '</div>';
  }).join('');

  // Feature filter counts
  var counts = {
    phish: FEAT_ORDER.filter(function(k) { return features[k] === -1; }).length,
    safe:  FEAT_ORDER.filter(function(k) { return features[k] ===  1; }).length,
    neut:  FEAT_ORDER.filter(function(k) { return !features || features[k] === 0; }).length,
  };
  var tabsHTML = ['all', 'phish', 'safe', 'neut'].map(function(f) {
    var lbl = f === 'all' ? 'All 30' : f === 'phish' ? 'Phishing' : f === 'safe' ? 'Safe' : 'Neutral';
    var cnt = f === 'all' ? 30 : f === 'phish' ? counts.phish : f === 'safe' ? counts.safe : counts.neut;
    return '<div class="ftab' + (f === _filter ? ' active' : '') + '" data-f="' + f + '">' +
      lbl + '<span class="cnt">' + cnt + '</span></div>';
  }).join('');

  // DOM status
  var domStatusHTML = domSigs > 0
    ? '<div class="dom-bar ok">✅ DOM scan complete · ' + domSigs + ' DOM signals detected</div>'
    : '<div class="dom-bar warn">⚠️ DOM scan restricted — URL features only</div>';

  // History
  var histHTML = (history && history.length)
    ? history.map(function(h) {
        return '<div class="hist-item" data-url="' + h.url + '">' +
          '<span class="hist-badge">' + h.badge + '</span>' +
          '<span class="hist-url" title="' + h.url + '">' + shortURL(h.url) + '</span>' +
          '<span class="hist-time">' + timeAgo(h.ts) + '</span>' +
        '</div>';
      }).join('')
    : '<div style="font-family:var(--mono);font-size:9px;color:var(--t3)">No history yet.</div>';

  document.getElementById('root').innerHTML =
    // URL
    '<div class="url-box">' +
      '<span class="url-lbl">Scanning</span>' +
      '<span class="url-val">' + url + '</span>' +
    '</div>' +
    domStatusHTML +

    // Hero
    '<div class="hero ' + risk.cls + '">' +
      '<div class="hero-icon">' + risk.badge + '</div>' +
      '<div>' +
        '<div class="hero-level ' + risk.cls + '">' + risk.level + '</div>' +
        '<div class="hero-sub">PhishVote · RF+XGB+CB+LGBM+GB · θ=' + threshold + ' · 97.42% train acc · UCI-2015</div>' +
      '</div>' +
      '<div class="hero-right">' +
        '<div class="hero-plbl">P(phish)</div>' +
        '<div class="hero-pct" style="color:' + barColor + '">' + probPct + '%</div>' +
        '<div class="hero-plbl">probability</div>' +
      '</div>' +
    '</div>' +

    // Explanation
    expHTML +

    // Signal summary + Risk score
    '<div class="g2">' +
      '<div class="card">' +
        '<div class="card-title">Signal Summary</div>' +
        '<div class="sig3">' +
          '<div class="sig-cell"><div class="sig-n p">' + nPhish + '</div><div class="sig-l">Phishing</div></div>' +
          '<div class="sig-cell"><div class="sig-n s">' + nSafe  + '</div><div class="sig-l">Safe</div></div>' +
          '<div class="sig-cell"><div class="sig-n n">' + nNeut  + '</div><div class="sig-l">Neutral</div></div>' +
        '</div>' +
      '</div>' +
      '<div class="card">' +
        '<div class="card-title">Risk Score</div>' +
        '<div class="pb">' +
          '<div class="pb-row"><div class="pb-name">Phishing Probability</div><div class="pb-pct" style="color:' + barColor + '">' + probPct + '%</div></div>' +
          '<div class="pb-trk"><div class="pb-fill" style="width:' + probPct + '%;background:' + barColor + '"></div></div>' +
          '<div class="pb-note">' + (probPct >= threshold * 100 ? '⚠️ Above threshold' : '✅ Below threshold') + ' θ=' + threshold + '</div>' +
        '</div>' +
        '<div class="pb" style="margin-top:9px">' +
          '<div class="pb-row"><div class="pb-name">Legitimate Confidence</div><div class="pb-pct" style="color:#16a34a">' + safePct + '%</div></div>' +
          '<div class="pb-trk"><div class="pb-fill" style="width:' + safePct + '%;background:#16a34a"></div></div>' +
        '</div>' +
      '</div>' +
    '</div>' +

    // Full importance chart
    '<div class="card" style="margin-bottom:14px">' +
      '<div class="card-title">All 30 Feature Importances (RF Gini — sorted by weight)</div>' +
      '<div class="imp-chart">' + impHTML + '</div>' +
    '</div>' +

    // Feature breakdown with filter tabs
    '<div class="feat-section">' +
      '<div class="card-title" style="margin-bottom:9px">Feature Breakdown · UCI-2015</div>' +
      '<div class="feat-tabs" id="feat-tabs">' + tabsHTML + '</div>' +
      '<div id="feat-rows">' + buildFeatRows(features, _filter) + '</div>' +
    '</div>' +

    // History (full width)
    '<div class="card" style="margin-bottom:14px">' +
      '<div class="card-title">Recent Scans</div>' +
      histHTML +
    '</div>' +

    '<div class="footer">' +
      'PhishVote v7.0 · Duhaylungsod & Dumalogdog · University of Mindanao · ' +
      'UCI-2015 Dataset (Mohammad et al.) · 30 Heuristic Features · θ=0.5 · 97.42% Accuracy<br>' +
      'Ensemble: RF(0.13) + XGB(0.33) + CB(0.20) + LGBM(0.27) + GB(0.07) · Adaptive Soft-Voting · Stratified 80/20 · SMOTE' +
    '</div>';

  // Feature filter tabs
  document.getElementById('feat-tabs').addEventListener('click', function(e) {
    var t = e.target.closest('.ftab');
    if (!t) return;
    _filter = t.dataset.f;
    document.querySelectorAll('.ftab').forEach(function(el) { el.classList.remove('active'); });
    t.classList.add('active');
    document.getElementById('feat-rows').innerHTML = buildFeatRows(features, _filter);
  });

  // History item clicks
  document.querySelectorAll('.hist-item').forEach(function(el) {
    el.addEventListener('click', function() { chrome.tabs.create({ url: el.dataset.url }); });
  });

  // Copy URL
  document.getElementById('btn-copy-url').addEventListener('click', function() {
    navigator.clipboard.writeText(url).then(function() {
      var b = document.getElementById('btn-copy-url');
      b.textContent = '✅ Copied'; b.classList.add('copied');
      setTimeout(function() { b.textContent = '📋 Copy URL'; b.classList.remove('copied'); }, 1500);
    });
  });
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function() {
  var params = new URLSearchParams(window.location.search);
  _tabId = parseInt(params.get('tabId'));

  if (!_tabId) {
    document.getElementById('root').innerHTML =
      '<div class="loading"><div class="err-box">No tab ID found.<br>Click the PhishVote icon on a website first.</div></div>';
    return;
  }

  chrome.storage.local.get(['pv_' + _tabId, 'pv_history'], function(data) {
    var result  = data['pv_' + _tabId];
    var history = data['pv_history'] || [];

    if (!result) {
      document.getElementById('root').innerHTML =
        '<div class="loading"><div class="err-box">No analysis found for this tab.<br>Navigate to a website and wait for PhishVote to finish scanning.</div></div>';
      return;
    }

    renderPage(result, history);
  });

  // Rescan
  document.getElementById('btn-rescan').addEventListener('click', function() {
    var btn = document.getElementById('btn-rescan');
    btn.textContent = '⟳ Scanning…'; btn.disabled = true;
    chrome.storage.local.remove('pv_' + _tabId, function() {
      chrome.tabs.get(_tabId, function(tab) {
        if (chrome.runtime.lastError || !tab) {
          btn.textContent = '⟳ Rescan'; btn.disabled = false; return;
        }
        chrome.tabs.reload(_tabId, {}, function() {
          btn.textContent = '⟳ Rescan'; btn.disabled = false;
        });
      });
    });
  });
});
