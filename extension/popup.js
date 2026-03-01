// popup.js — PhishVote UI
// engine.js is loaded first and provides: extractFeatures, getFeatLabels,
// scoreWithModel, getVoterProbs, getRiskInfo, FEAT_LABELS_DS01, FEAT_LABELS_DSBASE

// ─── State ───────────────────────────────────────────────────────────────────
var STATE = {
  modelType:   'phishvote',   // 'phishvote' | 'baseline'
  dataset:     'ds01',        // 'ds01' | 'dsbase'
  url:         '',
  models:      {},
  showCompare: false,
  showFeats:   true,
};

// ─── Model loading ───────────────────────────────────────────────────────────
var MODEL_FILES = {
  phishvote_ds01:    'models/phishvote_model_ds01.json',
  phishvote_dsbase:  'models/phishvote_model_dsbase.json',
  baseline_ds01:     'models/baseline_model_ds01.json',
  baseline_dsbase:   'models/baseline_model_dsbase.json',
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

// ─── Render helpers ──────────────────────────────────────────────────────────
function pct(v) { return Math.round(v * 100); }

function featChip(val) {
  if (val === -1) return '<span class="feat-chip p">−1 phish</span>';
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

function renderFeatures(features, ds) {
  var labels  = getFeatLabels(ds);
  var entries = Object.entries(features);
  var active  = entries.filter(function(e){ return e[1] !== 0; });
  var neutral = entries.filter(function(e){ return e[1] === 0; });
  var sorted  = active.concat(neutral);

  return sorted.map(function(e) {
    var key = e[0], val = e[1];
    var label    = labels[key] || key;
    var dimStyle = val === 0 ? 'opacity:0.4' : '';
    return '<div class="feat-row" style="' + dimStyle + '">' +
      '<span class="feat-name">' + label + '</span>' +
      featChip(val) +
      '</div>';
  }).join('');
}

function renderCompare(models, ds) {
  var pvData = models['phishvote_' + ds];
  var blData = models['baseline_'  + ds];
  if (!pvData || !blData) return '';

  var pvM = pvData.phishvote_metrics  || {};
  var blM = blData.ensemble_metrics   || {};
  var pvWins = (pvM.accuracy || 0) >= (blM.accuracy || 0);

  return '<div class="compare-section">' +
    '<div class="sect-hdr"><span class="sect-title">📊 PhishVote vs Saeed (2025) · ' + ds.toUpperCase() + '</span></div>' +
    '<div class="compare-grid">' +
      '<div class="compare-card' + (pvWins ? ' cc-winner' : '') + '">' +
        '<div class="cc-title">🛡️ PhishVote' + (pvWins ? ' 🏆' : '') + '</div>' +
        '<div class="cc-metric"><span class="cc-key">Accuracy</span><span class="cc-val">' + (pvM.accuracy ?? '—') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">F1-Score</span><span class="cc-val">' + (pvM.f1 ?? '—') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">Precision</span><span class="cc-val">' + (pvM.precision ?? '—') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">θ*</span><span class="cc-val">' + (pvData.threshold ?? '—') + '</span></div>' +
      '</div>' +
      '<div class="compare-card' + (!pvWins ? ' cc-winner' : '') + '">' +
        '<div class="cc-title">📊 Saeed 2025' + (!pvWins ? ' 🏆' : '') + '</div>' +
        '<div class="cc-metric"><span class="cc-key">Accuracy</span><span class="cc-val">' + (blM.accuracy ?? '—') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">F1-Score</span><span class="cc-val">' + (blM.f1 ?? '—') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">Precision</span><span class="cc-val">' + (blM.precision ?? '—') + '%</span></div>' +
        '<div class="cc-metric"><span class="cc-key">θ*</span><span class="cc-val">' + (blData.threshold ?? '—') + '</span></div>' +
      '</div>' +
    '</div></div>';
}

// ─── Main render ─────────────────────────────────────────────────────────────
function render() {
  var modelType   = STATE.modelType;
  var dataset     = STATE.dataset;
  var url         = STATE.url;
  var models      = STATE.models;
  var showCompare = STATE.showCompare;
  var showFeats   = STATE.showFeats;

  var modelKey  = modelType + '_' + dataset;
  var modelData = models[modelKey];

  var features  = extractFeatures(url, dataset);
  var prob      = (features && modelData) ? scoreWithModel(features, modelData, modelType) : 0.5;
  var voters    = (features && modelData) ? getVoterProbs(features, modelData, modelType)  : [];
  var threshold = (modelData && modelData.threshold) ? modelData.threshold
                  : (modelType === 'phishvote' ? 0.5 : 0.5);
  var risk      = getRiskInfo(prob, threshold);
  var probPct   = pct(prob);

  var featLabels  = getFeatLabels(dataset);
  var phishSig    = features ? Object.values(features).filter(function(v){ return v === -1; }).length : 0;
  var safeSig     = features ? Object.values(features).filter(function(v){ return v ===  1; }).length : 0;
  var totalFeat   = Object.keys(featLabels).length;

  var ensembleName = modelType === 'phishvote' ? 'PhishVote' : 'Saeed (2025)';
  var voterList    = modelType === 'phishvote'
    ? ((modelData && modelData.selected_voters) ? modelData.selected_voters.join(' · ') : 'RF · XGB · CB · LGBM · GB')
    : 'LR · GB · KNN';
  var voteType = modelType === 'phishvote' ? 'Soft · rank-weighted' : 'Hard · majority';

  var loadNote = modelData ? '' : '<div class="model-warn">⚠️ Model file not found — using heuristic scoring</div>';

  var html =
    loadNote +
    // Model toggle
    '<div class="toggle-wrap">' +
      '<div class="toggle-label">Detection Model</div>' +
      '<div class="toggle-row">' +
        '<button class="toggle-btn' + (modelType === 'phishvote' ? ' active' : '') + '" data-model="phishvote">' +
          '<span class="tb-name">🛡️ PhishVote</span>' +
          '<span class="tb-sub">RF+XGB+CB+LGBM+GB · soft vote</span>' +
        '</button>' +
        '<button class="toggle-btn' + (modelType === 'baseline' ? ' active' : '') + '" data-model="baseline">' +
          '<span class="tb-name">📊 Saeed (2025)</span>' +
          '<span class="tb-sub">LR+GB+KNN · hard vote</span>' +
        '</button>' +
      '</div>' +
    '</div>' +

    // Dataset toggle
    '<div class="ds-toggle">' +
      '<span class="ds-label">Training Dataset</span>' +
      '<div class="ds-chips">' +
        '<div class="ds-chip' + (dataset === 'ds01' ? ' active' : '') + '" data-ds="ds01">DS01 · LegitPhish 2025</div>' +
        '<div class="ds-chip' + (dataset === 'dsbase' ? ' active' : '') + '" data-ds="dsbase">DS-Base · phishing-2020</div>' +
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
        ensembleName + ' · ' + voterList + ' · ' + voteType +
        ' · θ=' + threshold +
        ' · ' + phishSig + '⚠ ' + safeSig + '✓ of ' + totalFeat + ' signals' +
      '</div>' +
    '</div>' +

    // Voters
    '<div class="voters-row">' + renderVoters(voters, threshold) + '</div>' +

    // Features
    '<div class="feat-section">' +
      '<div class="sect-hdr">' +
        '<span class="sect-title">Feature Analysis (' + totalFeat + ' indicators · ' + dataset.toUpperCase() + ')</span>' +
        '<span class="sect-toggle" id="feat-toggle">' + (showFeats ? '▲ hide' : '▼ show') + '</span>' +
      '</div>' +
      '<div class="feat-grid" id="feat-grid" style="display:' + (showFeats ? 'grid' : 'none') + '">' +
        (features ? renderFeatures(features, dataset) : '<div style="color:var(--text3);font-size:10px;padding:6px">Could not extract features from this URL</div>') +
      '</div>' +
    '</div>' +

    // Compare toggle
    '<div style="padding:0 14px 8px;border-top:1px solid var(--border)">' +
      '<button class="compare-btn" id="compare-toggle">' +
        (showCompare ? '▲ Hide comparison' : '▼ Compare PhishVote vs Saeed (2025)') +
      '</button>' +
    '</div>' +

    (showCompare ? renderCompare(models, dataset) : '') +

    // Footer
    '<div class="footer">' +
      '<span class="footer-note">PhishVote v2.0 · Capstone Research</span>' +
      '<button class="rescan-btn" id="rescan-btn">⟳ Rescan</button>' +
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

  document.querySelectorAll('.ds-chip').forEach(function(chip) {
    chip.addEventListener('click', function() {
      STATE.dataset = chip.dataset.ds;
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
      '<div class="loading"><div class="spinner"></div><p>Rescanning…</p></div>';
    setTimeout(render, 300);
  });
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async function() {
  try {
    STATE.models = await loadModels();
  } catch(e) {
    console.warn('PhishVote: loadModels failed', e);
    STATE.models = {};
  }

  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.url) {
      document.getElementById('root').innerHTML =
        '<div class="err">⚠️ Cannot scan this page.<br><small>chrome:// and edge:// pages are restricted.</small></div>';
      return;
    }
    STATE.url = tab.url;
    render();
  });
});
