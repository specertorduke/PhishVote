// popup.js — PhishVote v7.1
// Fix: polls storage every 400 ms (up to 8 s) so result renders as soon as background finishes.

function timeAgo(ts) {
  var s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)   return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  return Math.floor(s / 3600) + 'h ago';
}

function shortURL(url) {
  try {
    var u = new URL(url);
    return u.hostname + (u.pathname.length > 1 ? u.pathname.substring(0, 22) + '…' : '');
  } catch(e) { return url.substring(0, 30) + '…'; }
}

document.addEventListener('DOMContentLoaded', function() {
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    var tab = tabs && tabs[0];
    if (!tab || !tab.url ||
        tab.url.startsWith('chrome://') ||
        tab.url.startsWith('chrome-extension://') ||
        tab.url.startsWith('edge://') ||
        tab.url.startsWith('about:')) {
      document.getElementById('root').innerHTML =
        '<div class="loading"><p>Cannot scan this page.</p></div>';
      return;
    }
    loadData(tab);
  });
});

function loadData(tab) {
  chrome.storage.local.get(['pv_' + tab.id, 'pv_history'], function(d) {
    var result  = d['pv_' + tab.id];
    var history = d['pv_history'] || [];
    if (result) {
      render(result, tab, history);
    } else {
      // Show scanning state immediately, then poll every 400 ms (max 20 attempts = 8 s)
      renderScanning(tab.url, history);
      var attempts = 0;
      var interval = setInterval(function() {
        attempts++;
        chrome.storage.local.get(['pv_' + tab.id, 'pv_history'], function(d2) {
          var r2 = d2['pv_' + tab.id];
          var h2 = d2['pv_history'] || history;
          if (r2) {
            clearInterval(interval);
            render(r2, tab, h2);
          } else if (attempts >= 20) {
            clearInterval(interval);
            renderScanTimeout(tab.url, h2);
          }
        });
      }, 400);
    }
  });
}

function renderScanning(url, history) {
  var body =
    '<div class="body">' +
    '<div class="url-row">' +
      '<span class="url-icon">🔗</span>' +
      '<span class="url-text" title="' + url + '">' + shortURL(url) + '</span>' +
    '</div>' +
    '<div class="verdict scanning">' +
      '<div class="v-icon">🔍</div>' +
      '<div>' +
        '<div class="v-level scanning">Analyzing…</div>' +
        '<div class="v-prob">Checking 30 UCI-2015 features</div>' +
      '</div>' +
    '</div>';
  if (history && history.length) body += renderHistoryHTML(history);
  body += '</div>';
  document.getElementById('root').innerHTML = body;
}

function renderScanTimeout(url, history) {
  var body =
    '<div class="body">' +
    '<div class="url-row">' +
      '<span class="url-icon">🔗</span>' +
      '<span class="url-text" title="' + url + '">' + shortURL(url) + '</span>' +
    '</div>' +
    '<div class="verdict scanning">' +
      '<div class="v-icon">⏳</div>' +
      '<div>' +
        '<div class="v-level scanning">Still scanning…</div>' +
        '<div class="v-prob">DOM scan may be restricted on this page</div>' +
      '</div>' +
    '</div>';
  if (history && history.length) body += renderHistoryHTML(history);
  body += '</div>';
  document.getElementById('root').innerHTML = body;
}

function renderHistoryHTML(history) {
  var html = '<div class="div"></div><div class="hist-label">Recent Scans</div>';
  history.slice(0, 4).forEach(function(h) {
    html +=
      '<div class="hist-item" data-url="' + h.url + '">' +
        '<span class="hist-badge">' + h.badge + '</span>' +
        '<span class="hist-url" title="' + h.url + '">' + shortURL(h.url) + '</span>' +
        '<span class="hist-time">' + timeAgo(h.ts) + '</span>' +
      '</div>';
  });
  return html;
}

function render(result, tab, history) {
  var url       = result.url;
  var prob      = result.prob;
  var risk      = result.risk;
  var nPhish    = result.nPhish  || 0;
  var nSafe     = result.nSafe   || 0;
  var nNeut     = result.nNeut   || 0;
  var domSigs   = result.domSigs || 0;
  var features  = result.features || {};
  var threshold = result.threshold || 0.5;

  var probPct  = Math.round(prob * 100);
  var safePct  = 100 - probPct;
  var isSafe   = risk.cls === 'safe' || risk.cls === 'likely-safe';
  var isAlert  = risk.cls === 'suspicious' || risk.cls === 'phishing' || risk.cls === 'high-risk';

  var colors = {
    'safe':        '#16a34a',
    'likely-safe': '#4d7c0f',
    'suspicious':  '#c2410c',
    'phishing':    '#be123c',
    'high-risk':   '#991b1b',
  };
  var barColor = colors[risk.cls] || '#1d4ed8';

  var allVals  = Object.keys(features).slice(0, 28).map(function(k) { return features[k]; });
  var dotsHTML = allVals.map(function(v) {
    return '<div class="dot ' + (v === -1 ? 'p' : v === 1 ? 's' : 'n') + '"></div>';
  }).join('');

  var chromBlocked = result.chromBlocked || false;
  var domHTML = chromBlocked
    ? '<div class="dom-line blocked">🚫 Chrome blocked page — DOM set to phishing defaults</div>'
    : domSigs > 0
      ? '<div class="dom-line ok">✅ DOM scan complete · ' + domSigs + ' signals</div>'
      : '<div class="dom-line warn">⚠️ DOM restricted — URL features only</div>';

  var btnCls = risk.cls === 'phishing' || risk.cls === 'high-risk' ? 'alert-style'
             : risk.cls === 'suspicious' ? 'warn-style'
             : isSafe ? 'safe-style'
             : 'neutral-style';
  var btnLabel = isAlert ? '⚠️ View Full Analysis →'
               : isSafe  ? '✅ View Report →'
               : '📋 View Report →';

  var html =
    '<div class="body">' +
    '<div class="url-row">' +
      '<span class="url-icon">🔗</span>' +
      '<span class="url-text" title="' + url + '">' + shortURL(url) + '</span>' +
    '</div>' +
    domHTML +
    '<div class="verdict ' + risk.cls + '">' +
      '<div class="v-icon">' + risk.badge + '</div>' +
      '<div>' +
        '<div class="v-level ' + risk.cls + '">' + risk.level + '</div>' +
        '<div class="v-prob">P(phish) = ' + probPct + '%</div>' +
      '</div>' +
    '</div>' +
    '<div class="bar-section">' +
      '<div class="bar-row">' +
        '<div class="bar-lbl">P(phish)</div>' +
        '<div class="bar-trk"><div class="bar-fill" style="width:' + probPct + '%;background:' + barColor + '"></div></div>' +
        '<div class="bar-num" style="color:' + barColor + '">' + probPct + '%</div>' +
      '</div>' +
      '<div class="bar-row">' +
        '<div class="bar-lbl">P(legit)</div>' +
        '<div class="bar-trk"><div class="bar-fill" style="width:' + safePct + '%;background:#16a34a"></div></div>' +
        '<div class="bar-num" style="color:#16a34a">' + safePct + '%</div>' +
      '</div>' +
    '</div>' +
    '<div class="dots-wrap">' +
      '<div class="dots-row">' + dotsHTML + '</div>' +
      '<div class="sig-counts">' + nPhish + ' phish · ' + nSafe + ' safe · ' + nNeut + ' neut · of 30</div>' +
      '<div class="model-line">PhishVote · RF · XGB · CB · LGBM · GB · θ=' + threshold + ' · 97.42% acc</div>' +
    '</div>' +
    '<div class="div"></div>' +
    '<div class="actions">' +
      '<button class="btn-detail ' + btnCls + '" id="btn-detail">' + btnLabel + '</button>' +
      '<button class="btn-copy" id="btn-copy">📋 Copy</button>' +
    '</div>';

  if (history && history.length) html += renderHistoryHTML(history);
  html += '</div>';
  document.getElementById('root').innerHTML = html;

  document.getElementById('btn-detail').addEventListener('click', function() {
    chrome.tabs.create({ url: chrome.runtime.getURL('detail.html') + '?tabId=' + tab.id });
    window.close();
  });

  document.getElementById('btn-copy').addEventListener('click', function() {
    navigator.clipboard.writeText(url).then(function() {
      var b = document.getElementById('btn-copy');
      b.textContent = '✅ Copied'; b.classList.add('copied');
      setTimeout(function() { b.textContent = '📋 Copy'; b.classList.remove('copied'); }, 1500);
    });
  });

  document.querySelectorAll('.hist-item').forEach(function(el) {
    el.addEventListener('click', function() {
      chrome.tabs.create({ url: el.dataset.url });
      window.close();
    });
  });
}
