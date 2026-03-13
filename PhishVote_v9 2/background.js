// background.js — PhishVote v8
// 3-Pass pipeline:
//   Pass 1: URL features  → instant badge (no network)
//   Pass 2: DOM scan      → updated badge
//   Pass 3: API features  → final badge + banner (if alert)

importScripts('engine.js');

// ── Pre-load API keys on install ─────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(function() {
  chrome.storage.local.get([
    'pv_whois_key','pv_openpagerank_key',
    'pv_google_cse_key','pv_google_cse_cx','pv_virustotal_key'
  ], function(existing) {
    var d = {};
    if (!existing.pv_whois_key)        d.pv_whois_key        = 'at_ZBmYfOuPFzVkWTyxNVnwTz3T3yLaj';
    if (!existing.pv_openpagerank_key) d.pv_openpagerank_key = 'wc4o8ooow4wwc8ww4cgs08gws04kws0sg8o8000k';
    if (!existing.pv_google_cse_key)   d.pv_google_cse_key   = 'AIzaSyDFsUwaxJYDgTnFIYBN_Gxc2ejcN_QR_mw';
    if (!existing.pv_google_cse_cx)    d.pv_google_cse_cx    = '70ddd580a338f4805';
    if (!existing.pv_virustotal_key)   d.pv_virustotal_key   = '9780c1220271acfe813fa76fbf66c8caef59dd2530d720a2c5ce95ca60a681ae';
    if (Object.keys(d).length > 0) chrome.storage.local.set(d);
  });
});



var _model = null;
async function getModel() {
  if (_model) return _model;
  try {
    var r = await fetch(chrome.runtime.getURL('models/phishvote_model_dsbase.json'));
    _model = await r.json();
  } catch(e) {
    _model = { threshold: 0.5 };
  }
  return _model;
}

async function domScan(tabId) {
  try {
    var res = await chrome.scripting.executeScript({ target: { tabId }, func: extractPageDOM });
    return (res && res[0] && res[0].result) ? res[0].result : {};
  } catch(e) { return {}; }
}

function setBadge(tabId, cls) {
  var map = {
    'safe':        { text: '',  color: '#22c55e' },
    'likely-safe': { text: '',  color: '#84cc16' },
    'scanning':    { text: '…', color: '#94a3b8' },
    'suspicious':  { text: '?', color: '#f97316' },
    'phishing':    { text: '!', color: '#ef4444' },
    'high-risk':   { text: '!', color: '#dc2626' },
  };
  var b = map[cls] || map['safe'];
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

async function injectAlertBanner(tabId, result) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: function(data) {
        var old = document.getElementById('__pv__'); if (old) old.remove();
        var sty = document.getElementById('__pv_sty__'); if (sty) sty.remove();
        var C = {
          suspicious: { bg:'#fffbeb',bd:'#f97316',txt:'#9a3412',sub:'#c2410c',btn:'#f97316' },
          phishing:   { bg:'#fff1f2',bd:'#ef4444',txt:'#881337',sub:'#be123c',btn:'#ef4444' },
          'high-risk':{ bg:'#fef2f2',bd:'#dc2626',txt:'#7f1d1d',sub:'#991b1b',btn:'#dc2626' },
        }[data.cls];
        if (!C) return;
        var style = document.createElement('style');
        style.id = '__pv_sty__';
        style.textContent =
          '@keyframes __pv_in{from{transform:translateY(-110%);opacity:0}to{transform:translateY(0);opacity:1}}' +
          '@keyframes __pv_pulse{0%,100%{box-shadow:0 2px 16px rgba(0,0,0,.08)}50%{box-shadow:0 4px 28px rgba(0,0,0,.14)}}' +
          '#__pv__{position:fixed;top:0;left:0;right:0;z-index:2147483647;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;animation:__pv_in .4s cubic-bezier(0.16,1,0.3,1) forwards,__pv_pulse 3s ease-in-out 0.4s infinite;}';
        document.head.appendChild(style);
        var el = document.createElement('div'); el.id = '__pv__';
        el.innerHTML =
          '<div style="background:'+C.bg+';border-bottom:2px solid '+C.bd+';padding:10px 16px;display:flex;align-items:center;gap:12px;cursor:pointer">'+
            '<div style="width:36px;height:36px;border-radius:9px;background:'+C.btn+';display:flex;align-items:center;justify-content:center;font-size:17px;flex-shrink:0;color:#fff">'+data.icon+'</div>'+
            '<div style="flex:1;min-width:0">'+
              '<div style="font-size:12px;font-weight:700;color:'+C.txt+';letter-spacing:.2px">PhishVote: '+data.level+' — '+data.pct+'% phishing probability</div>'+
              '<div style="font-size:9.5px;color:'+C.sub+';margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+data.url+'</div>'+
            '</div>'+
            '<div style="font-size:9px;font-weight:600;color:'+C.txt+';flex-shrink:0;padding:4px 11px;border:1.5px solid '+C.bd+';border-radius:6px;background:rgba(255,255,255,.7);white-space:nowrap">View Analysis →</div>'+
            '<span id="__pv_x__" style="font-size:16px;color:#aaa;flex-shrink:0;padding:0 4px;line-height:1" title="Dismiss">✕</span>'+
          '</div>';
        document.body.prepend(el);
        document.getElementById('__pv_x__').addEventListener('click',function(e){
          e.stopPropagation(); el.style.transition='opacity .2s'; el.style.opacity='0';
          setTimeout(function(){el.remove();style.remove();},220);
        });
        el.querySelector('div').addEventListener('click',function(e){
          if(e.target.id==='__pv_x__')return; window.open(data.detailUrl,'_blank');
        });
      },
      args: [{
        cls: result.risk.cls,
        icon: result.risk.cls==='suspicious'?'⚠️':'🚨',
        level: result.risk.level,
        pct: Math.round(result.prob*100),
        url: result.url,
        detailUrl: chrome.runtime.getURL('detail.html')+'?tabId='+result.tabId,
      }]
    });
  } catch(e) {}
}

function buildResult(tabId, url, merged, threshold, domFeats, urlFeats, apiFeats, pass) {
  var allVals = FEAT_ORDER.map(function(k){ return merged?(merged[k]!==undefined?merged[k]:0):0; });
  var nPhish=allVals.filter(function(v){return v===-1;}).length;
  var nSafe =allVals.filter(function(v){return v=== 1;}).length;
  var nNeut =allVals.filter(function(v){return v=== 0;}).length;
  var domSigs=Object.values(domFeats||{}).filter(function(v){return v!==0;}).length;
  var apiSigs=Object.values(apiFeats||{}).filter(function(v){return v!==0;}).length;
  var topPhish=FEAT_ORDER.filter(function(k){return merged&&merged[k]===-1;})
    .sort(function(a,b){return(RF_IMPORTANCES[b]||0)-(RF_IMPORTANCES[a]||0);})
    .slice(0,3).map(function(k){return FEAT_LABELS[k];});
  var topSafe=FEAT_ORDER.filter(function(k){return merged&&merged[k]===1;})
    .sort(function(a,b){return(RF_IMPORTANCES[b]||0)-(RF_IMPORTANCES[a]||0);})
    .slice(0,3).map(function(k){return FEAT_LABELS[k];});
  var prob=scoreFeatures(merged);
  var risk=getRiskInfo(prob,threshold);
  return { url,tabId,prob,risk,threshold,urlFeats,domFeats:domFeats||{},apiFeats:apiFeats||{},
           features:merged,nPhish,nSafe,nNeut,domSigs,apiSigs,topPhish,topSafe,pass,timestamp:Date.now() };
}

// DOM features that get set to -1 when Chrome blocks the page
// (so we don't lose 24% AnchorURL + other DOM signals on blocked pages)
var BLOCKED_DOM_FEATS = {
  Favicon:-1, RequestURL:-1, AnchorURL:-1, LinksInScriptTags:-1,
  ServerFormHandler:-1, InfoEmail:1, WebsiteForwarding:-1,
  StatusBarCust:1, DisableRightClick:-1, UsingPopupWindow:-1, IframeRedirection:-1
};

async function analyseTab(tabId, url) {
  var ALERT_CLS = ['suspicious','phishing','high-risk'];

  // Pass 1 — instant URL badge
  var urlFeats = extractURLFeatures(url);
  var p1 = buildResult(tabId,url,urlFeats,0.5,{},urlFeats,{},1);
  setBadge(tabId, p1.risk.cls);
  await chrome.storage.local.set({['pv_'+tabId]: p1});

  // Pass 2 — DOM + model in parallel
  var domFeats={}, model={threshold:0.5};
  var chromBlocked = false;
  try {
    var r2 = await Promise.all([domScan(tabId), getModel()]);
    domFeats=r2[0]; model=r2[1];
  } catch(e){}
  var threshold = model.threshold||0.5;

  // Detect Chrome Safe Browsing interstitial:
  // When Chrome blocks a page as "Dangerous site", the real page never loads.
  // The DOM scan runs on the warning page which has no anchors, iframes, or forms.
  // Result: ALL 11 DOM features stay 0 — losing AnchorURL (24%) and others.
  // Fix: if DOM scan returns all-neutral AND the URL looks suspicious from Pass 1,
  // treat the block itself as confirmation — set DOM features to phishing values.
  var domAllNeutral = Object.keys(domFeats).length === 0 ||
    Object.values(domFeats).every(function(v){ return v === 0; });
  var urlAlreadySuspicious = p1.prob >= 0.25; // some URL signals already fired

  if (domAllNeutral && urlAlreadySuspicious) {
    // Chrome likely blocked the real page — DOM scan got the interstitial instead.
    // Use conservative phishing defaults for DOM features.
    domFeats = Object.assign({}, BLOCKED_DOM_FEATS);
    chromBlocked = true;
  }

  var merged2 = mergeFeatures(urlFeats, domFeats, {});
  var p2 = buildResult(tabId,url,merged2,threshold,domFeats,urlFeats,{},2);
  if (chromBlocked) p2.chromBlocked = true;
  setBadge(tabId, p2.risk.cls);
  await chrome.storage.local.set({['pv_'+tabId]: p2});

  // Pass 3 — all APIs in parallel (show scanning spinner)
  setBadge(tabId, 'scanning');
  var apiFeats={};
  try { apiFeats = await fetchAPIFeatures(url); } catch(e){}
  var merged3 = mergeFeatures(urlFeats, domFeats, apiFeats);
  var p3 = buildResult(tabId,url,merged3,threshold,domFeats,urlFeats,apiFeats,3);
  setBadge(tabId, p3.risk.cls);
  await chrome.storage.local.set({['pv_'+tabId]: p3});

  // History
  chrome.storage.local.get(['pv_history'],function(d){
    var hist=d['pv_history']||[];
    hist=hist.filter(function(h){return h.url!==url;});
    hist.unshift({url,prob:p3.prob,riskCls:p3.risk.cls,riskLevel:p3.risk.level,badge:p3.risk.badge,ts:Date.now()});
    if(hist.length>5)hist=hist.slice(0,5);
    chrome.storage.local.set({pv_history:hist});
  });

  // Banner on alert pages only
  if(ALERT_CLS.indexOf(p3.risk.cls)!==-1) await injectAlertBanner(tabId,p3);
}

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if(changeInfo.status!=='complete'||!tab.url)return;
  var url=tab.url;
  if(url.startsWith('chrome://')||url.startsWith('chrome-extension://')||
     url.startsWith('edge://')||url.startsWith('about:')||url.startsWith('data:'))return;
  analyseTab(tabId, url);
});

// ── VT cache listener: when VirusTotal finishes its 45s delayed analysis,
// re-score the tab and update badge/banner with the real result ──────────────
chrome.storage.onChanged.addListener(function(changes, area) {
  if (area !== 'local') return;
  Object.keys(changes).forEach(function(key) {
    if (!key.startsWith('pv_vt_')) return;
    // A VT result just came in — find any active tab that was pending
    chrome.tabs.query({}, function(tabs) {
      tabs.forEach(function(tab) {
        if (!tab.url || tab.url.startsWith('chrome://')) return;
        chrome.storage.local.get(['pv_' + tab.id], function(d) {
          var stored = d['pv_' + tab.id];
          if (!stored || stored.url !== tab.url) return;
          // Only re-score if StatsReport was neutral (0 = pending)
          if (stored.apiFeats && stored.apiFeats.StatsReport === 0) {
            // Trigger a fresh full analysis on this tab
            analyseTab(tab.id, tab.url);
          }
        });
      });
    });
  });
});
