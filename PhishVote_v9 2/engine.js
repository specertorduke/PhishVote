// engine.js — PhishVote v8 | UCI-2015 · 30 features · ALL ACTIVE
// v8: AgeofDomain, DNSRecording, DomainRegLen, AbnormalURL → WHOIS XML API
//     WebsiteTraffic → Tranco top-1M list (local JSON)
//     PageRank       → Open PageRank API
//     GoogleIndex    → Google Custom Search API
//     LinksPointingToPage → HackerTarget API (free, no key)
//     StatsReport    → VirusTotal API
//
// API KEYS — set these in chrome.storage or config.js (see README):
//   WHOIS_XML_KEY   — https://www.whoisxmlapi.com  (500 free/mo)
//   OPENPAGERANK_KEY — https://www.domcop.com/openpagerank (1000 free/day)
//   GOOGLE_CSE_KEY  — https://programmablesearchengine.google.com (100 free/day)
//   GOOGLE_CSE_CX   — your Custom Search Engine ID
//   VIRUSTOTAL_KEY  — https://www.virustotal.com/gui/join-us (500 free/day)

// ── Labels ────────────────────────────────────────────────────────────────────
const FEAT_LABELS = {
  'UsingIP':           'IP Address in URL',
  'LongURL':           'URL Length',
  'ShortURL':          'URL Shortener',
  'Symbol@':           '@ Symbol',
  'Redirecting//':     'Double Slash Redirect',
  'PrefixSuffix-':     'Dash in Domain',
  'SubDomains':        'Sub-Domains',
  'HTTPS':             'SSL State',
  'DomainRegLen':      'Domain Reg Length',
  'Favicon':           'Favicon Source',
  'NonStdPort':        'Non-Standard Port',
  'HTTPSDomainURL':    'HTTPS in Domain Name',
  'RequestURL':        'Request URL',
  'AnchorURL':         'Anchor URL',
  'LinksInScriptTags': 'Links in Tags',
  'ServerFormHandler': 'Server Form Handler',
  'InfoEmail':         'Submits to Email',
  'AbnormalURL':       'Abnormal URL',
  'WebsiteForwarding': 'Redirect Count',
  'StatusBarCust':     'Mouseover Change',
  'DisableRightClick': 'Right-Click Disabled',
  'UsingPopupWindow':  'Popup Window',
  'IframeRedirection': 'iFrame Detected',
  'AgeofDomain':       'Domain Age',
  'DNSRecording':      'DNS Record',
  'WebsiteTraffic':    'Web Traffic',
  'PageRank':          'Page Rank',
  'GoogleIndex':       'Google Index',
  'LinksPointingToPage':'Inbound Links',
  'StatsReport':       'Blacklist Report'
};

const FEAT_ORDER = [
  'UsingIP','LongURL','ShortURL','Symbol@','Redirecting//','PrefixSuffix-',
  'SubDomains','HTTPS','DomainRegLen','Favicon','NonStdPort','HTTPSDomainURL',
  'RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler','InfoEmail',
  'AbnormalURL','WebsiteForwarding','StatusBarCust','DisableRightClick',
  'UsingPopupWindow','IframeRedirection','AgeofDomain','DNSRecording',
  'WebsiteTraffic','PageRank','GoogleIndex','LinksPointingToPage','StatsReport'
];

const DOM_FEATURES = new Set([
  'Favicon','RequestURL','AnchorURL','LinksInScriptTags','ServerFormHandler',
  'InfoEmail','WebsiteForwarding','StatusBarCust','DisableRightClick',
  'UsingPopupWindow','IframeRedirection'
]);

// Features that come from external APIs (Pass 3)
const API_FEATURES = new Set([
  'AgeofDomain','DNSRecording','DomainRegLen','AbnormalURL',
  'WebsiteTraffic','PageRank','GoogleIndex','LinksPointingToPage','StatsReport'
]);

const RF_IMPORTANCES = {
  'UsingIP':0.0127,'LongURL':0.0083,'ShortURL':0.0056,'Symbol@':0.005,
  'Redirecting//':0.0035,'PrefixSuffix-':0.0446,'SubDomains':0.0702,
  'HTTPS':0.3138,'DomainRegLen':0.0161,'Favicon':0.0041,'NonStdPort':0.0024,
  'HTTPSDomainURL':0.0061,'RequestURL':0.0193,'AnchorURL':0.2410,
  'LinksInScriptTags':0.0436,'ServerFormHandler':0.0214,'InfoEmail':0.0054,
  'AbnormalURL':0.0039,'WebsiteForwarding':0.0052,'StatusBarCust':0.0028,
  'DisableRightClick':0.0012,'UsingPopupWindow':0.005,'IframeRedirection':0.0023,
  'AgeofDomain':0.0154,'DNSRecording':0.0119,'WebsiteTraffic':0.0811,
  'PageRank':0.0115,'GoogleIndex':0.0123,'LinksPointingToPage':0.0196,'StatsReport':0.0047
};

const VOTER_WEIGHTS = {
  'XGBoost':0.3333,'LightGBM':0.2667,'CatBoost':0.20,
  'Random Forest':0.1333,'Gradient Boosting':0.0667
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function getHostname(url) {
  try {
    var host = new URL(url).hostname.toLowerCase();
    return host.startsWith('www.') ? host.slice(4) : host;
  } catch(e) { return ''; }
}

// ── Pass 1: URL Features (instant, no network) ────────────────────────────────
function extractURLFeatures(url) {
  var u;
  try { u = new URL(url); } catch(e) { return null; }
  var host = u.hostname.toLowerCase();
  var full = url, path = u.pathname + u.search;

  var ipRe    = /^(\d{1,3}\.){3}\d{1,3}$/;
  var shortRe = /^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bl\.ink|rb\.gy|cutt\.ly|short\.link|tiny\.cc|x\.co|snipurl\.com|shorturl\.at|clck\.ru|qr\.ae|po\.st|lnkd\.in)$/i;

  // Extract just the registered domain (last 2 parts), e.g. "xwriq.cn" from "faq.uccard.acritu.xwriq.cn"
  var parts      = host.split('.');
  var tld        = parts.slice(-1)[0];
  var sld        = parts.length >= 2 ? parts.slice(-2).join('.') : host;
  var sldName    = parts.length >= 2 ? parts[parts.length - 2] : host; // e.g. "xwriq"
  var dots       = parts.length - 2; // subdomain depth

  // ── Suspicious TLDs common in phishing (not in UCI but strong real-world signal) ──
  var suspTLD = /\.(tk|ml|ga|cf|gq|xyz|top|club|online|site|website|space|fun|icu|live|buzz|vip|work|cn|ru|pw|cc|ws|su|biz\.pl|info\.pl)$/i.test(host);

  // ── Numeric-only SLD — e.g. "153255.com", "559321.com" ──────────────────────
  // Legitimate brands never have pure-number domain names
  var numericSLD = /^\d+$/.test(sldName);

  // ── Random-looking domain — long consonant clusters, no real words ───────────
  // Detects: ybrjaouww, kirvxcjdvmui, xwriq, rtmul, vbwtx etc.
  // Heuristic: SLD has >=6 chars, >70% consonants, no common vowel pattern
  function isRandomDomain(name) {
    if (name.length < 6) return false;
    var consonants = (name.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
    var ratio = consonants / name.length;
    return ratio > 0.72;
  }
  var randomDomain = isRandomDomain(sldName);

  // ── Brand impersonation in subdomain ─────────────────────────────────────────
  // e.g. "faq.uccard.acritu.xwriq.cn" — known brand appears in subdomain not SLD
  var brands = ['paypal','apple','google','microsoft','amazon','facebook','netflix',
                'instagram','twitter','bank','secure','account','login','verify',
                'uccard','rakuten','docomo','softbank','aeon','smbc','mufg','ntt'];
  var hostWithoutTLD = parts.slice(0,-1).join('.');
  var brandInSub = brands.some(function(b) {
    // brand appears somewhere in host but NOT as the actual registered domain
    return hostWithoutTLD.indexOf(b) !== -1 && sldName.indexOf(b) === -1;
  });

  // ── Subdomain depth ──────────────────────────────────────────────────────────
  // UCI rule: >2 subdomains = -1, 1-2 = 0, 0 = 1
  // But if random or suspicious, even 1 subdomain should push toward phishing
  var subDomainScore;
  if (dots > 2)       subDomainScore = -1;
  else if (dots >= 1) subDomainScore =  0;
  else                subDomainScore =  1;

  // ── AbnormalURL heuristic (upgraded from regex, API will override) ───────────
  // Flags: numeric SLD, random domain, brand-in-subdomain, suspicious TLD
  var abnormalHeuristic = (numericSLD || randomDomain || brandInSub) ? -1 : 1;

  // ── DomainRegLen heuristic (API will override with real WHOIS) ───────────────
  // Suspicious TLDs + random names almost always = recently registered
  var domRegLenHeuristic = (suspTLD && (randomDomain || numericSLD)) ? -1 : 0;

  // ── Embedded FQDN in path ─────────────────────────────────────────────────────
  var embFQDN = /[a-z0-9][a-z0-9\-]{2,}\.(com|net|org|edu|gov|io|co|uk|de|fr|br|ru|cn|info|biz)/i.test(path);

  return {
    'UsingIP':       ipRe.test(host)                                   ? -1 : 1,
    'LongURL':       full.length>75 ? -1 : full.length>54             ?  0 : 1,
    'ShortURL':      shortRe.test(host)                                ? -1 : 1,
    'Symbol@':       full.includes('@')                                ? -1 : 1,
    'Redirecting//': path.indexOf('//')!==-1                           ? -1 : 1,
    'PrefixSuffix-': host.includes('-')                                ? -1 : 1,
    'SubDomains':    subDomainScore,
    // HTTPS asymmetric fix (v9): HTTPS=1 no longer awards safe credit.
    // Modern phishing sites use free HTTPS (Let's Encrypt) universally.
    // Only the ABSENCE of HTTPS (HTTP only) is a phishing signal (-1).
    // This prevents HTTPS from dominating the score as a false-safe signal.
    'HTTPS':         u.protocol==='https:'                             ?  0 : -1,
    'NonStdPort':    (u.port&&['80','443',''].indexOf(u.port)===-1)    ? -1 : 1,
    'HTTPSDomainURL':host.indexOf('https')!==-1                        ? -1 : 1,
    'InfoEmail':     full.toLowerCase().indexOf('mailto:')!==-1        ? -1 : 1,
    'AbnormalURL':   embFQDN ? -1 : abnormalHeuristic,
    'DomainRegLen':  domRegLenHeuristic,
    // DOM features — neutral until Pass 2
    'Favicon':0,'RequestURL':0,'AnchorURL':0,'LinksInScriptTags':0,
    'ServerFormHandler':0,'WebsiteForwarding':0,'StatusBarCust':0,
    'DisableRightClick':0,'UsingPopupWindow':0,'IframeRedirection':0,
    // API features — neutral until Pass 3
    'AgeofDomain':0,'DNSRecording':0,'WebsiteTraffic':0,
    'PageRank':0,'GoogleIndex':0,'LinksPointingToPage':0,'StatsReport':0
  };
}

// ── Pass 2: DOM Features (injected into live page) ────────────────────────────
// Self-contained function — injected via chrome.scripting.executeScript
function extractPageDOM() {
  var pageUrl=window.location.href, host='';
  try{host=new URL(pageUrl).hostname.toLowerCase();}catch(e){}
  var R={};
  // Favicon
  var favs=Array.from(document.querySelectorAll('link[rel*="icon"]'));
  R.Favicon=favs.length===0?0:favs.some(function(el){
    var h=el.getAttribute('href')||'';
    if(!h||h.startsWith('data:'))return false;
    if(h.startsWith('/')&&!h.startsWith('//'))return false;
    try{return new URL(h,pageUrl).hostname.toLowerCase()!==host;}catch(e){return false;}
  })?-1:1;
  // RequestURL
  var reqs=Array.from(document.querySelectorAll('img[src],script[src],form[action],audio[src],video[src],embed[src],object[data]'));
  if(reqs.length===0){R.RequestURL=1;}else{
    var extR=reqs.filter(function(el){
      var u=el.getAttribute('src')||el.getAttribute('data')||el.getAttribute('action')||'';
      if(!u||u.startsWith('data:')||u.startsWith('#')||u.startsWith('javascript:'))return false;
      if(u.startsWith('/')&&!u.startsWith('//'))return false;
      try{return new URL(u,pageUrl).hostname.toLowerCase()!==host;}catch(e){return false;}
    }).length;
    var r1=extR/reqs.length; R.RequestURL=r1<0.22?1:r1<0.61?0:-1;
  }
  // AnchorURL
  var ancs=Array.from(document.querySelectorAll('a[href]'));
  if(ancs.length===0){R.AnchorURL=1;}else{
    var extA=ancs.filter(function(el){
      var h=el.getAttribute('href')||'';
      if(!h||h.startsWith('#')||h.startsWith('javascript:')||h.startsWith('mailto:')||h.startsWith('tel:'))return false;
      if(h.startsWith('/')&&!h.startsWith('//'))return false;
      try{return new URL(h,pageUrl).hostname.toLowerCase()!==host;}catch(e){return false;}
    }).length;
    var r2=extA/ancs.length; R.AnchorURL=r2<0.31?1:r2<0.67?0:-1;
  }
  // LinksInScriptTags
  var tags=Array.from(document.querySelectorAll('script[src],link[href],meta[content]'));
  if(tags.length===0){R.LinksInScriptTags=1;}else{
    var extT=tags.filter(function(el){
      var u=el.getAttribute('src')||el.getAttribute('href')||el.getAttribute('content')||'';
      if(!u)return false;
      if(u.startsWith('/')&&!u.startsWith('//'))return false;
      try{return new URL(u,pageUrl).hostname.toLowerCase()!==host;}catch(e){return false;}
    }).length;
    var r3=extT/tags.length; R.LinksInScriptTags=r3<0.17?1:r3<0.81?0:-1;
  }
  // ServerFormHandler
  var forms=Array.from(document.querySelectorAll('form'));
  if(forms.length===0){R.ServerFormHandler=1;}else{
    var sfh=forms.map(function(f){
      var a=(f.getAttribute('action')||'').trim();
      if(!a||a.toLowerCase()==='about:blank')return 0;
      if(a.toLowerCase().startsWith('mailto:'))return -1;
      if(a.startsWith('/')&&!a.startsWith('//'))return 1;
      try{return new URL(a,pageUrl).hostname.toLowerCase()===host?1:-1;}catch(e){return 1;}
    });
    R.ServerFormHandler=sfh.indexOf(-1)!==-1?-1:sfh.indexOf(0)!==-1?0:1;
  }
  R.InfoEmail=Array.from(document.querySelectorAll('form')).some(function(f){
    return (f.getAttribute('action')||'').toLowerCase().startsWith('mailto:');
  })?-1:1;
  // WebsiteForwarding
  var rc=0;
  try{var ne=performance.getEntriesByType&&performance.getEntriesByType('navigation');
    if(ne&&ne.length>0)rc=ne[0].redirectCount||0;
    else if(performance.navigation)rc=performance.navigation.redirectCount||0;
  }catch(e){}
  R.WebsiteForwarding=rc===0?1:rc===1?0:-1;
  // StatusBarCust
  var hasSB=Array.from(document.querySelectorAll('[onmouseover]')).some(function(el){
    var mo=(el.getAttribute('onmouseover')||'').toLowerCase();
    return mo.indexOf('window.status')!==-1||mo.indexOf('status =')!==-1;
  });
  if(!hasSB)hasSB=Array.from(document.querySelectorAll('script:not([src])')).some(function(s){
    var t=s.textContent||'';return t.indexOf('window.status')!==-1&&t.indexOf('mouseover')!==-1;
  });
  R.StatusBarCust=hasSB?-1:1;
  // DisableRightClick
  var rc2=false;
  [document.body,document.documentElement].forEach(function(el){
    if(el&&(el.getAttribute('oncontextmenu')||'').toLowerCase().indexOf('return false')!==-1)rc2=true;
  });
  if(!rc2)rc2=Array.from(document.querySelectorAll('script:not([src])')).some(function(s){
    var t=s.textContent||'';
    return t.indexOf('contextmenu')!==-1&&(t.indexOf('return false')!==-1||t.indexOf('preventDefault')!==-1);
  });
  R.DisableRightClick=rc2?-1:1;
  // UsingPopupWindow
  R.UsingPopupWindow=Array.from(document.querySelectorAll('script:not([src])')).some(function(s){
    return (s.textContent||'').indexOf('window.open(')!==-1;
  })?-1:1;
  // IframeRedirection — matches BeautifulSoup4 approach (friend's html_features.py).
  // ANY iframe = phishing signal (-1). Legitimate sites rarely use iframes;
  // phishing kits commonly embed credential forms inside iframes.
  var iframes=Array.from(document.querySelectorAll('iframe'));
  R.IframeRedirection=iframes.length===0?1:-1;
  return R;
}

// ── Pass 3: API Features (background service worker fetch calls) ──────────────

// Load API keys from chrome.storage.local (set via options page or setup)
async function getApiKeys() {
  return new Promise(function(resolve) {
    chrome.storage.local.get([
      'pv_whois_key','pv_openpagerank_key',
      'pv_google_cse_key','pv_google_cse_cx','pv_virustotal_key'
    ], function(d) { resolve(d); });
  });
}

// ── Feature 1+2+3+4: WHOIS XML API ───────────────────────────────────────────
// Covers: AgeofDomain, DNSRecording, DomainRegLen, AbnormalURL
// Free tier: 500 requests/month at https://www.whoisxmlapi.com
async function fetchWhoisFeatures(hostname, keys) {
  var result = { AgeofDomain:0, DNSRecording:0, DomainRegLen:0, AbnormalURL:0 };
  var key = keys['pv_whois_key'];
  if (!key) return result;
  try {
    var r = await fetch(
      'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=' + key +
      '&domainName=' + encodeURIComponent(hostname) + '&outputFormat=JSON',
      { signal: AbortSignal.timeout(6000) }
    );
    var d = await r.json();
    var rec = d.WhoisRecord || {};

    // DNSRecording: domain_name exists in WHOIS = 1, else = -1
    result.DNSRecording = rec.domainName ? 1 : -1;

    var reg = rec.registryData || rec;

    // AgeofDomain: creation >= 6 months ago = 1, else = -1
    var created = reg.createdDateNormalized || reg.createdDate || '';
    if (created) {
      var ageMs = Date.now() - new Date(created).getTime();
      var ageMonths = ageMs / (1000 * 60 * 60 * 24 * 30);
      result.AgeofDomain = ageMonths >= 6 ? 1 : -1;
    } else {
      result.AgeofDomain = -1;
    }

    // DomainRegLen: expiry > 365 days from now = 1, else = -1
    var expires = reg.expiresDateNormalized || reg.expiresDate || '';
    if (expires) {
      var daysLeft = (new Date(expires).getTime() - Date.now()) / (1000 * 60 * 60 * 24);
      result.DomainRegLen = daysLeft > 365 ? 1 : -1;
    } else {
      result.DomainRegLen = -1;
    }

    // AbnormalURL: WHOIS hostname not in original URL = -1 (phishing), else = 1
    var whoisName = (reg.domainName || rec.domainName || '').toLowerCase();
    if (whoisName) {
      result.AbnormalURL = hostname.includes(whoisName) ? 1 : -1;
    } else {
      result.AbnormalURL = -1;
    }
  } catch(e) {
    // API down or rate-limited — stay neutral (0) rather than penalise
    result = { AgeofDomain:0, DNSRecording:0, DomainRegLen:0, AbnormalURL:0 };
  }
  return result;
}

// ── Feature 5: WebsiteTraffic — Tranco top-200k list ─────────────────────────
// Local JSON file: data/tranco.json  (build once with: python3 data/build_tranco.py)
// Rule: rank <= 100,000 = 1 (legitimate), rank 100k-200k = 0, not listed = -1
//
// MV3 SERVICE WORKER NOTE: Background service workers are ephemeral in MV3 —
// they terminate after ~30 seconds of inactivity and restart on the next page.
// The module-level _tranco variable RESETS to null on every restart.
// Fix: use a 5-second timeout on the fetch so we never hang waiting for a large file.
// build_tranco.py now outputs top-200k only (~2.5MB) instead of full 1M (~8MB)
// to ensure the fetch+parse completes well within the timeout window.
var _tranco = null;
async function getTranco() {
  if (_tranco && Object.keys(_tranco).length > 10) return _tranco;
  try {
    var controller = new AbortController();
    var timer = setTimeout(function(){ controller.abort(); }, 5000);
    var r = await fetch(
      chrome.runtime.getURL('data/tranco.json'),
      { signal: controller.signal }
    );
    clearTimeout(timer);
    if (!r.ok) { _tranco = {}; return _tranco; }
    _tranco = await r.json();
    // Sanity check: if still a placeholder file, treat as empty
    if (_tranco['__PLACEHOLDER__']) { _tranco = {}; }
  } catch(e) { _tranco = {}; }
  return _tranco;
}

async function fetchWebsiteTraffic(hostname) {
  try {
    var tranco = await getTranco();
    // Try exact hostname first, then root domain (strips subdomains)
    // e.g. "mail.google.com" -> also tries "google.com"
    var root = hostname.split('.').slice(-2).join('.');
    var rank = tranco[hostname] !== undefined ? tranco[hostname]
             : tranco[root]    !== undefined ? tranco[root]
             : null;
    if (rank === null) return -1;   // not in top 200k → new/unknown domain → phishing signal
    if (rank <= 100000) return 1;   // top 100k → well-established legitimate domain
    return 0;                       // 100k-200k → moderate traffic → neutral
  } catch(e) { return 0; }
}

// ── Feature 6: PageRank — Open PageRank API ───────────────────────────────────
// Free: 1000 requests/day at https://www.domcop.com/openpagerank
// Rule: page_rank_decimal < 0.2 = -1, else = 1
async function fetchPageRank(hostname, keys) {
  var key = keys['pv_openpagerank_key'];
  if (!key) return 0;
  try {
    var r = await fetch(
      'https://openpagerank.com/api/v1.0/getPageRank?domains[]=' + encodeURIComponent(hostname),
      { headers: { 'API-OPR': key }, signal: AbortSignal.timeout(5000) }
    );
    var d = await r.json();
    var pr = d.response && d.response[0] ? parseFloat(d.response[0].page_rank_decimal) : null;
    if (pr === null || isNaN(pr)) return 0;
    return pr < 0.2 ? -1 : 1;
  } catch(e) { return 0; }
}

// ── Feature 7: GoogleIndex — Google Custom Search API ────────────────────────
// Free: 100 queries/day at https://programmablesearchengine.google.com
// Rule: results > 0 = indexed (1), else = -1
async function fetchGoogleIndex(hostname, keys) {
  var key = keys['pv_google_cse_key'];
  var cx  = keys['pv_google_cse_cx'];
  if (!key || !cx) return 0;
  try {
    var r = await fetch(
      'https://www.googleapis.com/customsearch/v1?key=' + key +
      '&cx=' + cx + '&q=site:' + encodeURIComponent(hostname) + '&num=1',
      { signal: AbortSignal.timeout(5000) }
    );
    var d = await r.json();
    var total = d.searchInformation ? parseInt(d.searchInformation.totalResults || '0') : 0;
    return total > 0 ? 1 : -1;
  } catch(e) { return 0; }
}

// ── Feature 8: LinksPointingToPage — HackerTarget API ────────────────────────
// Free: 100 requests/day, NO API KEY needed
// https://hackertarget.com/pagelinks-lookup/
// Rule: 0 links = -1, 1-2 = 0, >2 = 1
async function fetchLinksPointingToPage(url) {
  try {
    var r = await fetch(
      'https://api.hackertarget.com/pagelinks/?q=' + encodeURIComponent(url),
      { signal: AbortSignal.timeout(6000) }
    );
    var text = await r.text();
    // Response is newline-separated list of links, or error message
    if (text.includes('error') || text.includes('API count exceeded')) return 0;
    var links = text.split('\n').filter(function(l) { return l.trim().length > 0; });
    if (links.length === 0) return -1;
    if (links.length <= 2) return 0;
    return 1;
  } catch(e) { return 0; }
}

// ── Feature 9: StatsReport — VirusTotal API ──────────────────────────────────
// Free: 500 requests/day — https://www.virustotal.com/gui/join-us
// Mirrors friend's VirusTotal usage (BeautifulSoup4 project).
// Rule: any engine flags malicious = -1, all clean = 1, unknown/pending = 0
//
// btoa() crashes on non-ASCII URLs (e.g. Japanese phishing: クレジットセゾン).
// Fix: encode via TextEncoder → Uint8Array → binary string → btoa safely.
function _vtUrlId(url) {
  try {
    var bytes = new TextEncoder().encode(url);
    var bin = '';
    bytes.forEach(function(b) { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  } catch(e) {
    return btoa(unescape(encodeURIComponent(url))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }
}

async function fetchStatsReport(url, keys) {
  var key = keys['pv_virustotal_key'];
  if (!key) return 0;

  // Cache: store VT result per URL so revisits don't waste quota
  var cacheKey = 'pv_vt_' + _vtUrlId(url).slice(0, 50);
  try {
    var cached = await new Promise(function(res) {
      chrome.storage.local.get([cacheKey], function(d) { res(d[cacheKey]); });
    });
    if (cached !== undefined) return cached; // -1, 0, or 1
  } catch(e) {}

  try {
    var urlId = _vtUrlId(url);
    var r = await fetch(
      'https://www.virustotal.com/api/v3/urls/' + urlId,
      { headers: { 'x-apikey': key }, signal: AbortSignal.timeout(8000) }
    );

    if (r.status === 404) {
      // URL unknown to VT — submit it, then re-check after 45 seconds
      try {
        await fetch('https://www.virustotal.com/api/v3/urls', {
          method: 'POST',
          headers: { 'x-apikey': key, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'url=' + encodeURIComponent(url),
          signal: AbortSignal.timeout(5000)
        });
      } catch(e2) {}
      // Re-check once VT has had time to scan (45s)
      setTimeout(async function() {
        try {
          var r2 = await fetch(
            'https://www.virustotal.com/api/v3/urls/' + urlId,
            { headers: { 'x-apikey': key }, signal: AbortSignal.timeout(8000) }
          );
          if (r2.ok) {
            var d2 = await r2.json();
            var s2 = d2.data && d2.data.attributes && d2.data.attributes.last_analysis_stats;
            if (s2) {
              var res2 = s2.malicious > 0 ? -1 : 1;
              var save = {}; save[cacheKey] = res2;
              chrome.storage.local.set(save);
              // Re-score the tab with the new VT result
              // (background.js will pick this up on next popup open)
            }
          }
        } catch(e2) {}
      }, 45000);
      return 0; // neutral while pending
    }

    if (!r.ok) return 0;
    var d = await r.json();
    var stats = d.data && d.data.attributes && d.data.attributes.last_analysis_stats;
    if (!stats) return 0;
    var result = stats.malicious > 0 ? -1 : 1;
    // Cache result
    var save = {}; save[cacheKey] = result;
    chrome.storage.local.set(save);
    return result;
  } catch(e) { return 0; }
}

// ── Main API orchestrator ─────────────────────────────────────────────────────
// Called from background.js after DOM scan completes
async function fetchAPIFeatures(url) {
  var hostname = getHostname(url);
  if (!hostname) return {};

  var keys = await getApiKeys();

  // Run all API calls in parallel — none blocks the others
  var results = await Promise.allSettled([
    fetchWhoisFeatures(hostname, keys),      // [0] → AgeofDomain, DNSRecording, DomainRegLen, AbnormalURL
    fetchWebsiteTraffic(hostname),           // [1] → WebsiteTraffic
    fetchPageRank(hostname, keys),           // [2] → PageRank
    fetchGoogleIndex(hostname, keys),        // [3] → GoogleIndex
    fetchLinksPointingToPage(url),           // [4] → LinksPointingToPage
    fetchStatsReport(url, keys),             // [5] → StatsReport
  ]);

  var whois   = results[0].status==='fulfilled' ? results[0].value : {};
  var traffic = results[1].status==='fulfilled' ? results[1].value : 0;
  var pr      = results[2].status==='fulfilled' ? results[2].value : 0;
  var gindex  = results[3].status==='fulfilled' ? results[3].value : 0;
  var links   = results[4].status==='fulfilled' ? results[4].value : 0;
  var vt      = results[5].status==='fulfilled' ? results[5].value : 0;

  return {
    AgeofDomain:        whois.AgeofDomain   !== undefined ? whois.AgeofDomain   : 0,
    DNSRecording:       whois.DNSRecording  !== undefined ? whois.DNSRecording  : 0,
    DomainRegLen:       whois.DomainRegLen  !== undefined ? whois.DomainRegLen  : 0,
    AbnormalURL:        whois.AbnormalURL   !== undefined ? whois.AbnormalURL   : 0,
    WebsiteTraffic:     traffic,
    PageRank:           pr,
    GoogleIndex:        gindex,
    LinksPointingToPage:links,
    StatsReport:        vt,
  };
}

// ── Merge all three passes ─────────────────────────────────────────────────────
function mergeFeatures(urlF, domF, apiF) {
  if (!urlF) return null;
  var m = Object.assign({}, urlF);
  // Merge DOM features
  if (domF) {
    DOM_FEATURES.forEach(function(k) {
      if (domF[k] !== undefined) {
        m[k] = (k === 'InfoEmail') ? ((m[k]===-1 || domF[k]===-1) ? -1 : domF[k]) : domF[k];
      }
    });
  }
  // Merge API features (override neutral 0s with real values)
  if (apiF) {
    API_FEATURES.forEach(function(k) {
      if (apiF[k] !== undefined && apiF[k] !== 0) {
        m[k] = apiF[k];
      }
    });
  }
  return m;
}

// ── Scoring ───────────────────────────────────────────────────────────────────
// Context-aware HTTPS weighting:
// In UCI-2015, HTTPS was rare on phishing sites (weight 31.38% = correct for 2015).
// Since 2018, free TLS via Let's Encrypt means phishing sites routinely use HTTPS.
// We discount HTTPS's contribution when the domain is structurally suspicious
// (random-looking, numeric SLD, brand-in-subdomain, or suspicious TLD).
function scoreFeatures(features) {
  if (!features) return 0.10;

  // Detect structurally suspicious domain from already-computed features
  var domainSuspicious = (
    features['AbnormalURL'] === -1 ||   // random/numeric/brand-spoofing domain
    features['DNSRecording'] === -1 ||  // no DNS record at all
    (features['SubDomains'] === -1 && features['DomainRegLen'] === -1) // deep subs + short reg
  );

  var wSum=0, wTot=0, nDet=0;
  FEAT_ORDER.forEach(function(k) {
    var val = features[k] !== undefined ? features[k] : 0;
    if (val === 0) return;
    var w = RF_IMPORTANCES[k] || (1/30);
    // Discount HTTPS from 31.38% → 4% when domain is structurally suspicious
    // Rationale: free TLS (Let's Encrypt) makes HTTPS meaningless as a trust signal
    // for randomly-registered domains. The 2015 weight is no longer valid for HTTPS.
    if (k === 'HTTPS' && domainSuspicious && val === 1) {
      w = 0.04;
    }
    wSum += w * (val === -1 ? 1.0 : 0.0);
    wTot += w; nDet++;
  });
  if (wTot===0 || nDet===0) return 0.10;
  var raw  = wSum / wTot;
  var conf = Math.min(1.0, nDet / 6.0);
  return raw * conf + 0.15 * (1.0 - conf);
}

// ── Risk classification ───────────────────────────────────────────────────────
function getRiskInfo(prob, threshold) {
  var t = threshold || 0.5;
  if (prob < 0.20) return { level:'SAFE',        badge:'✅', cls:'safe',        color:'#22c55e' };
  if (prob < 0.40) return { level:'LIKELY SAFE', badge:'🟢', cls:'likely-safe', color:'#84cc16' };
  if (prob < t)    return { level:'SUSPICIOUS',  badge:'⚠️',  cls:'suspicious',  color:'#f97316' };
  if (prob < 0.82) return { level:'PHISHING',    badge:'🚨', cls:'phishing',    color:'#ef4444' };
  return                   { level:'HIGH RISK',  badge:'🔴', cls:'high-risk',   color:'#dc2626' };
}
