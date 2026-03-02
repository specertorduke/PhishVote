// background.js — PhishVote v2 background worker (UCI-2015)
// Sets badge color using the same URL-level heuristics as the popup's UCI-2015 features.

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;
  try {
    const url  = tab.url;
    const u    = new URL(url);
    const host = u.hostname.toLowerCase();
    const path = u.pathname + u.search;
    const ipRe    = /^(\d{1,3}\.){3}\d{1,3}$/;
    const shortRe = /^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bl\.ink|rb\.gy|cutt\.ly)$/i;
    const dots    = host.split('.').length - 2;

    // UCI-2015 phishing signals (same logic as engine.js extractURLFeatures)
    const phishSignals = [
      ipRe.test(host),                                       // UsingIP
      url.length > 75,                                       // LongURL = -1
      shortRe.test(host),                                    // ShortURL
      url.includes('@'),                                     // Symbol@
      path.indexOf('//') !== -1,                             // Redirecting//
      host.includes('-'),                                    // PrefixSuffix-
      dots > 2,                                              // SubDomains = -1
      u.protocol !== 'https:',                               // HTTPS = -1
      (u.port && ['80','443',''].indexOf(u.port) === -1),    // NonStdPort
      host.indexOf('https') !== -1,                          // HTTPSDomainURL
    ];
    const hits = phishSignals.filter(Boolean).length;

    if (hits >= 4) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#e74c3c' });
      chrome.action.setBadgeText({ tabId, text: '!' });
    } else if (hits >= 2) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#f39c12' });
      chrome.action.setBadgeText({ tabId, text: '?' });
    } else {
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#2ecc71' });
      chrome.action.setBadgeText({ tabId, text: '' });
    }
  } catch (e) {
    chrome.action.setBadgeText({ tabId, text: '' });
  }
});
