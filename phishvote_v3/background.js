// background.js — PhishVote v3 service worker
// Sets toolbar badge colour based on URL-level phishing signals.

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
  if (changeInfo.status !== 'complete' || !tab.url) return;
  try {
    var u    = new URL(tab.url);
    var host = u.hostname.toLowerCase();
    var path = u.pathname + u.search;
    var ipRe    = /^(\d{1,3}\.){3}\d{1,3}$/;
    var shortRe = /^(bit\.ly|tinyurl\.com|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bl\.ink|rb\.gy|cutt\.ly|short\.link|tiny\.cc)$/i;
    var dots    = host.split('.').length - 2;

    var signals = [
      ipRe.test(host),
      tab.url.length > 75,
      shortRe.test(host),
      tab.url.includes('@'),
      path.indexOf('//') !== -1,
      host.includes('-'),
      dots > 2,
      u.protocol !== 'https:',
      (u.port && ['80','443',''].indexOf(u.port) === -1),
      host.indexOf('https') !== -1,
    ];
    var hits = signals.filter(Boolean).length;

    if (hits >= 4) {
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#e74c3c' });
      chrome.action.setBadgeText({ tabId: tabId, text: '!' });
    } else if (hits >= 2) {
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#f39c12' });
      chrome.action.setBadgeText({ tabId: tabId, text: '?' });
    } else {
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: '#2ecc71' });
      chrome.action.setBadgeText({ tabId: tabId, text: '' });
    }
  } catch(e) {
    chrome.action.setBadgeText({ tabId: tabId, text: '' });
  }
});
