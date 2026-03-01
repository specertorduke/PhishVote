// background.js — PhishVote v2 background worker
// Sets badge color based on quick heuristic checks

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url) return;
  try {
    const url = tab.url.toLowerCase();
    const host = new URL(url).hostname;
    const checks = [
      /^(\d{1,3}\.){3}\d{1,3}$/.test(host),
      url.includes('@'),
      !url.startsWith('https'),
      host.includes('-') && host.split('.').length > 3,
      url.length > 100,
      ['bit.ly','tinyurl','goo.gl','ow.ly'].some(s => host.includes(s)),
    ];
    const hits = checks.filter(Boolean).length;
    if (hits >= 3) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#e74c3c' });
      chrome.action.setBadgeText({ tabId, text: '!' });
    } else if (hits >= 1) {
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
