// inject_keys.js — runs once on install to pre-load API keys into storage
// Keys are pre-configured for this installation of PhishVote.

chrome.runtime.onInstalled.addListener(function() {
  chrome.storage.local.get([
    'pv_whois_key','pv_openpagerank_key',
    'pv_google_cse_key','pv_google_cse_cx','pv_virustotal_key'
  ], function(existing) {
    var defaults = {};
    // Only set if not already set (don't overwrite if user changed them)
    if (!existing['pv_whois_key'])
      defaults['pv_whois_key'] = 'at_ZBmYfOuPFzVkWTyxNVnwTz3T3yLaj';
    if (!existing['pv_openpagerank_key'])
      defaults['pv_openpagerank_key'] = 'wc4o8ooow4wwc8ww4cgs08gws04kws0sg8o8000k';
    if (!existing['pv_google_cse_key'])
      defaults['pv_google_cse_key'] = 'AIzaSyDFsUwaxJYDgTnFIYBN_Gxc2ejcN_QR_mw';
    if (!existing['pv_google_cse_cx'])
      defaults['pv_google_cse_cx'] = '70ddd580a338f4805';
    if (!existing['pv_virustotal_key'])
      defaults['pv_virustotal_key'] = '9780c1220271acfe813fa76fbf66c8caef59dd2530d720a2c5ce95ca60a681ae';
    if (Object.keys(defaults).length > 0) {
      chrome.storage.local.set(defaults, function() {
        console.log('[PhishVote] API keys pre-loaded:', Object.keys(defaults));
      });
    }
  });
});
