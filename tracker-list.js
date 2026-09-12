// network/tracker-list.js
//
// Wraps the bundled tracker dataset. Used by cname-detector and
// thirdparty-detector so both agree on "is this domain a tracker" and
// "is this domain a known-benign heavy caller we should not flag".

let _trackers = null;
let _allowlist = null;

async function loadDataset() {
  if (_trackers && _allowlist) return;
  const url = chrome.runtime.getURL("data/tracker-domains.json");
  const res = await fetch(url);
  const data = await res.json();
  _trackers = new Set(data.trackers);
  _allowlist = new Set(data.allowlist);
}

/** Returns the registrable domain (simple eTLD+1 heuristic — good enough for a hackathon). */
export function getRegistrableDomain(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;
  // naive: last two labels, except common two-part TLDs
  const twoPartTlds = new Set(["co.uk", "com.au", "co.in", "co.jp"]);
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTlds.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

export async function isKnownTracker(hostname) {
  await loadDataset();
  const domain = getRegistrableDomain(hostname);
  return _trackers.has(domain);
}

export async function isAllowlisted(hostname) {
  await loadDataset();
  const domain = getRegistrableDomain(hostname);
  return _allowlist.has(domain) || _allowlist.has(hostname);
}
