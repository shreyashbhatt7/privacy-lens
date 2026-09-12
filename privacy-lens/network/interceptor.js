// network/interceptor.js
//
// This is the wiretap. chrome.webRequest fires onBeforeRequest before a
// request goes out and onHeadersReceived once the response headers are
// back — they're correlated by requestId. We stitch the two together
// into one "request record" and hand it to each detector.
//
// IMPORTANT: this file does no batching. Every detector call either
// returns immediately (nothing interesting) or calls appendEvent(),
// which writes to chrome.storage.session right away. The service worker
// can die ~30s after going idle — there is no "flush at the end".

import { inspectEtag } from "./etag-detector.js";
import { inspectCacheHeaders } from "./cache-detector.js";
import { inspectForCnameCloaking } from "./cname-detector.js";
import { inspectThirdPartyCall } from "./thirdparty-detector.js";
import { getRegistrableDomain } from "./tracker-list.js";

// Short-lived, per-requestId scratch space to join onBeforeRequest with
// onHeadersReceived. Not persisted — if the SW dies mid-flight for a
// specific in-progress request, that's an acceptable loss (the request
// itself didn't complete meaningfully). Persisted state lives in lib/store.js.
const inFlight = new Map();

// `initiator` can be undefined, the opaque string "null" (sandboxed iframes,
// some ad requests), or otherwise not a valid absolute URL. Never let a
// bad initiator take down the whole detector pipeline for a request.
function safeHostname(urlLike) {
  if (!urlLike || urlLike === "null") return null;
  try {
    return new URL(urlLike).hostname;
  } catch {
    return null;
  }
}

function getHeader(headers, name) {
  const lower = name.toLowerCase();
  const found = (headers ?? []).find((h) => h.name.toLowerCase() === lower);
  return found ? found.value : null;
}

async function getTopSiteForTab(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab?.url) return null;
    const url = new URL(tab.url);
    // See identical fix + rationale in background.js's getTopSiteForSenderTab —
    // file:// pages have an empty hostname, which getRegistrableDomain()
    // correctly returns as "", but that's falsy and would otherwise drop
    // every network-layer event for a locally-opened tracker-lab page.
    if (url.protocol === "file:") return "local-file";
    return getRegistrableDomain(url.hostname) || null;
  } catch {
    return null;
  }
}

export function initInterceptor() {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (details.tabId < 0) return; // ignore requests not tied to a tab (e.g. extension's own)
      inFlight.set(details.requestId, {
        url: details.url,
        method: details.method,
        initiator: details.initiator ?? null,
        type: details.type,
        tabId: details.tabId,
        timestamp: details.timeStamp,
      });
    },
    { urls: ["<all_urls>"] }
  );

  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      const record = inFlight.get(details.requestId);
      inFlight.delete(details.requestId); // don't leak entries for requests we won't see again

      if (!record) return;
      handleCompletedRequest({
        ...record,
        status: details.statusCode,
        responseHeaders: details.responseHeaders ?? [],
      }).catch((err) => console.error("[PrivacyLens] detector error", err));
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
  );

  // Bound the map's growth if some requests never complete (aborted, etc.)
  setInterval(() => {
    const cutoff = Date.now() - 2 * 60 * 1000;
    for (const [id, rec] of inFlight) {
      if (rec.timestamp < cutoff) inFlight.delete(id);
    }
  }, 60 * 1000);
}

async function handleCompletedRequest(record) {
  const topSite = await getTopSiteForTab(record.tabId);
  if (!topSite) return; // can't attribute to a site — skip

  let requestHostname;
  try {
    requestHostname = new URL(record.url).hostname;
  } catch {
    return;
  }

  const etag = getHeader(record.responseHeaders, "etag");
  const cacheControl = getHeader(record.responseHeaders, "cache-control");
  const initiatorDomain = safeHostname(record.initiator);

  // Run every detector concurrently — they're independent and each one
  // internally no-ops fast when there's nothing to flag.
  await Promise.all([
    inspectEtag({
      etagValue: etag,
      requestDomain: requestHostname,
      topSite,
      tabId: record.tabId,
    }),
    inspectCacheHeaders({
      url: record.url,
      cacheControlHeader: cacheControl,
      topSite,
      tabId: record.tabId,
    }),
    inspectForCnameCloaking({
      requestHostname,
      topSite,
      tabId: record.tabId,
    }),
    inspectThirdPartyCall({
      url: record.url,
      initiatorDomain,
      topSite,
      resourceType: record.type,
      tabId: record.tabId,
    }),
  ]);
}
