// network/cache-detector.js
//
// A tracker can set Cache-Control: immutable / a very long max-age on a
// small resource, so the CACHED FILE ITSELF becomes a persistent
// identifier — it survives cookie clears because it isn't a cookie.
// We flag: aggressive cache directives + a URL path that looks like it
// carries a per-user token (long hex/base64-ish segment) rather than a
// generic static asset name.

import { createTrackingEvent } from "../shared/events.js";
import { appendEvent } from "../lib/store.js";
import { getRegistrableDomain } from "./tracker-list.js";

const LONG_MAX_AGE_SECONDS = 60 * 60 * 24 * 30; // 30 days
const TOKEN_LIKE = /[a-f0-9]{16,}|[A-Za-z0-9_-]{24,}/; // hex/base64-ish long run

function parseCacheControl(headerValue) {
  const parts = headerValue.toLowerCase().split(",").map((s) => s.trim());
  const result = { immutable: false, maxAge: null, noStore: false };
  for (const part of parts) {
    if (part === "immutable") result.immutable = true;
    if (part === "no-store") result.noStore = true;
    const m = part.match(/^max-age=(\d+)/);
    if (m) result.maxAge = parseInt(m[1], 10);
  }
  return result;
}

/**
 * @param {Object} params
 * @param {string} params.url
 * @param {string} params.cacheControlHeader
 * @param {string} params.topSite
 * @param {number} params.tabId
 */
export async function inspectCacheHeaders({ url, cacheControlHeader, topSite, tabId }) {
  if (!cacheControlHeader) return;

  const { immutable, maxAge, noStore } = parseCacheControl(cacheControlHeader);
  if (noStore) return;

  const aggressive = immutable || (maxAge !== null && maxAge >= LONG_MAX_AGE_SECONDS);
  if (!aggressive) return;

  let path;
  try {
    path = new URL(url).pathname;
  } catch {
    return;
  }
  const looksLikeToken = TOKEN_LIKE.test(path);
  if (!looksLikeToken) return; // long cache on e.g. /logo.png alone isn't suspicious

  const requestDomain = new URL(url).hostname;
  // Immutable cache tokens permanently bypass revalidation and act as supercookies -> high confidence (0.75).
  // Standard long max-age cache tokens -> medium confidence (0.55).
  const confidence = immutable ? 0.75 : 0.55;
  const severity = confidence >= 0.7 ? "high" : confidence >= 0.4 ? "medium" : "low";

  const event = createTrackingEvent({
    tabId,
    site: topSite,
    category: "identifier",
    subtype: "cache-token",
    source: { url },
    target: { domain: getRegistrableDomain(requestDomain) },
    evidence: {
      api: "Cache-Control header",
      immutable,
      maxAgeSeconds: maxAge,
      pathLooksTokenized: true,
    },
    severity,
    confidence,
  });

  await appendEvent(event);
}
