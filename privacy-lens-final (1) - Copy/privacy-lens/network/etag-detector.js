// network/etag-detector.js
//
// An ETag is meant for cache validation, but a tracker can hand out a
// unique ETag value that the browser dutifully echoes back on every
// visit — functioning as an invisible cookie. The signal is NOT
// "an ETag exists". It's "the same value keeps coming back, across
// navigations/sessions, and possibly across sites."
//
// We never store or display raw ETag values — only their hash.

import { createTrackingEvent } from "../shared/events.js";
import { hashIdentifier, getPersistentMap, setPersistentMap, appendEvent } from "../lib/store.js";
import { getRegistrableDomain } from "./tracker-list.js";

const STORE_KEY = "pl_etag_observations";
const SESSION_REPORTED_KEY = "pl_etag_reported_session";
const SEVERITY_RANK = { low: 1, medium: 2, high: 3 };

// Confidence grows with reuse count and with cross-site spread, caps at 0.95.
function scoreReuse({ timesSeen, siteCount }) {
  const reuseComponent = Math.min(timesSeen / 6, 0.6); // saturates around 6 reuses
  const spreadComponent = Math.min((siteCount - 1) * 0.2, 0.35); // cross-site is worse
  return Math.min(0.95, 0.05 + reuseComponent + spreadComponent);
}

// Session-scoped "have we already told the Live Feed about this exact
// domain+ETag combo, and at what severity" — separate from the persistent
// cross-session observation map above. Without this, every single request
// that reuses an already-flagged ETag re-emits an identical event, which is
// why one page load produced 58 near-duplicate entries.
//
// IMPORTANT: the decision to report must happen SYNCHRONOUSLY against an
// in-memory Map, not via two separate awaited chrome.storage.session calls.
// A real site fires many requests to the same tracker within milliseconds —
// if inspectEtag() awaits a read, then awaits a write, two concurrent calls
// for the same mapKey can both read "not yet reported" before either write
// lands, and both slip through at the same severity. JS is single-threaded,
// so a synchronous Map.get/Map.set pair with no await in between cannot
// race, no matter how many concurrent requests are in flight.
//
// chrome.storage.session is still used, but only as best-effort persistence
// so the state survives a service-worker restart — it is not what gates
// the decision.
const sessionReportedCache = new Map(); // mapKey -> "low" | "medium" | "high"
let sessionCacheHydrated = false;
let hydratePromise = null;

async function ensureHydrated() {
  if (sessionCacheHydrated) return;
  if (!hydratePromise) {
    hydratePromise = (async () => {
      const { [SESSION_REPORTED_KEY]: reported = {} } = await chrome.storage.session.get(SESSION_REPORTED_KEY);
      for (const [key, severity] of Object.entries(reported)) {
        sessionReportedCache.set(key, severity);
      }
      sessionCacheHydrated = true;
    })();
  }
  await hydratePromise;
}

function persistSessionCacheInBackground() {
  // Fire-and-forget — never awaited by the decision path, so it can't
  // reintroduce the race. Worst case on a crash mid-write: state resets,
  // which just means one possible extra duplicate, not a correctness bug.
  chrome.storage.session
    .set({ [SESSION_REPORTED_KEY]: Object.fromEntries(sessionReportedCache) })
    .catch((err) => console.error("[PrivacyLens][etag] failed to persist session cache", err));
}

/**
 * @param {Object} params
 * @param {string} params.etagValue     - raw ETag header value
 * @param {string} params.requestDomain - hostname the request went to
 * @param {string} params.topSite       - top-level site the user is browsing
 * @param {number} params.tabId
 */
export async function inspectEtag({ etagValue, requestDomain, topSite, tabId }) {
  if (!etagValue) return;

  // Weak ETags (W/"...") and obviously short/generic values are much less
  // likely to be tracking identifiers (e.g. W/"abc" style build hashes).
  const cleaned = etagValue.replace(/^W\//, "").replace(/"/g, "");
  if (cleaned.length < 8) return;

  await ensureHydrated(); // no-op after the first call in this worker lifetime

  const domainHash = await hashIdentifier(getRegistrableDomain(requestDomain));
  const valueHash = await hashIdentifier(cleaned);
  const mapKey = `${domainHash}:${valueHash}`;

  const observations = await getPersistentMap(STORE_KEY);
  const prior = observations[mapKey] ?? { timesSeen: 0, sites: [], firstSeen: Date.now() };

  prior.timesSeen += 1;
  if (!prior.sites.includes(topSite)) prior.sites.push(topSite);
  observations[mapKey] = prior;
  await setPersistentMap(STORE_KEY, observations);

  // Require at least one repeat sighting before we say anything —
  // a single observation is not evidence of persistence.
  if (prior.timesSeen < 2) return;

  const confidence = scoreReuse({ timesSeen: prior.timesSeen, siteCount: prior.sites.length });
  const severity = confidence >= 0.7 ? "high" : confidence >= 0.4 ? "medium" : "low";

  // SYNCHRONOUS check-and-mark — no await between the read and the write,
  // so two concurrent calls for the same mapKey cannot both pass.
  const lastReported = sessionReportedCache.get(mapKey) ?? null;
  if (lastReported && SEVERITY_RANK[severity] <= SEVERITY_RANK[lastReported]) return;
  sessionReportedCache.set(mapKey, severity);
  persistSessionCacheInBackground();

  const event = createTrackingEvent({
    tabId,
    site: topSite,
    category: "identifier",
    subtype: "etag",
    source: { requestDomain },
    target: { domain: getRegistrableDomain(requestDomain) },
    evidence: {
      api: "ETag header",
      valueHash,
      timesSeen: prior.timesSeen,
      distinctSitesSeenOn: prior.sites.length,
    },
    severity,
    confidence,
  });

  await appendEvent(event);
}
