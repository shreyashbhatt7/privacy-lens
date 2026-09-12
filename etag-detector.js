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
async function getSessionReportState(mapKey) {
  const { [SESSION_REPORTED_KEY]: reported = {} } = await chrome.storage.session.get(SESSION_REPORTED_KEY);
  return reported[mapKey] ?? null; // null | "low" | "medium" | "high"
}

async function setSessionReportState(mapKey, severity) {
  const { [SESSION_REPORTED_KEY]: reported = {} } = await chrome.storage.session.get(SESSION_REPORTED_KEY);
  reported[mapKey] = severity;
  await chrome.storage.session.set({ [SESSION_REPORTED_KEY]: reported });
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

  // Skip if we've already reported this exact combo this session at an
  // equal-or-higher severity. Let a genuine escalation (e.g. it spreads to
  // a new site and crosses into "high") through instead of staying silent.
  const lastReported = await getSessionReportState(mapKey);
  if (lastReported && SEVERITY_RANK[severity] <= SEVERITY_RANK[lastReported]) return;
  await setSessionReportState(mapKey, severity);

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
