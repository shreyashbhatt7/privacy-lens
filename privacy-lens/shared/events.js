// shared/events.js
//
// TrackingEvent schema, validators, and MAIN-world draft helpers — THE
// integration contract per ARCHITECTURE_LOCK.md (section 6: shared/events.js).
// Every detector in network/, fingerprint/, and (eventually) detection/
// imports from here. Do not fork a second copy of this file.
//
// ─────────────────────────────────────────────────────────────────────────
// TWO-STAGE EVENT LIFECYCLE (this is the piece that used to be undocumented
// and caused the Person 1 vs Person 2 schema drift called out in
// docs/EVENT_SCHEMA_REFERENCE.md):
//
//   1. DRAFT (page/MAIN-world context — fingerprint/*.js via main-world.js)
//      Created by createFingerprintDraft(). At this point we're running
//      inside the page itself: there is no chrome.* API access, and we
//      don't know the tabId or the top-level site. The draft is sent via
//      window.postMessage -> content-bridge.js -> chrome.runtime.sendMessage
//      to the background service worker, where evidence is still nested
//      as evidence.details (see createFingerprintDraft below).
//
//   2. FINAL TrackingEvent (background service worker context)
//      Created by createTrackingEvent(). This is the ONLY function that
//      produces a canonical, validated TrackingEvent — the shape documented
//      in docs/EVENT_SCHEMA_REFERENCE.md and consumed by lib/store.js,
//      the panel UI, and (eventually) Person 3's correlation engine.
//
//      background.js is responsible for turning a fingerprint draft into a
//      final event: it fills in tabId/site (known once you have `sender.tab`
//      in a chrome.runtime.onMessage listener) and FLATTENS
//      evidence.details into evidence per EVENT_SCHEMA_REFERENCE.md
//      correction #1 ("evidence.details does not exist anywhere in
//      Person 1's code — all evidence fields are flat"). Person 1's network
//      detectors already call createTrackingEvent() directly with flat
//      evidence, since they run in the background and know tabId/site
//      immediately — they never go through the draft stage at all.
//
// This resolves the schema question EVENT_SCHEMA_REFERENCE.md left open as
// "Option A vs Option B": we standardize on Option B (flat evidence, single
// canonical shape) but only at the background ingestion boundary, so
// neither Person 1's nor Person 2's existing detector code needed to change.
// ─────────────────────────────────────────────────────────────────────────

const VALID_CATEGORIES = ["fingerprinting", "network", "storage", "identifier"];
const VALID_SEVERITIES = ["low", "medium", "high"];

let _counter = 0;
function nextId() {
  _counter += 1;
  return `evt_${Date.now()}_${_counter}`;
}

/**
 * Canonical, validated TrackingEvent shape:
 *   id: string            — auto-generated
 *   timestamp: number      — auto-generated (Date.now())
 *   tabId: number | null
 *   site: string | null    — top-level eTLD+1 the user is browsing
 *   category: "fingerprinting" | "network" | "storage" | "identifier"
 *   subtype: string        — free-form, detector-defined (e.g. "canvas", "etag", "cname", "beacon")
 *   source: object         — detector-defined, e.g. { script } for fingerprint hooks,
 *                             { requestDomain } / { url } / { requestHostname } for network detectors
 *   target: object         — detector-defined, but every current detector uses { domain }
 *   evidence: object       — FLAT, detector-defined fields (e.g. { api, valueHash, timesSeen }).
 *                             Do NOT nest a second `.details` object in here — see note above.
 *   severity: "low" | "medium" | "high"
 *   confidence: number     — 0.0–1.0
 *
 * Only category, severity, and confidence are validated below. source/target/
 * evidence are intentionally free-form objects — consumers (correlation
 * engine, UI) must branch on category/subtype to know which keys to expect.
 * See docs/EVENT_SCHEMA_REFERENCE.md for the current per-detector key table.
 *
 * @param {Object} fields
 * @param {number} [fields.tabId]
 * @param {string} [fields.site]
 * @param {"fingerprinting"|"network"|"storage"|"identifier"} fields.category
 * @param {string} fields.subtype
 * @param {Object} [fields.source]
 * @param {Object} [fields.target]
 * @param {Object} [fields.evidence]
 * @param {"low"|"medium"|"high"} fields.severity
 * @param {number} fields.confidence
 */
export function createTrackingEvent(fields) {
  if (!VALID_CATEGORIES.includes(fields.category)) {
    throw new Error(`Invalid category: ${fields.category}`);
  }
  if (!VALID_SEVERITIES.includes(fields.severity)) {
    throw new Error(`Invalid severity: ${fields.severity}`);
  }
  if (typeof fields.confidence !== "number" || fields.confidence < 0 || fields.confidence > 1) {
    throw new Error(`Invalid confidence: ${fields.confidence}`);
  }

  return {
    id: nextId(),
    timestamp: Date.now(),
    tabId: fields.tabId ?? null,
    site: fields.site ?? null,
    category: fields.category,
    subtype: fields.subtype,
    source: fields.source ?? {},
    target: fields.target ?? {},
    evidence: fields.evidence ?? {},
    severity: fields.severity,
    confidence: fields.confidence,
  };
}

// ─────────────────────────────────────────────────────────────────────────
// MAIN-world draft helpers (Person 2 / fingerprint/*.js). These run inside
// the page's own JS context, before anything is finalized into a real
// TrackingEvent — see lifecycle note at the top of this file.
// ─────────────────────────────────────────────────────────────────────────

/**
 * Extracts the calling script URL from an Error stack trace.
 * Filters out internal extension bundle stack frames and extracts the clean URL.
 * @param {string} stack - Raw new Error().stack string
 * @returns {string} Extracted script URL or 'inline'
 */
export function parseScriptFromStack(stack) {
  if (!stack || typeof stack !== 'string') return 'inline';
  const lines = stack.split('\n').slice(1); // skip "Error" line
  for (const line of lines) {
    // Skip extension bundle frames or internal helper calls
    if (line.includes('main-world.bundle') || line.includes('main-world.js') || line.includes('content-bridge')) {
      continue;
    }
    // Match http/https/file URLs with optional line:col numbers
    const match = line.match(/(https?:\/\/[^\s\)\:]+|file:\/\/[^\s\)\:]+)(?::\d+)?(?::\d+)?/);
    if (match && match[1]) {
      return match[1];
    }
  }
  return 'inline';
}

/**
 * Extracts hostname domain from a target URL string.
 * @param {string} urlStr - Target endpoint URL
 * @returns {string|undefined} Domain name or undefined
 */
export function extractDomain(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return undefined;
  try {
    const base = typeof window !== 'undefined' && window.location?.href ? window.location.href : 'http://localhost';
    const parsed = new URL(urlStr, base);
    return parsed.hostname || undefined;
  } catch (err) {
    return undefined;
  }
}

/**
 * Creates a draft TrackingEvent payload from Person 2's fingerprint hooks.
 * NOT a final TrackingEvent — no id, no tabId, no site (unknowable from
 * page context). background.js finalizes this into a real event via
 * createTrackingEvent() once it arrives with sender.tab info attached.
 * Evidence is nested under `.details` here as an implementation convenience
 * for the MAIN-world hooks; background.js flattens it on finalization.
 *
 * @param {Object} params
 * @param {string} params.subtype - "canvas" | "webgl" | "audio" | "storage" | "beacon" | "font"
 * @param {string} [params.script] - URL of caller script extracted from stack trace
 * @param {string} [params.stack] - Optional raw stack trace for parsing script
 * @param {string} params.api - Exact name of the API called
 * @param {Object} [params.details] - Optional extra metadata/arguments (nested under evidence.details)
 * @param {string} [params.targetDomain] - Optional target domain (populated for beacon/fetch/xhr)
 * @returns {Object} Draft tracking event object (see lifecycle note above)
 */
export function createFingerprintDraft({
  subtype,
  script = undefined,
  stack = '',
  api,
  details = {},
  targetDomain = undefined
}) {
  const resolvedScript = script || (stack ? parseScriptFromStack(stack) : 'inline');

  return {
    category: 'fingerprinting',
    subtype,
    source: {
      script: resolvedScript
    },
    target: targetDomain ? { domain: targetDomain } : undefined,
    evidence: {
      api,
      details: details || {}
    },
    timestamp: Date.now(),
    severity: 'low',
    confidence: 0.0 // Placeholder: Person 2 does NOT set confidence, Person 3 calculates in correlation engine
  };
}
