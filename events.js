// shared/events.js
//
// TrackingEvent schema + validators — THE integration contract per the
// implementation plan's repo structure (section 6: shared/events.js).
// Every detector in network/, fingerprint/, and detection/ imports from
// here. Do not fork a second copy of this file anywhere.
//
// This replaces the earlier lib/event-schema.js — that file's contents
// live here now. Update any stray imports if you find them.

const VALID_CATEGORIES = ["fingerprinting", "network", "storage", "identifier"];
const VALID_SEVERITIES = ["low", "medium", "high"];

let _counter = 0;
function nextId() {
  _counter += 1;
  return `evt_${Date.now()}_${_counter}`;
}

/**
 * Enforced shape:
 *   id: string            — auto-generated
 *   timestamp: number      — auto-generated (Date.now())
 *   tabId: number | null
 *   site: string | null    — top-level eTLD+1 the user is browsing
 *   category: "fingerprinting" | "network" | "storage" | "identifier"
 *   subtype: string        — free-form, detector-defined (e.g. "canvas", "etag", "cname", "beacon")
 *   source: object         — detector-defined, e.g. { script } for fingerprint hooks,
 *                             { requestDomain } / { url } / { requestHostname } for network detectors
 *   target: object         — detector-defined, but every current detector uses { domain }
 *   evidence: object       — FLAT, detector-defined fields (e.g. { api, valueHash, timesSeen })
 *                             — do NOT assume a nested evidence.details shape unless the team
 *                             explicitly standardizes on one
 *   severity: "low" | "medium" | "high"
 *   confidence: number     — 0.0–1.0
 *
 * Only category, severity, and confidence are validated below. source/target/
 * evidence are intentionally free-form objects — consumers (correlation
 * engine, UI) must branch on category/subtype to know which keys to expect.
 * See EVENT_SCHEMA_REFERENCE.md for the current per-detector key table.
 *
 * @param {Object} fields
 * @param {number} fields.tabId
 * @param {string} fields.site
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
