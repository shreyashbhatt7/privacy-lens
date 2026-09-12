// ui/event-display.js
//
// Person 3's sidepanel UI was originally built and demoed against ad-hoc
// mock events shaped like { type, domain, severity: "HIGH", timestamp }.
// The real pipeline (Person 1's network detectors + Person 2's fingerprint
// hooks, finalized in background.js) produces the canonical TrackingEvent
// shape instead: { id, timestamp, tabId, site, category, subtype, source,
// target, evidence, severity: "low", confidence }. See
// docs/EVENT_SCHEMA_REFERENCE.md for the authoritative schema.
//
// This module is the adapter between the two — kept separate from
// sidepanel.js (which is DOM-bound) so the mapping itself is a plain,
// testable function.

// category:subtype -> human-readable label for the Live Feed.
// Sourced from docs/EVENT_SCHEMA_REFERENCE.md's per-detector table plus
// the fingerprint subtypes fingerprint/*.js actually emits.
const TYPE_LABELS = {
  "identifier:etag": "ETAG TRACKING",
  "identifier:cache-token": "CACHE TOKEN TRACKING",
  "network:cname-cloaking": "CNAME CLOAKING",
  "network:beacon": "THIRD-PARTY BEACON",
  "network:third-party-load": "THIRD-PARTY SCRIPT LOAD",
  "fingerprinting:canvas": "CANVAS FINGERPRINT",
  "fingerprinting:webgl": "WEBGL FINGERPRINT",
  "fingerprinting:audio": "AUDIO FINGERPRINT",
  "fingerprinting:font": "FONT FINGERPRINT",
  "fingerprinting:storage": "STORAGE/COOKIE PROBE",
  "fingerprinting:beacon": "SCRIPT NETWORK CALL",
};

/**
 * Human-readable event type label for the Live Feed, e.g. "CANVAS FINGERPRINT".
 * Falls back to a generated "CATEGORY · SUBTYPE" label for anything not in
 * the table above, so a future detector (Person 3's correlation engine,
 * a new fingerprint vector, etc.) never renders as "Unknown Event".
 */
export function typeLabelFor(event) {
  const key = `${event.category}:${event.subtype}`;
  return TYPE_LABELS[key] ?? `${(event.category ?? "unknown").toUpperCase()} · ${(event.subtype ?? "?").toUpperCase()}`;
}

/**
 * Domain shown under each feed entry. Prefers the tracker/target domain
 * (present for network/identifier events and fingerprint beacon calls) —
 * that's the more informative "who" for a tracking event — and falls back
 * to the site being browsed for pure fingerprint reads (canvas, WebGL,
 * audio, fonts, storage) where there's no remote endpoint to report.
 */
export function domainFor(event) {
  return event.target?.domain || event.site || "Unknown domain";
}

/** Canonical severity is lowercase ("low"/"medium"/"high"); the UI's filter
 * buttons and CSS classes use uppercase. */
export function severityUpper(event) {
  return (event.severity ?? "low").toUpperCase();
}

/**
 * Full display-ready projection of a canonical TrackingEvent, for the feed
 * card and dashboard stats. Keeps the original event under `raw` so JSON
 * export can still include the full canonical record.
 */
export function toDisplayEvent(event) {
  return {
    raw: event,
    type: typeLabelFor(event),
    domain: domainFor(event),
    severity: severityUpper(event),
    timestamp: event.timestamp,
    site: event.site ?? null,
  };
}
