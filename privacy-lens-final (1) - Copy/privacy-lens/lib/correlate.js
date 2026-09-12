// lib/correlate.js
//
// Person 1's network-layer thirdparty-detector.js and Person 2's
// fingerprint-layer storage.js (sendBeacon/fetch/XHR hooks) can both fire
// for the SAME real outbound call, from two different vantage points
// (webRequest headers vs. a monkey-patched page-context API). Rather than
// treating the second sighting as noise to delete, we tag both events as
// "confirmed via 2 independent detection layers" when they share a target
// domain and land within a short window of each other — this is genuinely
// stronger evidence than either alone, and should read that way in the UI.
//
// Pure function, no chrome.* dependency — safe to unit test with plain node
// and safe to run in the side panel on every re-render.

const CORRELATION_WINDOW_MS = 2000;

function isBeaconLike(event) {
  return (
    (event.category === "network" && (event.subtype === "beacon" || event.subtype === "third-party-load")) ||
    (event.category === "fingerprinting" && event.subtype === "beacon")
  );
}

/**
 * Returns a NEW array (does not mutate input) where any event that has a
 * cross-layer counterpart (same target.domain, opposite category, within
 * CORRELATION_WINDOW_MS) gets `crossLayerConfirmed: true` added.
 *
 * @param {Array<Object>} events - canonical TrackingEvents
 * @returns {Array<Object>}
 */
export function correlateCrossLayerBeacons(events) {
  const candidates = events
    .map((e, idx) => ({ e, idx }))
    .filter(({ e }) => isBeaconLike(e) && e.target?.domain);

  const confirmedIds = new Set();

  for (let i = 0; i < candidates.length; i++) {
    for (let j = i + 1; j < candidates.length; j++) {
      const a = candidates[i].e;
      const b = candidates[j].e;

      if (a.category === b.category) continue; // only cross-layer pairs count
      if (a.target.domain !== b.target.domain) continue;
      if (Math.abs((a.timestamp ?? 0) - (b.timestamp ?? 0)) > CORRELATION_WINDOW_MS) continue;

      confirmedIds.add(a.id);
      confirmedIds.add(b.id);
    }
  }

  if (confirmedIds.size === 0) return events;

  return events.map((e) => (confirmedIds.has(e.id) ? { ...e, crossLayerConfirmed: true } : e));
}
