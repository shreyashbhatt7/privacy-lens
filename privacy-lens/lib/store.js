// lib/store.js
//
// Two jobs:
//  1. Hash any raw identifier (ETag value, cookie-like cache key, etc.)
//     before it ever touches storage or the UI.
//  2. Persist TrackingEvents INCREMENTALLY to chrome.storage.session.
//     The MV3 service worker can be killed ~30s after going idle, so we
//     never buffer events in a plain JS array waiting for some "final flush".
//     Every event is appended as it's produced.

const EVENTS_KEY = "pl_events";
const MAX_EVENTS_IN_MEMORY = 5000; // simple ring-buffer cap for the hackathon

/** SHA-256 hash of a raw string, hex-encoded. Never display/store raw identifiers. */
export async function hashIdentifier(rawValue) {
  const enc = new TextEncoder().encode(String(rawValue));
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Append one event immediately. Called by every detector as soon as it
 * decides something is worth reporting — not batched.
 */
export async function appendEvent(event) {
  const { [EVENTS_KEY]: existing = [] } = await chrome.storage.session.get(EVENTS_KEY);
  existing.push(event);
  if (existing.length > MAX_EVENTS_IN_MEMORY) {
    existing.splice(0, existing.length - MAX_EVENTS_IN_MEMORY);
  }
  await chrome.storage.session.set({ [EVENTS_KEY]: existing });

  // Let the side panel / correlation engine react live rather than polling.
  chrome.runtime.sendMessage({ type: "pl_new_event", event }).catch(() => {
    // No listener yet (panel closed) — fine, event is already persisted.
  });
}

export async function getAllEvents() {
  const { [EVENTS_KEY]: existing = [] } = await chrome.storage.session.get(EVENTS_KEY);
  return existing;
}

export async function clearEvents() {
  await chrome.storage.session.remove(EVENTS_KEY);
}

/**
 * Clears only the events belonging to one tab — called on a fresh
 * top-level navigation (including a plain reload) so a site's score
 * reflects the current page load, not every visit since the browser
 * session started.
 */
export async function clearEventsForTab(tabId) {
  const { [EVENTS_KEY]: existing = [] } = await chrome.storage.session.get(EVENTS_KEY);
  const remaining = existing.filter((e) => e.tabId !== tabId);
  await chrome.storage.session.set({ [EVENTS_KEY]: remaining });
}

/**
 * Small persistent (not per-session) key/value map for cross-visit detector
 * state — e.g. "have we seen this ETag value from this domain before".
 * Uses chrome.storage.local so it survives browser restarts, which is the
 * whole point of the ETag/cache detectors (persistence across sessions).
 */
export async function getPersistentMap(mapKey) {
  const { [mapKey]: existing = {} } = await chrome.storage.local.get(mapKey);
  return existing;
}

export async function setPersistentMap(mapKey, obj) {
  await chrome.storage.local.set({ [mapKey]: obj });
}
