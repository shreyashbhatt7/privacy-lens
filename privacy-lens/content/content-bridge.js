/**
 * Privacy Lens - Isolated Content Script Bridge (with 500ms Batching & Dedup)
 * Owner: Person 2 (Browser Forensics)
 * 
 * Phase 12-18: Event Batching & Deduplication
 * 
 * Runs in the ISOLATED world with access to Chrome Extension APIs.
 * Listens for window.postMessage events emitted by MAIN world hooks (main-world.js),
 * aggregates/deduplicates events within a 500ms sliding window, and flushes batches
 * to the background event bus via chrome.runtime.sendMessage.
 */

import { MESSAGE_SOURCES, MESSAGE_TYPES } from '../shared/constants.js';

let buffer = [];
let flushTimer = null;
const BATCH_WINDOW_MS = 500;

/**
 * Buffers and deduplicates incoming tracking events within a 500ms window.
 * @param {Object} event - Raw TrackingEvent payload from MAIN world
 */
export function bufferedSend(event) {
  if (!event || typeof event !== 'object') return;

  const scriptUrl = event.source?.script || 'inline';
  const apiName = event.evidence?.api || '';
  const dedupKey = `${event.subtype}:${apiName}:${scriptUrl}`;

  const existing = buffer.find((item) => item._key === dedupKey);
  if (existing) {
    existing.count = (existing.count || 1) + 1;
    // Update timestamp to most recent occurrence
    existing.timestamp = event.timestamp || Date.now();
  } else {
    buffer.push({
      ...event,
      _key: dedupKey,
      count: 1
    });
  }

  if (!flushTimer) {
    flushTimer = setTimeout(flushBuffer, BATCH_WINDOW_MS);
  }
}

/**
 * Flushes buffered events to the background service worker event bus.
 */
export function flushBuffer() {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }

  if (buffer.length === 0) return;

  const batchPayload = buffer.map(({ _key, ...eventData }) => eventData);
  buffer = [];

  // chrome.runtime.sendMessage throws SYNCHRONOUSLY (not a promise rejection)
  // with "Extension context invalidated" if this page's content script is
  // still running from a previous load of the extension (e.g. the extension
  // was reloaded/rebuilt in chrome://extensions while this tab stayed open).
  // chrome.runtime.id becomes undefined the moment that happens, so check it
  // up front, and still wrap the call itself in try/catch as a safety net
  // for the synchronous throw.
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime?.id && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage({
        type: MESSAGE_TYPES.BATCH_EVENTS,
        payload: batchPayload,
        events: batchPayload
      }).catch(() => {
        // Ignore background worker idle or disconnected port errors in development
      });
    }
  } catch (err) {
    // Extension context invalidated mid-flight — nothing to recover here;
    // this tab will get a valid context back on its next reload.
  }
}

// Listen for fingerprinting and API access events from the page context
if (typeof window !== 'undefined') {
  window.addEventListener('message', (event) => {
    // Validate same-window origin and PrivacyLens flag / source identifier
    if (event.source !== window) return;

    const isPrivacyLensEvent = event.data?.__privacyLens === true ||
      event.data?.source === MESSAGE_SOURCES.MAIN_WORLD;

    if (!isPrivacyLensEvent) return;

    const rawEvent = event.data.payload || event.data.event;
    if (!rawEvent) return;

    bufferedSend(rawEvent);
  });
}
