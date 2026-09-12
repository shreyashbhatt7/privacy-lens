/**
 * Privacy Lens - MAIN World Entry Point & Dispatcher
 * Owner: Person 2 (Browser Forensics)
 * 
 * Phase 2-12: Tier 1 MAIN-world Hooks
 * 
 * Runs directly in the page's JS context ("world": "MAIN").
 * Installs prototype hooks across all fingerprint vectors and provides
 * window.__PL_report to dispatch raw TrackingEvent payloads via postMessage.
 */

import { MESSAGE_SOURCES } from '../shared/constants.js';
import { createFingerprintDraft, extractDomain } from '../shared/events.js';
import { initCanvasHooks } from './canvas.js';
import { initWebGLHooks } from './webgl.js';
import { initAudioHooks } from './audio.js';
import { initStorageHooks } from './storage.js';
import { initFontHooks } from './fonts.js';

/**
 * Dispatches an observed API access event to the isolated content script bridge.
 * @param {string} subtype - Vector category ("canvas", "webgl", "audio", "storage", "beacon", "font")
 * @param {Object} rawEvidence - Raw API evidence details (e.g. { api: "HTMLCanvasElement.toDataURL", url, ... })
 */
export function report(subtype, rawEvidence = {}) {
  try {
    const stack = new Error().stack || '';
    const { api = subtype, url, ...details } = rawEvidence;

    // For beacon/fetch/xhr, extract target domain from URL
    const targetDomain = extractDomain(url);
    const resolvedDetails = url ? { ...details, url } : details;

    const eventDraft = createFingerprintDraft({
      subtype,
      api,
      details: resolvedDetails,
      targetDomain,
      stack
    });

    window.postMessage({
      source: MESSAGE_SOURCES.MAIN_WORLD,
      __privacyLens: true,
      payload: eventDraft,
      event: eventDraft
    }, '*');
  } catch (err) {
    // Fail-safe to ensure page scripts are never broken
    console.debug('[PrivacyLens] report error:', err);
  }
}

// Attach to window so all hook modules can report reliably
if (typeof window !== 'undefined') {
  window.__PL_report = report;
}

// Initialize all hook submodules immediately at document_start
(function initializeMainWorldHooks() {
  initCanvasHooks();
  initWebGLHooks();
  initAudioHooks();
  initStorageHooks();
  initFontHooks();
})();
