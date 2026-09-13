// background.js — MV3 service worker entry point.
//
// Three jobs:
//  1. Boot Person 1's network interceptor (webRequest-based detectors —
//     these call appendEvent() directly since they already run in this
//     context and know tabId/site immediately).
//  2. Receive Person 2's fingerprint event batches from content-bridge.js
//     (chrome.runtime.sendMessage), finalize each draft into a canonical
//     TrackingEvent, and persist it the same way. This listener is the
//     piece that was missing before integration — the fingerprint hooks
//     fired correctly, but nothing was listening on the background side.
//  3. Let the extension icon open the side panel (Person 3's UI, wired to
//     the live pipeline as of the second integration pass — see
//     ui/sidepanel.js and ui/event-display.js).

import { initInterceptor } from "./network/interceptor.js";
import { getRegistrableDomain } from "./network/tracker-list.js";
import { MESSAGE_TYPES } from "./shared/constants.js";
import { appendEvent, clearEventsForTab } from "./lib/store.js";
import { confidenceEngine } from "./detection/confidence-engine.js";

initInterceptor();

chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true }).catch(() => {});

// Reset per-tab history and correlation state on every fresh top-level
// navigation (including a plain reload), so a site's privacy score and
// evidence chain reflect the CURRENT page load, not every visit to that
// tab since the browser session started. Without this, pl_events only
// ever grows, and calculatePrivacyScore() sums the full session history
// with no decay — so any repeatedly-tested site eventually saturates to F
// regardless of what the current page is actually doing.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // only top-level frame, not iframes
  clearEventsForTab(details.tabId).catch((err) =>
    console.error("[PrivacyLens] failed to clear events for tab", err)
  );
  confidenceEngine.resetForTab(details.tabId);
});

/**
 * Turns one fingerprint draft (from createFingerprintDraft() in
 * shared/events.js, batched by content-bridge.js) into a canonical
 * TrackingEvent using Person 3's Confidence & Correlation Engine (Phase 24-32).
 * Fills in tabId/site, correlates signal combinations from the same script,
 * computes calibrated confidence and severity, and flattens evidence.
 */
function finalizeFingerprintDraft(draft, topSite, tabId) {
  return confidenceEngine.evaluateEvent(draft, { topSite, tabId });
}

async function getTopSiteForSenderTab(tab) {
  try {
    if (!tab?.url) return null;
    const url = new URL(tab.url);
    // file:// (and other schemes with no host, e.g. a raw local path) have an
    // empty hostname — getRegistrableDomain("") returns "", which is falsy
    // and would otherwise cause every tracker-lab fingerprint event opened
    // via file:// to be silently dropped as "can't attribute to a site".
    // Give local files a stable synthetic site label instead so demo runs
    // against tracker-lab/*.html actually record events.
    if (url.protocol === "file:") return "local-file";
    return getRegistrableDomain(url.hostname) || null;
  } catch {
    return null;
  }
}

chrome.runtime.onMessage.addListener((message, sender) => {
  if (!message?.type) return;

  if (message.type === MESSAGE_TYPES.BATCH_EVENTS) {
    const drafts = message.payload ?? message.events ?? [];
    (async () => {
      const topSite = await getTopSiteForSenderTab(sender.tab);
      const tabId = sender.tab?.id ?? null;
      if (!topSite) return; // can't attribute to a site — skip, matches network detector behavior

      for (const draft of drafts) {
        try {
          const event = finalizeFingerprintDraft(draft, topSite, tabId);
          await appendEvent(event);
        } catch (err) {
          console.error("[PrivacyLens] failed to finalize fingerprint event", err, draft);
        }
      }
    })();
    return; // fire-and-forget; content-bridge doesn't await a response
  }

  if (message.type === MESSAGE_TYPES.TRACKING_EVENT) {
    // Legacy / immediate single-event path (not currently emitted by
    // content-bridge.js, which always batches — kept for forward
    // compatibility with ARCHITECTURE_LOCK.md's documented message shape).
    (async () => {
      const topSite = await getTopSiteForSenderTab(sender.tab);
      const tabId = sender.tab?.id ?? null;
      if (!topSite || !message.event) return;
      try {
        const event = finalizeFingerprintDraft(message.event, topSite, tabId);
        await appendEvent(event);
      } catch (err) {
        console.error("[PrivacyLens] failed to finalize fingerprint event", err, message.event);
      }
    })();
  }
});

console.log("[PrivacyLens] background worker started, network interceptor + fingerprint ingestion active");
