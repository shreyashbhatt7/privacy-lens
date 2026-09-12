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
import { createTrackingEvent } from "./shared/events.js";
import { MESSAGE_TYPES } from "./shared/constants.js";
import { appendEvent } from "./lib/store.js";

initInterceptor();

chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true }).catch(() => {});

/**
 * Turns one fingerprint draft (from createFingerprintDraft() in
 * shared/events.js, batched by content-bridge.js) into a canonical
 * TrackingEvent. Fills in tabId/site from the message sender (only known
 * here, in the background — the page context that produced the draft has
 * neither) and flattens evidence.details into evidence, per the
 * Option B decision recorded in docs/EVENT_SCHEMA_REFERENCE.md.
 */
function finalizeFingerprintDraft(draft, topSite, tabId) {
  const { api, details } = draft.evidence ?? {};
  const { count, _key, ...rest } = draft; // strip content-bridge's dedup bookkeeping

  return createTrackingEvent({
    tabId,
    site: topSite,
    category: rest.category ?? "fingerprinting",
    subtype: rest.subtype,
    source: rest.source,
    target: rest.target,
    evidence: {
      api,
      ...(details ?? {}),
      ...(count && count > 1 ? { count } : {}),
    },
    severity: rest.severity ?? "low",
    confidence: rest.confidence ?? 0.0,
  });
}

async function getTopSiteForSenderTab(tab) {
  try {
    if (!tab?.url) return null;
    return getRegistrableDomain(new URL(tab.url).hostname);
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
