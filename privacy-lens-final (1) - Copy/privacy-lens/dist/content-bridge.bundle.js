(() => {
  // shared/constants.js
  var MESSAGE_SOURCES = {
    MAIN_WORLD: "PRIVACY_LENS_MAIN_WORLD",
    CONTENT_SCRIPT: "PRIVACY_LENS_CONTENT_SCRIPT",
    BACKGROUND_BUS: "PRIVACY_LENS_BACKGROUND_BUS"
  };
  var MESSAGE_TYPES = {
    TRACKING_EVENT: "PRIVACY_LENS_TRACKING_EVENT",
    BATCH_EVENTS: "PRIVACY_LENS_BATCH_EVENTS"
  };

  // content/content-bridge.js
  var buffer = [];
  var flushTimer = null;
  var BATCH_WINDOW_MS = 500;
  function bufferedSend(event) {
    if (!event || typeof event !== "object") return;
    const scriptUrl = event.source?.script || "inline";
    const apiName = event.evidence?.api || "";
    const dedupKey = `${event.subtype}:${apiName}:${scriptUrl}`;
    const existing = buffer.find((item) => item._key === dedupKey);
    if (existing) {
      existing.count = (existing.count || 1) + 1;
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
  function flushBuffer() {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    if (buffer.length === 0) return;
    const batchPayload = buffer.map(({ _key, ...eventData }) => eventData);
    buffer = [];
    try {
      if (typeof chrome !== "undefined" && chrome.runtime?.id && chrome.runtime?.sendMessage) {
        chrome.runtime.sendMessage({
          type: MESSAGE_TYPES.BATCH_EVENTS,
          payload: batchPayload,
          events: batchPayload
        }).catch(() => {
        });
      }
    } catch (err) {
    }
  }
  if (typeof window !== "undefined") {
    window.addEventListener("message", (event) => {
      if (event.source !== window) return;
      const isPrivacyLensEvent = event.data?.__privacyLens === true || event.data?.source === MESSAGE_SOURCES.MAIN_WORLD;
      if (!isPrivacyLensEvent) return;
      const rawEvent = event.data.payload || event.data.event;
      if (!rawEvent) return;
      bufferedSend(rawEvent);
    });
  }
})();
//# sourceMappingURL=content-bridge.bundle.js.map
