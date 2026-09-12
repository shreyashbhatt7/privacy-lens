// tests/test-event-display.js
//
// Verifies ui/event-display.js correctly maps canonical TrackingEvents
// (as produced by background.js's finalizeFingerprintDraft() and by
// Person 1's network detectors directly) into the display shape Person 3's
// sidepanel UI renders.

import { typeLabelFor, domainFor, severityUpper, toDisplayEvent } from "../ui/event-display.js";

let failures = 0;
function check(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  console.log(`${ok ? "[PASS]" : "[FAIL]"} ${name}` + (ok ? "" : ` — got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`));
  if (!ok) failures += 1;
}

// A network-layer event (Person 1) — has target.domain (the tracker), site is the page.
const etagEvent = {
  id: "evt_1",
  timestamp: 1000,
  tabId: 5,
  site: "news-site.com",
  category: "identifier",
  subtype: "etag",
  source: { requestDomain: "cdn.tracker.net" },
  target: { domain: "tracker.net" },
  evidence: { api: "ETag header", valueHash: "abc", timesSeen: 3, distinctSitesSeenOn: 2 },
  severity: "high",
  confidence: 0.82,
};

// A pure fingerprint read (Person 2, finalized) — no target, only site.
const canvasEvent = {
  id: "evt_2",
  timestamp: 2000,
  tabId: 5,
  site: "news-site.com",
  category: "fingerprinting",
  subtype: "canvas",
  source: { script: "https://cdn.example.com/tracker.js" },
  target: {},
  evidence: { api: "HTMLCanvasElement.toDataURL", format: "image/png" },
  severity: "low",
  confidence: 0.0,
};

// A fingerprint beacon call (Person 2, finalized) — has target.domain.
const fpBeaconEvent = {
  ...canvasEvent,
  id: "evt_3",
  subtype: "beacon",
  target: { domain: "telemetry.example.com" },
  evidence: { api: "fetch", url: "https://telemetry.example.com/collect" },
};

// An unrecognized future category/subtype — should fall back gracefully.
const unknownEvent = { category: "storage", subtype: "mystery-vector", site: "x.com", severity: "medium", timestamp: 3000 };

check("etag label", typeLabelFor(etagEvent), "ETAG TRACKING");
check("etag domain prefers target", domainFor(etagEvent), "tracker.net");
check("etag severity uppercased", severityUpper(etagEvent), "HIGH");

check("canvas label", typeLabelFor(canvasEvent), "CANVAS FINGERPRINT");
check("canvas domain falls back to site (no target)", domainFor(canvasEvent), "news-site.com");
check("canvas severity uppercased", severityUpper(canvasEvent), "LOW");

check("fingerprint beacon label", typeLabelFor(fpBeaconEvent), "SCRIPT NETWORK CALL");
check("fingerprint beacon domain prefers target", domainFor(fpBeaconEvent), "telemetry.example.com");

check("unknown category/subtype falls back to generated label", typeLabelFor(unknownEvent), "STORAGE · MYSTERY-VECTOR");
check("unknown event domain falls back to site", domainFor(unknownEvent), "x.com");

const display = toDisplayEvent(etagEvent);
check("toDisplayEvent keeps raw event for export", display.raw, etagEvent);
check("toDisplayEvent type", display.type, "ETAG TRACKING");
check("toDisplayEvent domain", display.domain, "tracker.net");
check("toDisplayEvent severity", display.severity, "HIGH");

console.log(failures === 0 ? "\n[PASS] all event-display checks passed" : `\n[FAIL] ${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
