// ui/plain-language.js
//
// Simple Mode's translation layer. Takes the same canonical TrackingEvents
// and calculatePrivacyScore() output Advanced Mode already uses — no new
// detection logic, no new numbers — and renders them as a 3-state traffic
// light plus a short list of plain-English findings, with no confidence
// percentages, category jargon, or letter grades.
//
// Deliberately rule-based (not an LLM call): deterministic, free, and
// works offline for a demo. A later pass can swap buildSummarySentence()
// for an API call without touching anything else in this file.

/**
 * 3-state banding over the existing 0-100 privacy score. Thresholds are
 * intentionally coarser than the A-F grade — Simple Mode's whole point is
 * to not make small score movements feel alarming.
 */
export function trafficLevelForScore(score) {
  if (score >= 80) {
    return { level: "typical", label: "Typical for a website", color: "#22c55e" };
  }
  if (score >= 55) {
    return { level: "elevated", label: "More tracking than usual", color: "#eab308" };
  }
  return { level: "high", label: "Much more tracking than usual", color: "#ef4444" };
}

// One plain phrase per category:subtype — same key space as
// event-display.js's TYPE_LABELS, but written for a non-technical reader
// and parameterized on the domain instead of exposing the raw API name.
const PLAIN_PHRASES = {
  "identifier:etag": (d) => `A hidden tracking code keeps identifying you to ${d}, even across visits.`,
  "identifier:cache-token": (d) => `${d} is using your browser's cache to remember who you are.`,
  "network:cname-cloaking": (d) => `A part of this site that looks first-party is secretly run by ${d}.`,
  "network:beacon": (d) => `This page quietly sent data to ${d}.`,
  "network:third-party-load": (d) => `This page loaded a script from ${d}.`,
  "fingerprinting:canvas": () => `This site took a "fingerprint" of your device using how it draws graphics.`,
  "fingerprinting:webgl": () => `This site checked details about your device's graphics hardware to help identify it.`,
  "fingerprinting:audio": () => `This site fingerprinted your device using how it processes audio.`,
  "fingerprinting:font": () => `This site checked which fonts you have installed, which can help identify your device.`,
  "fingerprinting:storage": () => `This site is storing an identifier in your browser to recognize you later.`,
  "fingerprinting:beacon": (d) => `A script on this page sent information about your device to ${d}.`,
};

function plainPhraseFor(displayEvent) {
  const key = `${displayEvent.raw.category}:${displayEvent.raw.subtype}`;
  const fn = PLAIN_PHRASES[key];
  if (fn) return fn(displayEvent.domain);
  return `This site used a tracking technique (${displayEvent.raw.category}) involving ${displayEvent.domain}.`;
}

/**
 * Up to `max` plain-English findings, most-confident-first, deduped by
 * category:subtype so a canvas fingerprint firing 30 times shows up once,
 * not thirty times. This intentionally mirrors updateDashboard()'s
 * "distinct methods, not raw event count" philosophy in sidepanel.js.
 */
export function topPlainFindings(displayEvents, max = 3) {
  const bestPerMethod = new Map(); // "category:subtype" -> best display event

  for (const e of displayEvents) {
    const key = `${e.raw.category}:${e.raw.subtype}`;
    const existing = bestPerMethod.get(key);
    const conf = e.confidence ?? 0;
    if (!existing || conf > (existing.confidence ?? 0)) {
      bestPerMethod.set(key, e);
    }
  }

  return [...bestPerMethod.values()]
    .sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0))
    .slice(0, max)
    .map(plainPhraseFor);
}

/**
 * One-line overall summary. Deliberately avoids numbers entirely — the
 * traffic light already carries the "how bad" signal, this sentence just
 * says what kind of thing is happening.
 */
export function buildSummarySentence(displayEvents, trafficLevel) {
  if (displayEvents.length === 0) {
    return "No tracking activity has been detected on this site yet.";
  }

  const categories = new Set(displayEvents.map((e) => e.raw.category));
  const distinctTargets = new Set(
    displayEvents.map((e) => e.raw.target?.domain).filter(Boolean)
  );

  const doesFingerprinting = categories.has("fingerprinting");
  const sendsDataOut = distinctTargets.size > 0;

  if (trafficLevel.level === "typical") {
    return "This site's tracking activity looks in line with most ordinary websites.";
  }

  if (doesFingerprinting && sendsDataOut) {
    return `This site tries to identify your specific device and shares that with ${distinctTargets.size} outside ${
      distinctTargets.size === 1 ? "company" : "companies"
    }.`;
  }
  if (doesFingerprinting) {
    return "This site uses several techniques to try to identify your specific device.";
  }
  if (sendsDataOut) {
    return `This site shares data with ${distinctTargets.size} outside ${
      distinctTargets.size === 1 ? "company" : "companies"
    }.`;
  }
  return "This site is doing more tracking than a typical website.";
}
