// ==========================================
// TrackerGuard / Privacy Lens - Side Panel
// Owner: Person 3 (Side Panel UI)
//
// Wired to the real pipeline at hour 18-24 integration:
//  - Events are canonical TrackingEvents (docs/EVENT_SCHEMA_REFERENCE.md),
//    not the {type, domain, severity: "HIGH"} mock shape this file
//    originally used. ui/event-display.js adapts between the two.
//  - Events are persisted by lib/store.js to chrome.storage.session, so
//    they survive the panel being closed/reopened (and a service worker
//    restart) — this file now loads that history on open instead of
//    starting from an empty in-memory array.
//  - Live updates arrive via the "pl_new_event" message lib/store.js's
//    appendEvent() sends after every write (not the old ad-hoc
//    "NEW_TRACKING_EVENT" / TRACKING_EVENT message pair from the
//    standalone prototype's background.js, which is no longer used).
//  - The previously-static "Per-Site Analysis" section is now populated
//    from real per-site event counts.
// ==========================================

import { getAllEvents, clearEvents } from "../lib/store.js";
import { toDisplayEvent } from "./event-display.js";
import { correlateCrossLayerBeacons } from "../lib/correlate.js";
import { renderTrackerGraph } from "./graph.js";
import { getRegistrableDomain } from "../network/tracker-list.js";
import { calculatePrivacyScore } from "../detection/scoring.js";

let events = []; // canonical TrackingEvent objects, oldest first
let currentFilter = "ALL"; // severity filter
let currentCategoryFilter = "ALL"; // category filter
let demoMode = false;
let activeTabId = null; // the tab this panel is currently showing (see chrome.tabs.query below)

// NOTE: there used to be a client-side time-window filter here
// (recentEventsForSite) to stop the privacy score from accumulating
// forever across a whole browser session. That's no longer needed:
// background.js now calls clearEventsForTab()/confidenceEngine.resetForTab()
// on every fresh top-level navigation (chrome.webNavigation.onBeforeNavigate),
// so pl_events in storage only ever holds each open tab's CURRENT page load.
// The main/export score is scoped to activeTabId below to match that
// per-tab design — two tabs on the same site score independently.

// Sites tracker-lab's test pages resolve to (see getTopSiteForTab /
// getTopSiteForSenderTab fix in background.js + network/interceptor.js):
// file:// pages (tier1-test.html) get the synthetic "local-file" site,
// and cache-token.html is served from http://localhost:5051.
const TRACKER_LAB_SITES = new Set(["local-file", "localhost"]);

const feed = document.getElementById("feed");
const totalEventsEl = document.getElementById("totalEvents");
const highEventsEl = document.getElementById("highEvents");
const mediumEventsEl = document.getElementById("mediumEvents");
const trackerScoreEl = document.getElementById("trackerScore");
const privacyScoreEl = document.getElementById("privacyScore");
const privacyGradeBadgeEl = document.getElementById("privacyGradeBadge");
const privacyRatingEl = document.getElementById("privacyRating");
const siteNameEl = document.getElementById("siteName");
const siteAnalysisEl = document.getElementById("siteAnalysis");
const trackerGraphEl = document.getElementById("trackerGraph");
let activeSite = null;

function formatTime(timestamp) {
  if (!timestamp) return "";
  return new Date(timestamp).toLocaleTimeString();
}

function renderFeed() {
  feed.innerHTML = "";

  // Tag any network-layer + fingerprint-layer sightings of the same
  // outbound call as cross-layer confirmed before mapping to display —
  // this is presented as stronger evidence, not deduped/hidden.
  const correlated = correlateCrossLayerBeacons(events);
  const display = correlated.map(toDisplayEvent);
  const filtered = display.filter((e) => {
    const severityMatch = currentFilter === "ALL" || e.severity === currentFilter;
    const categoryMatch = currentCategoryFilter === "ALL" || e.raw.category === currentCategoryFilter;
    return severityMatch && categoryMatch;
  });

  if (filtered.length === 0) {
    feed.innerHTML = `<div class="empty">No tracking activity detected.</div>`;
    return;
  }

  filtered
    .slice()
    .reverse() // newest first
    .forEach((e) => {
      const card = document.createElement("div");
      const isDemoSite = demoMode && TRACKER_LAB_SITES.has(e.site);
      card.className = `event ${e.severity.toLowerCase()}${isDemoSite ? " demo-flagged" : ""}`;

      const confidencePct = e.confidence != null ? Math.round(e.confidence * 100) : null;
      const vectorsHtml = e.correlatedVectors?.length
        ? `<div class="event-vectors">Vectors: ${e.correlatedVectors.join(" + ")}</div>`
        : "";
      const crossLayerBadge = e.crossLayerConfirmed
        ? `<span class="badge-cross-layer" title="Detected independently at both the network layer and the JavaScript layer">✓ 2-layer confirmed</span>`
        : "";

      card.innerHTML = `
        <div class="event-top">
          <span class="event-type">${e.type}</span>
          <span class="event-time">${formatTime(e.timestamp)}</span>
        </div>
        <div class="event-domain">${e.domain} ${crossLayerBadge}</div>
        ${confidencePct != null ? `<div class="event-confidence">${confidencePct}% confidence</div>` : ""}
        <div class="event-why" hidden>
          ${e.evidenceSummary ? `<div class="event-summary">${e.evidenceSummary}</div>` : ""}
          ${vectorsHtml}
        </div>
      `;

      // Click to expand/collapse the "why we flagged this" detail — collapsed
      // by default so the feed stays scannable; only shown if there's
      // something to say (a summary or correlated vectors).
      const why = card.querySelector(".event-why");
      if (e.evidenceSummary || vectorsHtml) {
        card.classList.add("expandable");
        card.addEventListener("click", () => {
          why.hidden = !why.hidden;
        });
      }

      feed.appendChild(card);
    });
}

function renderSiteAnalysis() {
  const bySite = new Map(); // site -> { total, high, medium, low, events: [] }

  for (const event of events) {
    const site = event.site || "Unknown site";
    const bucket = bySite.get(site) ?? { total: 0, high: 0, medium: 0, low: 0, events: [] };
    bucket.total += 1;
    bucket.events.push(event);
    const sev = (event.severity ?? "low").toLowerCase();
    if (sev === "high" || sev === "medium" || sev === "low") bucket[sev] += 1;
    bySite.set(site, bucket);
  }

  if (bySite.size === 0) {
    siteAnalysisEl.innerHTML = `<div class="empty">No sites detected yet.</div>`;
    return;
  }

  siteAnalysisEl.innerHTML = "";
  // Busiest sites first.
  [...bySite.entries()]
    .sort((a, b) => b[1].total - a[1].total)
    .forEach(([site, data]) => {
      const siteScore = calculatePrivacyScore(events.filter((e) => e.site === site));
      const row = document.createElement("div");
      row.className = "event"; // reuse the feed card styling for a consistent look
      row.innerHTML = `
        <div class="event-top">
          <span class="event-type">${site}</span>
          <span class="event-score-pill" style="background: ${siteScore.color}22; color: ${siteScore.color}; border: 1px solid ${siteScore.color}55;">
            Score ${siteScore.score} · Grade ${siteScore.grade}
          </span>
        </div>
        <div class="event-domain">${data.high} high · ${data.medium} medium · ${data.low} low · ${data.total} event${data.total === 1 ? "" : "s"}</div>
      `;
      siteAnalysisEl.appendChild(row);
    });
}

function updateDashboard() {
  totalEventsEl.textContent = events.length;

  const high = events.filter((e) => (e.severity ?? "low").toLowerCase() === "high").length;
  const medium = events.filter((e) => (e.severity ?? "low").toLowerCase() === "medium").length;
  highEventsEl.textContent = high;
  mediumEventsEl.textContent = medium;

  // Tracker count = number of distinct detection methods seen (category:subtype pairs),
  // not raw event count — a tracker calling toDataURL() 50 times is one method, not 50.
  const methods = new Set(events.map((e) => `${e.category}:${e.subtype}`));
  trackerScoreEl.textContent = methods.size;

  // Calculate holistic site Privacy Score (0-100 and A-F letter grade).
  // Scoped to THIS TAB specifically (not just the site name), matching the
  // per-tab reset in background.js — two tabs open on the same site score
  // independently, each reflecting only its own current page load.
  const tabEvents = activeTabId != null ? events.filter((e) => e.tabId === activeTabId) : events;
  const privacyResult = calculatePrivacyScore(tabEvents);

  if (privacyScoreEl) {
    privacyScoreEl.textContent = privacyResult.score;
    privacyScoreEl.style.color = privacyResult.color;
  }
  if (privacyGradeBadgeEl) {
    privacyGradeBadgeEl.textContent = privacyResult.grade;
    privacyGradeBadgeEl.className = `grade-badge grade-${privacyResult.grade.toLowerCase()}`;
  }
  if (privacyRatingEl) {
    privacyRatingEl.textContent = `Grade ${privacyResult.grade} · ${privacyResult.rating}`;
  }
}

function renderAll() {
  updateDashboard();
  renderFeed();
  renderSiteAnalysis();
  renderTrackerGraph(trackerGraphEl, events, activeSite);
}

// --- Load persisted history on open, then listen for live updates ---

async function init() {
  events = await getAllEvents();
  renderAll();
}

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "pl_new_event" && message.event) {
    events.push(message.event);
    renderAll();
  }
});

// The side panel persists across navigations, but its in-memory `events`
// array doesn't automatically know when background.js clears a tab's
// history on navigation (chrome.webNavigation.onBeforeNavigate). Without
// this, the panel would keep showing the PREVIOUS page's events for the
// active tab until the panel itself was closed and reopened. Re-sync from
// storage whenever the active tab starts a fresh navigation.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (tabId !== activeTabId) return;
  if (changeInfo.status !== "loading") return;
  getAllEvents().then((fresh) => {
    events = fresh;
    renderAll();
  });
});

// If the user switches to a different tab, re-resolve activeSite/activeTabId
// and refresh from storage so the panel reflects whichever tab is now active.
chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (!tab) return;
    activeTabId = tab.id ?? null;
    try {
      const hostname = new URL(tab.url).hostname;
      activeSite = getRegistrableDomain(hostname) || hostname;
      siteNameEl.textContent = activeSite || "Unknown";
    } catch {
      siteNameEl.textContent = "Unknown";
    }
    getAllEvents().then((fresh) => {
      events = fresh;
      renderAll();
    });
  });
});

init();

// --- Filter buttons ---

document.querySelectorAll(".filter").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".filter").forEach((btn) => btn.classList.remove("active"));
    button.classList.add("active");
    currentFilter = button.dataset.filter;
    renderFeed();
  });
});

// --- Category filter buttons (independent of the severity filter above —
// both are applied together in renderFeed) ---

document.querySelectorAll(".category-filter").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".category-filter").forEach((btn) => btn.classList.remove("active"));
    button.classList.add("active");
    currentCategoryFilter = button.dataset.category;
    renderFeed();
  });
});

// --- Demo Mode: outlines events from tracker-lab test pages so they're
// visually unambiguous during judging, without altering real-site behavior
// when off. ---

document.getElementById("demoModeToggle").addEventListener("change", (evt) => {
  demoMode = evt.target.checked;
  renderFeed();
});

// --- Clear button: clears persisted storage, not just this view ---

document.getElementById("clearBtn").addEventListener("click", async () => {
  await clearEvents();
  events = [];
  renderAll();
});

// --- Detect current site (for the header card AND the tracker graph, which
// is scoped to the active site — the feed intentionally still shows
// activity across all sites). Uses the same eTLD+1 registrable-domain
// logic the detectors use for event.site, so "www.example.com" in the
// active tab correctly matches events recorded against "example.com". ---

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (!tabs || !tabs[0]) {
    siteNameEl.textContent = "Unknown";
    return;
  }
  activeTabId = tabs[0].id ?? null;
  try {
    const hostname = new URL(tabs[0].url).hostname;
    activeSite = getRegistrableDomain(hostname) || hostname;
    siteNameEl.textContent = activeSite || "Unknown";
    renderAll();
  } catch {
    siteNameEl.textContent = "Unknown";
  }
});

// --- Export JSON: full canonical events, not just the display projection,
// including holistic privacy scores, so the report is comprehensive evidence ---

document.getElementById("jsonBtn").addEventListener("click", () => {
  const tabEvents = activeTabId != null ? events.filter((e) => e.tabId === activeTabId) : events;
  const currentSiteScore = calculatePrivacyScore(tabEvents);
  const globalScore = calculatePrivacyScore(events);

  const report = {
    generatedAt: new Date().toISOString(),
    currentSite: siteNameEl.textContent,
    privacyScore: currentSiteScore,
    globalPrivacyScore: globalScore,
    trackerScore: Number(trackerScoreEl.textContent),
    totalEvents: events.length,
    events,
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "tracker-report.json";
  a.click();
  URL.revokeObjectURL(url);
});

// PDF export intentionally cut per team's non-negotiable scope decision
// (docs — see PDF: "cut PDF export from MVP, it's not worth the hours").
