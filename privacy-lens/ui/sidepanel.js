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

let events = []; // canonical TrackingEvent objects, oldest first
let currentFilter = "ALL";

const feed = document.getElementById("feed");
const totalEventsEl = document.getElementById("totalEvents");
const highEventsEl = document.getElementById("highEvents");
const mediumEventsEl = document.getElementById("mediumEvents");
const trackerScoreEl = document.getElementById("trackerScore");
const siteNameEl = document.getElementById("siteName");
const siteAnalysisEl = document.getElementById("siteAnalysis");

function formatTime(timestamp) {
  if (!timestamp) return "";
  return new Date(timestamp).toLocaleTimeString();
}

function renderFeed() {
  feed.innerHTML = "";

  const display = events.map(toDisplayEvent);
  const filtered = display.filter((e) => currentFilter === "ALL" || e.severity === currentFilter);

  if (filtered.length === 0) {
    feed.innerHTML = `<div class="empty">No tracking activity detected.</div>`;
    return;
  }

  filtered
    .slice()
    .reverse() // newest first
    .forEach((e) => {
      const card = document.createElement("div");
      card.className = `event ${e.severity.toLowerCase()}`;
      card.innerHTML = `
        <div class="event-top">
          <span class="event-type">${e.type}</span>
          <span class="event-time">${formatTime(e.timestamp)}</span>
        </div>
        <div class="event-domain">${e.domain}</div>
      `;
      feed.appendChild(card);
    });
}

function renderSiteAnalysis() {
  const bySite = new Map(); // site -> { total, high, medium, low }

  for (const event of events) {
    const site = event.site || "Unknown site";
    const bucket = bySite.get(site) ?? { total: 0, high: 0, medium: 0, low: 0 };
    bucket.total += 1;
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
    .forEach(([site, counts]) => {
      const row = document.createElement("div");
      row.className = "event"; // reuse the feed card styling for a consistent look
      row.innerHTML = `
        <div class="event-top">
          <span class="event-type">${site}</span>
          <span class="event-time">${counts.total} event${counts.total === 1 ? "" : "s"}</span>
        </div>
        <div class="event-domain">${counts.high} high · ${counts.medium} medium · ${counts.low} low</div>
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

  // Tracker score = number of distinct detection methods seen (category:subtype pairs),
  // not raw event count — a tracker calling toDataURL() 50 times is one method, not 50.
  const methods = new Set(events.map((e) => `${e.category}:${e.subtype}`));
  trackerScoreEl.textContent = methods.size;
}

function renderAll() {
  updateDashboard();
  renderFeed();
  renderSiteAnalysis();
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

// --- Clear button: clears persisted storage, not just this view ---

document.getElementById("clearBtn").addEventListener("click", async () => {
  await clearEvents();
  events = [];
  renderAll();
});

// --- Detect current site (for the header card only — the feed intentionally
// shows activity across all sites, not just the active tab) ---

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (!tabs || !tabs[0]) {
    siteNameEl.textContent = "Unknown";
    return;
  }
  try {
    siteNameEl.textContent = new URL(tabs[0].url).hostname || "Unknown";
  } catch {
    siteNameEl.textContent = "Unknown";
  }
});

// --- Export JSON: full canonical events, not just the display projection,
// so the report is useful evidence rather than just UI labels ---

document.getElementById("jsonBtn").addEventListener("click", () => {
  const report = {
    generatedAt: new Date().toISOString(),
    currentSite: siteNameEl.textContent,
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

// --- PDF export: not yet implemented ---

document.getElementById("pdfBtn").addEventListener("click", () => {
  alert("PDF export will be added in the next step.");
});
