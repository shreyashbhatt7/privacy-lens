// panel/panel.js — throwaway debug view. Replace with the real
// Live Feed / Graph / Score UI (Person 3).

const EVENTS_KEY = "pl_events";

let allEvents = [];

function populateSubtypeOptions() {
  const select = document.getElementById("subtypeFilter");
  const current = select.value;
  const subtypes = [...new Set(allEvents.map((e) => e.subtype))].sort();
  select.innerHTML = '<option value="">All subtypes</option>' +
    subtypes.map((s) => `<option value="${s}">${s}</option>`).join("");
  select.value = subtypes.includes(current) ? current : "";
}

function applyFiltersAndRender() {
  const category = document.getElementById("categoryFilter").value;
  const subtype = document.getElementById("subtypeFilter").value;

  const filtered = allEvents
    .filter((e) => !category || e.category === category)
    .filter((e) => !subtype || e.subtype === subtype)
    .sort((a, b) => b.timestamp - a.timestamp); // newest first

  document.getElementById("summary").textContent =
    `${filtered.length} of ${allEvents.length} total events shown` +
    (category || subtype ? ` (filtered)` : "");

  document.getElementById("events").textContent = JSON.stringify(filtered.slice(0, 100), null, 2);
}

async function loadAndRender() {
  const { [EVENTS_KEY]: events = [] } = await chrome.storage.session.get(EVENTS_KEY);
  allEvents = events;
  populateSubtypeOptions();
  applyFiltersAndRender();
}

document.getElementById("categoryFilter").addEventListener("change", applyFiltersAndRender);
document.getElementById("subtypeFilter").addEventListener("change", applyFiltersAndRender);
document.getElementById("refreshBtn").addEventListener("click", loadAndRender);
document.getElementById("clearBtn").addEventListener("click", async () => {
  await chrome.storage.session.remove(EVENTS_KEY);
  loadAndRender();
});

loadAndRender();
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "pl_new_event") loadAndRender();
});
