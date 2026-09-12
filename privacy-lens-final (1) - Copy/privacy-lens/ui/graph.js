// ui/graph.js
//
// "Tracker graph" (PDF: site -> script -> fingerprint/third-party domain ->
// data transmission). Deliberately dependency-free: sidepanel.html is a
// normal extension page (not a content script), so it CAN use a bundler or
// pull in a graph library — but adding one this late in the build is a new
// failure surface for a feature that's genuinely optional next to the live
// feed + evidence chain. This is a small hand-rolled force layout instead:
// plain SVG, no build step, no new dependency, same visual idea (a center
// node radiating out to scripts/domains, radiating further to third-party
// targets).
//
// If there's time left after everything else, swapping this for a real D3
// force simulation is a drop-in visual upgrade — the node/edge data model
// below (buildGraphModel) is what you'd feed to d3-force too.

const WIDTH = 340;
const HEIGHT = 320;
const ITERATIONS = 120;

/**
 * Pulls a stable "source" identity out of an event regardless of category —
 * network detectors and fingerprint hooks use different key names for
 * "who did this" (see docs/EVENT_SCHEMA_REFERENCE.md).
 */
function sourceKeyFor(event) {
  const s = event.source || {};
  return s.script || s.requestDomain || s.requestHostname || s.url || "unknown script";
}

/**
 * Builds a { nodes, edges } graph model from canonical TrackingEvents for
 * ONE site: site (root) -> source (script/domain that acted) -> target
 * (third-party domain, when present). Severity of the worst event touching
 * a node determines its color.
 */
export function buildGraphModel(events, site) {
  const nodesById = new Map();
  const edgeKeys = new Set();
  const edges = [];

  const severityRank = { low: 1, medium: 2, high: 3 };
  function upsertNode(id, type, label) {
    const existing = nodesById.get(id);
    if (existing) return existing;
    const node = { id, type, label, severity: "low", count: 0 };
    nodesById.set(id, node);
    return node;
  }
  function bumpSeverity(node, severity) {
    node.count += 1;
    if ((severityRank[severity] || 1) > (severityRank[node.severity] || 1)) {
      node.severity = severity;
    }
  }
  function addEdge(fromId, toId) {
    const key = `${fromId}->${toId}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push({ from: fromId, to: toId });
  }

  const siteId = `site:${site || "this site"}`;
  const siteNode = upsertNode(siteId, "site", site || "this site");

  for (const event of events) {
    const srcKey = sourceKeyFor(event);
    const srcId = `src:${srcKey}`;
    const srcNode = upsertNode(srcId, "source", srcKey.length > 28 ? srcKey.slice(0, 25) + "…" : srcKey);
    bumpSeverity(srcNode, event.severity || "low");
    addEdge(siteId, srcId);

    const targetDomain = event.target?.domain;
    if (targetDomain) {
      const tgtId = `tgt:${targetDomain}`;
      const tgtNode = upsertNode(tgtId, "target", targetDomain);
      bumpSeverity(tgtNode, event.severity || "low");
      addEdge(srcId, tgtId);
    }
  }

  bumpSeverity(siteNode, "low"); // keep the root neutral regardless of children

  return { nodes: [...nodesById.values()], edges };
}

/**
 * Tiny force layout: repulsion between all node pairs, spring attraction
 * along edges, mild centering pull. The site node is pinned at the canvas
 * center. Runs synchronously for a fixed number of iterations — fine at
 * hackathon-demo scale (a few dozen nodes), not meant to scale further.
 */
function layoutGraph(nodes, edges) {
  const cx = WIDTH / 2;
  const cy = HEIGHT / 2;

  for (const node of nodes) {
    if (node.type === "site") {
      node.x = cx;
      node.y = cy;
    } else {
      const angle = Math.random() * Math.PI * 2;
      const radius = 40 + Math.random() * 80;
      node.x = cx + Math.cos(angle) * radius;
      node.y = cy + Math.sin(angle) * radius;
    }
  }

  const REPULSION = 1400;
  const SPRING_LENGTH = 90;
  const SPRING_STRENGTH = 0.02;
  const CENTER_PULL = 0.01;

  for (let iter = 0; iter < ITERATIONS; iter++) {
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      if (a.type === "site") continue; // pinned

      let fx = 0;
      let fy = 0;

      // Repel from every other node.
      for (let j = 0; j < nodes.length; j++) {
        if (i === j) continue;
        const b = nodes[j];
        const dx = a.x - b.x;
        const dy = a.y - b.y;
        const distSq = Math.max(dx * dx + dy * dy, 1);
        const force = REPULSION / distSq;
        const dist = Math.sqrt(distSq);
        fx += (dx / dist) * force;
        fy += (dy / dist) * force;
      }

      // Mild pull toward center so isolated nodes don't drift off-canvas.
      fx += (cx - a.x) * CENTER_PULL;
      fy += (cy - a.y) * CENTER_PULL;

      a.x += fx * 0.02;
      a.y += fy * 0.02;
    }

    // Spring attraction along edges (after repulsion, so edges pull
    // connected nodes back together against the repulsion above).
    for (const edge of edges) {
      const a = nodes.find((n) => n.id === edge.from);
      const b = nodes.find((n) => n.id === edge.to);
      if (!a || !b) continue;

      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const displacement = (dist - SPRING_LENGTH) * SPRING_STRENGTH;
      const ox = (dx / dist) * displacement;
      const oy = (dy / dist) * displacement;

      if (a.type !== "site") {
        a.x += ox;
        a.y += oy;
      }
      if (b.type !== "site") {
        b.x -= ox;
        b.y -= oy;
      }
    }

    // Keep everything inside the canvas with a small margin.
    for (const node of nodes) {
      node.x = Math.min(WIDTH - 20, Math.max(20, node.x));
      node.y = Math.min(HEIGHT - 20, Math.max(20, node.y));
    }
  }
}

const SEVERITY_COLOR = { low: "#eab308", medium: "#f97316", high: "#ef4444" };
const NODE_FILL = { site: "#3b82f6", source: null /* uses severity color */, target: "#ef4444" };

function nodeRadius(node) {
  if (node.type === "site") return 16;
  const base = node.type === "target" ? 9 : 7;
  return base + Math.min(6, Math.log2((node.count || 1) + 1) * 2);
}

function nodeColor(node) {
  if (node.type === "site") return NODE_FILL.site;
  if (node.type === "target") return NODE_FILL.target;
  return SEVERITY_COLOR[node.severity] || SEVERITY_COLOR.low;
}

function escapeXml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderSvg(nodes, edges) {
  const edgeLines = edges
    .map((edge) => {
      const a = nodes.find((n) => n.id === edge.from);
      const b = nodes.find((n) => n.id === edge.to);
      if (!a || !b) return "";
      return `<line x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" stroke="#334155" stroke-width="1.5" />`;
    })
    .join("");

  const nodeShapes = nodes
    .map((node) => {
      const r = nodeRadius(node);
      const color = nodeColor(node);
      const label = escapeXml(node.label);
      return `
        <g>
          <circle cx="${node.x.toFixed(1)}" cy="${node.y.toFixed(1)}" r="${r}" fill="${color}" fill-opacity="0.85" stroke="#0f172a" stroke-width="1.5">
            <title>${label}${node.type !== "site" ? ` (${node.count} event${node.count === 1 ? "" : "s"}, ${node.severity})` : ""}</title>
          </circle>
          <text x="${node.x.toFixed(1)}" y="${(node.y + r + 10).toFixed(1)}" text-anchor="middle" font-size="8" fill="#94a3b8">${
            label.length > 14 ? label.slice(0, 12) + "…" : label
          }</text>
        </g>`;
    })
    .join("");

  return `<svg viewBox="0 0 ${WIDTH} ${HEIGHT}" width="100%" height="${HEIGHT}" xmlns="http://www.w3.org/2000/svg">
    ${edgeLines}
    ${nodeShapes}
  </svg>`;
}

/**
 * Renders the tracker graph for `site` into `container` (a DOM element).
 * Call this from sidepanel.js's renderAll() alongside the feed/dashboard.
 *
 * @param {HTMLElement} container
 * @param {Array<Object>} events - canonical TrackingEvents (any site; this
 *   function filters to `site` internally so callers can pass the full list)
 * @param {string} site - top-level site to graph (usually the active tab's site)
 */
export function renderTrackerGraph(container, events, site) {
  const siteEvents = site ? events.filter((e) => e.site === site) : events;

  if (siteEvents.length === 0) {
    container.innerHTML = `<div class="empty">No activity to graph for this site yet.</div>`;
    return;
  }

  const { nodes, edges } = buildGraphModel(siteEvents, site);
  layoutGraph(nodes, edges);
  container.innerHTML = renderSvg(nodes, edges);
}
