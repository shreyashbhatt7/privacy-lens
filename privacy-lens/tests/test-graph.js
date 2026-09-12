// tests/test-graph.js
//
// Verifies buildGraphModel() in ui/graph.js correctly turns canonical
// TrackingEvents into a node/edge graph. Only tests the pure data-model
// function — layoutGraph()/renderSvg() need a DOM canvas and are exercised
// visually in the side panel instead.

import { buildGraphModel } from "../ui/graph.js";

let failures = 0;
function check(label, cond) {
  if (cond) {
    console.log(` [PASS] ${label}`);
  } else {
    console.error(` [FAIL] ${label}`);
    failures++;
  }
}

console.log("=== Tracker Graph Model Tests ===\n");

const events = [
  {
    category: "fingerprinting",
    subtype: "canvas",
    severity: "medium",
    source: { script: "https://ads.example/tracker.js" },
    target: undefined,
  },
  {
    category: "fingerprinting",
    subtype: "beacon",
    severity: "high",
    source: { script: "https://ads.example/tracker.js" },
    target: { domain: "collector.example.net" },
  },
  {
    category: "network",
    subtype: "cname-cloaking",
    severity: "high",
    source: { requestHostname: "metrics.thesite.com" },
    target: { domain: "adnetwork.net" },
  },
];

const { nodes, edges } = buildGraphModel(events, "thesite.com");

check("has one site node", nodes.filter((n) => n.type === "site").length === 1);
check("has two distinct source nodes", nodes.filter((n) => n.type === "source").length === 2);
check("has two distinct target nodes", nodes.filter((n) => n.type === "target").length === 2);

const trackerScriptNode = nodes.find((n) => n.id === "src:https://ads.example/tracker.js");
check("tracker.js source node exists", !!trackerScriptNode);
check("tracker.js source node severity escalates to the worst event touching it (high)", trackerScriptNode?.severity === "high");
check("tracker.js source node count reflects 2 events", trackerScriptNode?.count === 2);

const siteId = "site:thesite.com";
check("site -> source edges exist for both distinct sources", edges.filter((e) => e.from === siteId).length === 2);
check(
  "source -> target edge exists for the beacon event",
  edges.some((e) => e.from === "src:https://ads.example/tracker.js" && e.to === "tgt:collector.example.net")
);
check("no duplicate edges for repeated site->source pairs", edges.length === new Set(edges.map((e) => `${e.from}->${e.to}`)).size);

// Event with no target (pure canvas read) should NOT create a target node
// or a source->target edge — only site->source.
const canvasOnly = [{ category: "fingerprinting", subtype: "canvas", severity: "low", source: { script: "inline" }, target: undefined }];
const canvasOnlyModel = buildGraphModel(canvasOnly, "site.com");
check("event with no target creates no target node", canvasOnlyModel.nodes.filter((n) => n.type === "target").length === 0);

console.log(`\n${failures === 0 ? "=== All graph model tests passed! ===" : `=== ${failures} test(s) FAILED ===`}`);
process.exit(failures === 0 ? 0 : 1);
