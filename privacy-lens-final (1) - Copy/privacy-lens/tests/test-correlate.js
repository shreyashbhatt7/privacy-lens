// tests/test-correlate.js
//
// Verifies lib/correlate.js correctly tags cross-layer beacon pairs
// (network-layer thirdparty-detector.js sighting + fingerprint-layer
// storage.js sighting of the same outbound call) without touching
// unrelated events.

import { correlateCrossLayerBeacons } from "../lib/correlate.js";

let failures = 0;
function check(label, cond) {
  if (cond) {
    console.log(` [PASS] ${label}`);
  } else {
    console.error(` [FAIL] ${label}`);
    failures++;
  }
}

console.log("=== Cross-Layer Beacon Correlation Tests ===\n");

// --- Scenario 1: genuine cross-layer pair (network + fingerprinting, same
// target, close in time) should both get flagged.
const now = Date.now();
const pair = [
  {
    id: "net_1",
    category: "network",
    subtype: "beacon",
    target: { domain: "tracker.example.com" },
    timestamp: now,
  },
  {
    id: "fp_1",
    category: "fingerprinting",
    subtype: "beacon",
    target: { domain: "tracker.example.com" },
    timestamp: now + 300,
  },
  {
    id: "unrelated_1",
    category: "fingerprinting",
    subtype: "canvas",
    target: undefined,
    timestamp: now,
  },
];

const resultPair = correlateCrossLayerBeacons(pair);
check(
  "network + fingerprinting beacon to same domain within window both confirmed",
  resultPair.find((e) => e.id === "net_1").crossLayerConfirmed === true &&
    resultPair.find((e) => e.id === "fp_1").crossLayerConfirmed === true
);
check(
  "unrelated canvas event untouched",
  resultPair.find((e) => e.id === "unrelated_1").crossLayerConfirmed === undefined
);

// --- Scenario 2: same category twice (two network sightings) should NOT
// be flagged — only cross-layer pairs count, not repeated same-layer hits.
const sameLayer = [
  { id: "n1", category: "network", subtype: "beacon", target: { domain: "x.com" }, timestamp: now },
  { id: "n2", category: "network", subtype: "third-party-load", target: { domain: "x.com" }, timestamp: now + 100 },
];
const resultSameLayer = correlateCrossLayerBeacons(sameLayer);
check(
  "two same-category events to same domain are NOT cross-layer confirmed",
  resultSameLayer.every((e) => e.crossLayerConfirmed === undefined)
);

// --- Scenario 3: different domains should NOT be flagged even if same
// category pairing would otherwise match.
const differentDomains = [
  { id: "d1", category: "network", subtype: "beacon", target: { domain: "a.com" }, timestamp: now },
  { id: "d2", category: "fingerprinting", subtype: "beacon", target: { domain: "b.com" }, timestamp: now },
];
const resultDifferentDomains = correlateCrossLayerBeacons(differentDomains);
check(
  "different target domains are NOT cross-layer confirmed",
  resultDifferentDomains.every((e) => e.crossLayerConfirmed === undefined)
);

// --- Scenario 4: same domain, cross-layer, but too far apart in time
// should NOT be flagged.
const tooFarApart = [
  { id: "t1", category: "network", subtype: "beacon", target: { domain: "slow.com" }, timestamp: now },
  { id: "t2", category: "fingerprinting", subtype: "beacon", target: { domain: "slow.com" }, timestamp: now + 10000 },
];
const resultTooFarApart = correlateCrossLayerBeacons(tooFarApart);
check(
  "cross-layer pair outside the correlation window is NOT confirmed",
  resultTooFarApart.every((e) => e.crossLayerConfirmed === undefined)
);

// --- Scenario 5: does not mutate the input array's objects.
const original = [
  { id: "m1", category: "network", subtype: "beacon", target: { domain: "mut.com" }, timestamp: now },
  { id: "m2", category: "fingerprinting", subtype: "beacon", target: { domain: "mut.com" }, timestamp: now },
];
const originalSnapshotHasFlag = "crossLayerConfirmed" in original[0];
correlateCrossLayerBeacons(original);
check("input events are not mutated", "crossLayerConfirmed" in original[0] === originalSnapshotHasFlag);

console.log(`\n${failures === 0 ? "=== All correlation tests passed! ===" : `=== ${failures} test(s) FAILED ===`}`);
process.exit(failures === 0 ? 0 : 1);
