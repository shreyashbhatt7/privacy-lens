// tests/test-privacy-score.js
//
// Unit tests for calculatePrivacyScore() (Phase 32-40 deliverable: Privacy Score)
// Owner: Person 3 (Intelligence Layer & Side Panel UI)

import assert from 'node:assert/strict';
import { calculatePrivacyScore, PRIVACY_GRADE_THRESHOLDS } from '../detection/scoring.js';
import { calculatePrivacyScore as libCalculatePrivacyScore } from '../lib/privacy-score.js';

console.log('=== Privacy Lens Holistic Privacy Score Tests ===\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(` [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(` [FAIL] ${name}:`, err.message);
    failed++;
  }
}

// 1. Pristine / Empty state
test('Empty events list returns score 100 with Grade A and Excellent rating', () => {
  const result = calculatePrivacyScore([]);
  assert.equal(result.score, 100);
  assert.equal(result.grade, 'A');
  assert.equal(result.rating, 'Excellent');
  assert.equal(result.color, '#22c55e');
  assert.equal(result.breakdown.deductions, 0);
  assert.equal(result.breakdown.highCount, 0);
  assert.equal(result.breakdown.mediumCount, 0);
  assert.equal(result.breakdown.lowCount, 0);
  assert.equal(result.breakdown.crossLayerCount, 0);
});

test('lib/privacy-score.js re-export matches detection/scoring.js', () => {
  const r1 = calculatePrivacyScore([]);
  const r2 = libCalculatePrivacyScore([]);
  assert.deepEqual(r1, r2);
});

// 2. Benign / Low risk API calls
test('Single benign API call (e.g. screen.width) retains high score >= 95 with Grade A', () => {
  const events = [
    {
      id: 'evt_1',
      timestamp: 1000,
      site: 'clean-site.com',
      category: 'storage',
      subtype: 'storage',
      severity: 'low',
      confidence: 0.1,
      evidence: { api: 'screen.width' },
    },
  ];
  const result = calculatePrivacyScore(events);
  assert.ok(result.score >= 95, `Expected score >= 95, got ${result.score}`);
  assert.equal(result.grade, 'A');
  assert.equal(result.breakdown.lowCount, 1);
  assert.equal(result.breakdown.highCount, 0);
});

test('Multiple isolated low-risk checks retain Grade A', () => {
  const events = [
    { id: '1', timestamp: 1000, category: 'storage', subtype: 'storage', severity: 'low', confidence: 0.1 },
    { id: '2', timestamp: 1050, category: 'storage', subtype: 'storage', severity: 'low', confidence: 0.1 },
    { id: '3', timestamp: 1100, category: 'fingerprinting', subtype: 'font', severity: 'low', confidence: 0.2 },
  ];
  const result = calculatePrivacyScore(events);
  assert.ok(result.score >= 90, `Expected score >= 90, got ${result.score}`);
  assert.equal(result.grade, 'A');
});

// 3. Medium severity tracking
test('Multiple third-party medium-risk trackers drop score to Grade B', () => {
  const events = [
    { id: '1', timestamp: 1000, site: 'blog.com', category: 'network', subtype: 'third-party-load', target: { domain: 'cdn.tracker1.com' }, severity: 'medium', confidence: 0.55 },
    { id: '2', timestamp: 1100, site: 'blog.com', category: 'network', subtype: 'third-party-load', target: { domain: 'cdn.tracker2.com' }, severity: 'medium', confidence: 0.55 },
    { id: '3', timestamp: 1200, site: 'blog.com', category: 'network', subtype: 'cache-token', target: { domain: 'cdn.tracker3.com' }, severity: 'medium', confidence: 0.55 },
  ];
  const result = calculatePrivacyScore(events);
  assert.ok(result.score >= 75 && result.score <= 89, `Expected score in 75-89, got ${result.score}`);
  assert.equal(result.grade, 'B');
  assert.equal(result.rating, 'Good');
  assert.equal(result.breakdown.mediumCount, 3);
});

// 4. High severity fingerprinting
test('Dual-vector Canvas + WebGL fingerprinting drops score to Grade C', () => {
  const events = [
    { id: '1', timestamp: 1000, site: 'news.com', category: 'fingerprinting', subtype: 'canvas', severity: 'high', confidence: 0.75, evidence: { api: 'HTMLCanvasElement.toDataURL' } },
    { id: '2', timestamp: 1100, site: 'news.com', category: 'fingerprinting', subtype: 'webgl', severity: 'high', confidence: 0.75, evidence: { api: 'WebGLRenderingContext.getParameter' } },
  ];
  const result = calculatePrivacyScore(events);
  assert.ok(result.score >= 55 && result.score <= 74, `Expected score in 55-74, got ${result.score}`);
  assert.equal(result.grade, 'C');
  assert.equal(result.rating, 'Moderate Risk');
  assert.equal(result.breakdown.highCount, 2);
});

// 5. Multi-vector fingerprinting + active exfiltration
test('Tri-vector fingerprinting with active exfiltration drops score to Grade D or F', () => {
  const events = [
    { id: '1', timestamp: 1000, site: 'sketchy.com', category: 'fingerprinting', subtype: 'canvas', severity: 'high', confidence: 0.85 },
    { id: '2', timestamp: 1050, site: 'sketchy.com', category: 'fingerprinting', subtype: 'webgl', severity: 'high', confidence: 0.85 },
    { id: '3', timestamp: 1100, site: 'sketchy.com', category: 'fingerprinting', subtype: 'audio', severity: 'high', confidence: 0.90 },
    { id: '4', timestamp: 1200, site: 'sketchy.com', category: 'fingerprinting', subtype: 'beacon', target: { domain: 'collector.sketchy.com' }, severity: 'high', confidence: 0.95, evidence: { forensicNotes: 'Active Multi-Vector Exfiltration Chain' } },
  ];
  const result = calculatePrivacyScore(events);
  assert.ok(result.score < 55, `Expected score < 55, got ${result.score}`);
  assert.ok(result.grade === 'D' || result.grade === 'F', `Expected grade D or F, got ${result.grade}`);
});

// 6. Cross-layer confirmation penalty test
test('Cross-layer confirmed events incur higher deduction than unconfirmed events', () => {
  const baseEvents = [
    { id: '1', timestamp: 1000, category: 'fingerprinting', subtype: 'canvas', severity: 'high', confidence: 0.80 },
    { id: '2', timestamp: 1050, category: 'fingerprinting', subtype: 'beacon', target: { domain: 'analytics.com' }, severity: 'medium', confidence: 0.60 },
  ];

  const crossLayerEvents = [
    { id: '1', timestamp: 1000, category: 'fingerprinting', subtype: 'canvas', severity: 'high', confidence: 0.80 },
    // Matching DOM + Network beacons to analytics.com within 2000ms window
    { id: '2', timestamp: 1050, category: 'fingerprinting', subtype: 'beacon', target: { domain: 'analytics.com' }, severity: 'medium', confidence: 0.60 },
    { id: '3', timestamp: 1100, category: 'network', subtype: 'beacon', target: { domain: 'analytics.com' }, severity: 'medium', confidence: 0.60 },
  ];

  const baseResult = calculatePrivacyScore(baseEvents);
  const crossResult = calculatePrivacyScore(crossLayerEvents);

  assert.ok(
    crossResult.score < baseResult.score,
    `Expected cross-layer confirmed score (${crossResult.score}) < base score (${baseResult.score})`
  );
  assert.ok(crossResult.breakdown.crossLayerCount >= 2, `Expected crossLayerCount >= 2, got ${crossResult.breakdown.crossLayerCount}`);
});

// 7. Monotonicity test
test('Monotonicity: Adding additional threat events never increases privacy score', () => {
  const siteEvents = [];
  let prevScore = calculatePrivacyScore(siteEvents).score;

  const newEvents = [
    { id: '1', timestamp: 1000, category: 'storage', subtype: 'storage', severity: 'low', confidence: 0.1 },
    { id: '2', timestamp: 2000, category: 'network', subtype: 'third-party-load', severity: 'medium', confidence: 0.55 },
    { id: '3', timestamp: 3000, category: 'fingerprinting', subtype: 'canvas', severity: 'high', confidence: 0.85 },
    { id: '4', timestamp: 4000, category: 'fingerprinting', subtype: 'webgl', severity: 'high', confidence: 0.90 },
    { id: '5', timestamp: 5000, category: 'fingerprinting', subtype: 'beacon', severity: 'high', confidence: 0.95 },
  ];

  for (const evt of newEvents) {
    siteEvents.push(evt);
    const currScore = calculatePrivacyScore(siteEvents).score;
    assert.ok(
      currScore <= prevScore,
      `Monotonicity violation: score increased from ${prevScore} to ${currScore}`
    );
    prevScore = currScore;
  }
});

// 8. Robustness against malformed/null inputs
test('Robustness: handles non-array, null, undefined, and partial objects gracefully', () => {
  assert.equal(calculatePrivacyScore(null).score, 100);
  assert.equal(calculatePrivacyScore(undefined).score, 100);
  assert.equal(calculatePrivacyScore('invalid').score, 100);

  const partialEvents = [
    {},
    { id: 'x', severity: undefined },
    { id: 'y', severity: 'high', confidence: undefined },
  ];
  const result = calculatePrivacyScore(partialEvents);
  assert.ok(typeof result.score === 'number' && result.score >= 0 && result.score <= 100);
  assert.ok(['A', 'B', 'C', 'D', 'F'].includes(result.grade));
});

// 9. Diminishing returns on repetitive tracker events from the same domain
test('High volume repetitive tracker calls (e.g. 25 hits) from single tracker retain Grade B/C and do not saturate to Grade F', () => {
  const repetitiveEvents = [];
  for (let i = 0; i < 25; i++) {
    repetitiveEvents.push({
      id: `rep_${i}`,
      timestamp: 1000 + i * 50,
      site: 'commercial-site.com',
      category: 'network',
      subtype: 'third-party-load',
      target: { domain: 'analytics.google.com' },
      severity: 'medium',
      confidence: 0.55,
    });
  }

  const result = calculatePrivacyScore(repetitiveEvents);
  // Instead of plunging to 0 (Grade F), diminishing returns cap the penalty so the site remains Grade B or C
  assert.ok(
    result.score >= 70,
    `Expected score >= 70 for single-tracker high volume, got ${result.score}`
  );
  assert.ok(
    ['B', 'C'].includes(result.grade),
    `Expected Grade B or C, got ${result.grade}`
  );
  assert.equal(result.breakdown.distinctTrackers, 1);
});

// 10. Broad cross-site tracker proliferation correctly incurs higher deductions
test('Broad tracking network with 6 distinct tracker domains receives higher penalty than 1 tracker with 25 events', () => {
  const multiTrackerEvents = [
    { id: 't1', timestamp: 1000, category: 'network', subtype: 'beacon', target: { domain: 'tracker1.com' }, severity: 'medium', confidence: 0.65 },
    { id: 't2', timestamp: 1100, category: 'network', subtype: 'beacon', target: { domain: 'tracker2.com' }, severity: 'medium', confidence: 0.65 },
    { id: 't3', timestamp: 1200, category: 'network', subtype: 'beacon', target: { domain: 'tracker3.com' }, severity: 'medium', confidence: 0.65 },
    { id: 't4', timestamp: 1300, category: 'network', subtype: 'beacon', target: { domain: 'tracker4.com' }, severity: 'medium', confidence: 0.65 },
    { id: 't5', timestamp: 1400, category: 'network', subtype: 'beacon', target: { domain: 'tracker5.com' }, severity: 'medium', confidence: 0.65 },
    { id: 't6', timestamp: 1500, category: 'network', subtype: 'beacon', target: { domain: 'tracker6.com' }, severity: 'medium', confidence: 0.65 },
  ];

  const singleTrackerEvents = [];
  for (let i = 0; i < 25; i++) {
    singleTrackerEvents.push({
      id: `s_${i}`,
      timestamp: 1000 + i * 10,
      category: 'network',
      subtype: 'beacon',
      target: { domain: 'tracker1.com' },
      severity: 'medium',
      confidence: 0.65,
    });
  }

  const multiResult = calculatePrivacyScore(multiTrackerEvents);
  const singleResult = calculatePrivacyScore(singleTrackerEvents);

  assert.ok(
    multiResult.score < singleResult.score,
    `Expected multi-tracker score (${multiResult.score}) < single-tracker score (${singleResult.score})`
  );
});

console.log(`\n=== All Privacy Score Tests Completed (${failed} failure(s)) ===`);
if (failed > 0) process.exit(1);

