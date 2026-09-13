// tests/test-confidence-engine.js
//
// Automated verification for Person 3's Confidence & Correlation Engine (Phase 24-32).
// Verifies signal combination refinement across fingerprint/*.js hooks.

import { ConfidenceEngine } from '../detection/confidence-engine.js';
import { classifySignal } from '../detection/classifier.js';
import { VECTOR_TYPES } from '../detection/scoring.js';

let failures = 0;

function assert(condition, testName, message = '') {
  if (condition) {
    console.log(` [PASS] ${testName}`);
  } else {
    console.error(` [FAIL] ${testName}${message ? ` — ${message}` : ''}`);
    failures++;
  }
}

async function runTests() {
  console.log('=== Privacy Lens Confidence & Correlation Engine (Phase 24-32) Tests ===\n');

  const engine = new ConfidenceEngine(10000); // 10s window

  // -------------------------------------------------------------------------
  // Test 1: Signal Classification
  // -------------------------------------------------------------------------
  console.log('[1] Testing Signal Classification & Threat Vector Mapping...');

  const benignWebglDraft = {
    subtype: 'webgl',
    evidence: { api: 'WebGLRenderingContext.getParameter', details: { param: 0x0D33, paramName: 'MAX_TEXTURE_SIZE' } }
  };
  const classifiedBenign = classifySignal(benignWebglDraft);
  assert(
    classifiedBenign.isCapabilityCheck === true && classifiedBenign.vectorType === VECTOR_TYPES.WEBGL_CAPABILITY_PARAM,
    'WebGL MAX_TEXTURE_SIZE classified as capability param check',
    JSON.stringify(classifiedBenign)
  );

  const unmaskedWebglDraft = {
    subtype: 'webgl',
    evidence: { api: 'WebGLRenderingContext.getParameter', details: { param: 0x9246, paramName: 'UNMASKED_RENDERER_WEBGL' } }
  };
  const classifiedUnmasked = classifySignal(unmaskedWebglDraft);
  assert(
    classifiedUnmasked.isUnmaskedGpu === true && classifiedUnmasked.vectorType === VECTOR_TYPES.WEBGL_UNMASKED_GPU,
    'WebGL UNMASKED_RENDERER_WEBGL classified as unmasked GPU query',
    JSON.stringify(classifiedUnmasked)
  );

  const offlineAudioDraft = {
    subtype: 'audio',
    evidence: { api: 'OfflineAudioContext.startRendering', details: {} }
  };
  const classifiedAudio = classifySignal(offlineAudioDraft);
  assert(
    classifiedAudio.isOfflineAudio === true && classifiedAudio.vectorType === VECTOR_TYPES.AUDIO_OFFLINE_RENDER,
    'OfflineAudioContext.startRendering classified as offline audio fingerprinting',
    JSON.stringify(classifiedAudio)
  );

  const canvasDraft = {
    subtype: 'canvas',
    evidence: { api: 'HTMLCanvasElement.toDataURL', details: { format: 'image/png' } }
  };
  const classifiedCanvas = classifySignal(canvasDraft);
  assert(
    classifiedCanvas.vectorType === VECTOR_TYPES.CANVAS_READBACK,
    'HTMLCanvasElement.toDataURL classified as canvas readback',
    JSON.stringify(classifiedCanvas)
  );

  const beaconDraft = {
    subtype: 'beacon',
    evidence: { api: 'navigator.sendBeacon', details: { url: 'https://tracker.example.com/collect' } },
    target: { domain: 'tracker.example.com' }
  };
  const classifiedBeacon = classifySignal(beaconDraft);
  assert(
    classifiedBeacon.isExfiltration === true && classifiedBeacon.vectorType === VECTOR_TYPES.BEACON_EXFILTRATION,
    'navigator.sendBeacon classified as beacon exfiltration',
    JSON.stringify(classifiedBeacon)
  );

  // -------------------------------------------------------------------------
  // Test 2: Individually Benign Hooks (Individually Benign vs Suspicious Combinations)
  // -------------------------------------------------------------------------
  console.log('\n[2] Testing Individually Benign API Calls...');
  engine.resetState();

  // Single WebGL MAX_TEXTURE_SIZE query from legitimate script
  const benignResult = engine.evaluateEvent(
    {
      subtype: 'webgl',
      source: { script: 'https://cdn.legit-game.com/engine.js' },
      evidence: { api: 'WebGLRenderingContext.getParameter', details: { param: 0x0D33, paramName: 'MAX_TEXTURE_SIZE' } }
    },
    { topSite: 'gamesite.com', tabId: 1 }
  );

  assert(
    benignResult.severity === 'low' && benignResult.confidence <= 0.20,
    'Single WebGL MAX_TEXTURE_SIZE check has LOW severity and LOW confidence',
    `got confidence=${benignResult.confidence}, severity=${benignResult.severity}`
  );

  // Single screen.width query for responsive layout
  const screenResult = engine.evaluateEvent(
    {
      subtype: 'storage',
      source: { script: 'https://cdn.legit-ui.com/layout.js' },
      evidence: { api: 'screen.width', details: {} }
    },
    { topSite: 'gamesite.com', tabId: 1 }
  );

  assert(
    screenResult.severity === 'low' && screenResult.confidence <= 0.20,
    'Single screen.width query for responsive layout has LOW severity and LOW confidence',
    `got confidence=${screenResult.confidence}, severity=${screenResult.severity}`
  );

  // Single font check
  const fontResult = engine.evaluateEvent(
    {
      subtype: 'font',
      source: { script: 'https://cdn.legit-ui.com/font-loader.js' },
      evidence: { api: 'FontFaceSet.check', details: { font: '16px Roboto' } },
      count: 1
    },
    { topSite: 'gamesite.com', tabId: 1 }
  );

  assert(
    fontResult.severity === 'low' && fontResult.confidence <= 0.20,
    'Single font check (Roboto) has LOW severity and LOW confidence',
    `got confidence=${fontResult.confidence}, severity=${fontResult.severity}`
  );

  // -------------------------------------------------------------------------
  // Test 3: Multi-Vector Combinations (PDF Example Scenario)
  // -------------------------------------------------------------------------
  console.log('\n[3] Testing Multi-Vector Combinations (PDF Example Scenario)...');
  engine.resetState();

  const trackerScript = 'https://cdn.fingerprint-analytics.com/v3.js';
  const site = 'news-portal.com';
  const tabId = 10;

  // Step 1: Tracker queries WebGL parameter
  const evt1 = engine.evaluateEvent(
    {
      subtype: 'webgl',
      source: { script: trackerScript },
      evidence: { api: 'WebGLRenderingContext.getParameter', details: { param: 0x9246, paramName: 'UNMASKED_RENDERER_WEBGL' } }
    },
    { topSite: site, tabId }
  );

  // Step 2: Tracker calls canvas toDataURL
  const evt2 = engine.evaluateEvent(
    {
      subtype: 'canvas',
      source: { script: trackerScript },
      evidence: { api: 'HTMLCanvasElement.toDataURL', details: { format: 'image/png' } }
    },
    { topSite: site, tabId }
  );

  assert(
    evt2.severity === 'high' && evt2.confidence >= 0.70,
    'Canvas toDataURL + WebGL Unmasked GPU triggers HIGH severity (confidence >= 0.70)',
    `got confidence=${evt2.confidence}, severity=${evt2.severity}`
  );

  // Step 3: Tracker renders audio via OfflineAudioContext
  const evt3 = engine.evaluateEvent(
    {
      subtype: 'audio',
      source: { script: trackerScript },
      evidence: { api: 'OfflineAudioContext.startRendering', details: {} }
    },
    { topSite: site, tabId }
  );

  assert(
    evt3.severity === 'high' && evt3.confidence >= 0.85,
    'Tri-Vector (Canvas + WebGL + Offline Audio) triggers HIGH confidence >= 0.85',
    `got confidence=${evt3.confidence}, severity=${evt3.severity}`
  );

  // Step 4: Tracker transmits collected fingerprint via sendBeacon
  const evt4 = engine.evaluateEvent(
    {
      subtype: 'beacon',
      source: { script: trackerScript },
      target: { domain: 'telemetry.fingerprint-analytics.com' },
      evidence: { api: 'navigator.sendBeacon', details: { url: 'https://telemetry.fingerprint-analytics.com/ingest' } }
    },
    { topSite: site, tabId }
  );

  assert(
    evt4.severity === 'high' && evt4.confidence >= 0.95,
    'Full Evidence Chain (Canvas + WebGL + Audio + sendBeacon) triggers confidence >= 0.95',
    `got confidence=${evt4.confidence}, severity=${evt4.severity}`
  );

  assert(
    evt4.evidence.forensicNotes.includes('Active Multi-Vector Exfiltration Chain'),
    'Forensic notes correctly identify active exfiltration chain',
    `got forensicNotes="${evt4.evidence.forensicNotes}"`
  );

  // -------------------------------------------------------------------------
  // Test 4: High-Frequency Probing Multiplier
  // -------------------------------------------------------------------------
  console.log('\n[4] Testing High-Frequency Probing Multiplier (count > 5)...');
  engine.resetState();

  const probeScript = 'https://cdn.tracker.net/probe.js';

  // 25 rapid font checks in a loop
  const fontBatchEvt = engine.evaluateEvent(
    {
      subtype: 'font',
      source: { script: probeScript },
      evidence: { api: 'FontFaceSet.check', details: { font: '20px SystemFont' } },
      count: 25
    },
    { topSite: site, tabId }
  );

  assert(
    fontBatchEvt.confidence >= 0.60,
    'High-frequency font enumeration loop (count=25) boosts confidence >= 0.60',
    `got confidence=${fontBatchEvt.confidence}`
  );

  // -------------------------------------------------------------------------
  // Test 5: Script Isolation (Different Scripts Do Not Cross-Contaminate)
  // -------------------------------------------------------------------------
  console.log('\n[5] Testing Script Attribution & Context Isolation...');
  engine.resetState();

  const gameScript = 'https://games.com/bundle.js';
  const adScript = 'https://ads.com/ad.js';

  // Game script does WebGL capability check
  const gameEvt = engine.evaluateEvent(
    {
      subtype: 'webgl',
      source: { script: gameScript },
      evidence: { api: 'WebGLRenderingContext.getParameter', details: { param: 0x0D33, paramName: 'MAX_TEXTURE_SIZE' } }
    },
    { topSite: site, tabId }
  );

  // Ad script does Canvas readback
  const adEvt = engine.evaluateEvent(
    {
      subtype: 'canvas',
      source: { script: adScript },
      evidence: { api: 'HTMLCanvasElement.toDataURL', details: {} }
    },
    { topSite: site, tabId }
  );

  const gameSession = engine.getSession(site, tabId, gameScript);
  const adSession = engine.getSession(site, tabId, adScript);

  assert(
    gameSession.vectorGroups.size === 1 && !gameSession.vectorGroups.has('canvas'),
    'Game script session only contains WebGL',
    JSON.stringify(Array.from(gameSession.vectorGroups))
  );

  assert(
    adSession.vectorGroups.size === 1 && !adSession.vectorGroups.has('webgl'),
    'Ad script session only contains Canvas',
    JSON.stringify(Array.from(adSession.vectorGroups))
  );

  // -------------------------------------------------------------------------
  // Test 6: evaluateBatch (Batch Ingestion from Content Bridge)
  // -------------------------------------------------------------------------
  console.log('\n[6] Testing evaluateBatch for Content Bridge Ingestion...');
  engine.resetState();

  const batchDrafts = [
    {
      subtype: 'canvas',
      source: { script: trackerScript },
      evidence: { api: 'HTMLCanvasElement.toDataURL', details: {} }
    },
    {
      subtype: 'webgl',
      source: { script: trackerScript },
      evidence: { api: 'WebGLRenderingContext.getParameter', details: { param: 0x9246 } }
    },
    {
      subtype: 'audio',
      source: { script: trackerScript },
      evidence: { api: 'OfflineAudioContext.startRendering', details: {} }
    }
  ];

  const finalizedEvents = engine.evaluateBatch(batchDrafts, { topSite: site, tabId });

  assert(
    finalizedEvents.length === 3,
    'evaluateBatch returns 3 finalized TrackingEvents',
    `got length=${finalizedEvents.length}`
  );

  const lastBatchEvt = finalizedEvents[2];
  assert(
    lastBatchEvt.confidence >= 0.85 && lastBatchEvt.severity === 'high',
    'Last batch event reflects accumulated multi-vector confidence (>= 0.85)',
    `got confidence=${lastBatchEvt.confidence}, severity=${lastBatchEvt.severity}`
  );

  console.log(`\n=== All Confidence Engine Tests Completed (${failures} failure(s)) ===\n`);
  if (failures > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Test runner failed:', err);
  process.exit(1);
});
