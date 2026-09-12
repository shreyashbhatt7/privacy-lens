/**
 * Automated Verification Script for Tier 1 & Tier 2 Hooks and 500ms Batching
 * Verifies that:
 * 1. Canvas, WebGL, Audio, Storage, Cookie, and Beacon hooks intercept APIs.
 * 2. Tier 2 Font, Screen, and Navigator hooks intercept APIs.
 * 3. 500ms Batching and deduplication in content-bridge.js correctly aggregates rapid calls into count.
 */

const receivedMessages = [];
const relayedExtensionMessages = [];

// Mock window and postMessage environment
global.window = global;
global.window.addEventListener = (event, handler) => {};
global.window.postMessage = (msg) => {
  receivedMessages.push(msg);
};

// Mock Chrome runtime for content-bridge
global.chrome = {
  runtime: {
    sendMessage: (msg) => {
      relayedExtensionMessages.push(msg);
      return Promise.resolve({ received: true });
    }
  }
};

async function runTests() {
  console.log('=== Privacy Lens Tier 1 & Tier 2 Hooks + Batching Automated Test ===\n');

  // Setup DOM / Web API mocks
  class MockCanvas {
    toDataURL(format) { return 'data:image/png;base64,mock'; }
    toBlob(callback, format) { if (callback) callback(new Blob([])); }
  }
  class MockCanvas2DContext {
    getImageData(sx, sy, sw, sh) { return { data: new Uint8ClampedArray(4) }; }
    isPointInPath(x, y) { return true; }
  }
  class MockWebGLContext {
    getParameter(param) { return 'Mock Vendor/Renderer'; }
    getExtension(name) { return { UNMASKED_RENDERER_WEBGL: 0x9246 }; }
    readPixels(x, y, w, h, format, type, pixels) { return null; }
  }
  class MockAudioContext {
    createOscillator() { return {}; }
    createAnalyser() { return {}; }
    createDynamicsCompressor() { return {}; }
  }
  class MockOfflineAudioContext {
    startRendering() { return Promise.resolve({}); }
  }
  class MockStorage {
    constructor() { this._store = {}; }
    getItem(key) { return this._store[key] || null; }
    setItem(key, val) { this._store[key] = String(val); }
  }
  class MockFontFaceSet {
    check(font, text) { return true; }
    load(font, text) { return Promise.resolve([]); }
  }

  global.HTMLCanvasElement = MockCanvas;
  global.CanvasRenderingContext2D = MockCanvas2DContext;
  global.WebGLRenderingContext = MockWebGLContext;
  global.AudioContext = MockAudioContext;
  global.OfflineAudioContext = MockOfflineAudioContext;
  global.Storage = MockStorage;
  global.Screen = class MockScreen {};
  global.screen = new global.Screen();
  Object.defineProperty(global.Screen.prototype, 'width', { get: () => 1920, configurable: true });
  Object.defineProperty(global.Screen.prototype, 'height', { get: () => 1080, configurable: true });
  Object.defineProperty(global.Screen.prototype, 'colorDepth', { get: () => 24, configurable: true });

  global.Navigator = class MockNavigator {};
  if (!global.navigator) {
    global.navigator = new global.Navigator();
  }
  try {
    Object.defineProperty(global.navigator, 'plugins', { get: () => [], configurable: true });
    Object.defineProperty(global.navigator, 'userAgentData', { get: () => ({ brands: [] }), configurable: true });
  } catch (e) {}
  global.navigator.sendBeacon = (url, data) => true;
  global.fetch = (url) => Promise.resolve({ ok: true });
  global.XMLHttpRequest = class MockXHR {
    open(method, url) {}
  };

  // Mock Document cookie & fonts properties
  let _cookieVal = '';
  class MockDocument {}
  Object.defineProperty(MockDocument.prototype, 'cookie', {
    get() { return _cookieVal; },
    set(v) { _cookieVal = v; },
    configurable: true
  });
  global.Document = MockDocument;
  global.document = new MockDocument();
  global.document.fonts = new MockFontFaceSet();

  class MockIDBFactory {
    open(name, version) { return { result: {} }; }
  }
  global.IDBFactory = MockIDBFactory;
  global.indexedDB = new MockIDBFactory();

  // Load hooks
  const { initCanvasHooks } = await import('../fingerprint/canvas.js');
  const { initWebGLHooks } = await import('../fingerprint/webgl.js');
  const { initAudioHooks } = await import('../fingerprint/audio.js');
  const { initStorageHooks } = await import('../fingerprint/storage.js');
  const { initFontHooks } = await import('../fingerprint/fonts.js');
  const mainWorld = await import('../fingerprint/main-world.js');

  // Trigger Canvas Hooks
  const canvas = new MockCanvas();
  canvas.toDataURL('image/png');
  const ctx = new MockCanvas2DContext();
  ctx.getImageData(0, 0, 10, 10);

  // Trigger WebGL Hooks
  const gl = new MockWebGLContext();
  gl.getParameter(0x1F00); // VENDOR
  gl.getExtension('WEBGL_debug_renderer_info');

  // Trigger Audio Hooks
  const audio = new MockAudioContext();
  audio.createOscillator();
  audio.createDynamicsCompressor();

  // Trigger Storage Hooks
  const storage = new MockStorage();
  storage.setItem('user_token', 'xyz123');
  storage.getItem('user_token');

  // Trigger Cookie Hook
  document.cookie = 'session_id=abc456';
  const c = document.cookie;

  // Trigger IndexedDB Hook
  global.indexedDB.open('analytics_db', 1);

  // Trigger Beacon / Network Hooks
  navigator.sendBeacon('https://analytics.example.com/collect', 'id=123');
  fetch('https://telemetry.example.com/track');
  const xhr = new XMLHttpRequest();
  xhr.open('POST', 'https://metrics.example.com/log');

  // Trigger Tier 2 Font Hooks
  document.fonts.check('16px Arial');
  document.fonts.load('12px "Courier New"');

  // Trigger Tier 2 Screen & Navigator property reads
  const sw = screen.width;
  const scd = screen.colorDepth;
  const np = navigator.plugins;
  const uad = navigator.userAgentData;

  console.log(`[1] Captured ${receivedMessages.length} PrivacyLens hook events:`);
  let passCount = 0;

  for (const msg of receivedMessages) {
    const payload = msg.payload || msg.event;
    const hasValidEnvelope = msg.source === 'PRIVACY_LENS_MAIN_WORLD' || msg.__privacyLens === true;
    const hasValidCategory = payload && payload.category === 'fingerprinting';
    const hasValidEvidence = payload && payload.evidence && typeof payload.evidence.api === 'string' && typeof payload.evidence.details === 'object';
    const hasValidSourceScript = payload && payload.source && typeof payload.source.script === 'string';

    let targetDomainValid = true;
    if (payload && payload.subtype === 'beacon') {
      targetDomainValid = payload.target && typeof payload.target.domain === 'string' && payload.target.domain.length > 0;
    }

    if (hasValidEnvelope && hasValidCategory && hasValidEvidence && hasValidSourceScript && targetDomainValid) {
      const targetStr = payload.target?.domain ? ` -> target: ${payload.target.domain}` : '';
      const scriptStr = payload.source?.script ? ` (source: ${payload.source.script})` : '';
      console.log(` [PASS] [${payload.subtype}] ${payload.evidence.api}${targetStr}${scriptStr}`);
      passCount++;
    } else {
      console.error(` [FAIL] Schema mismatch on message:`, JSON.stringify(msg, null, 2));
    }
  }

  console.log(`\nResults: ${passCount}/${receivedMessages.length} events strictly conforming to TrackingEvent schema.`);
  if (passCount !== receivedMessages.length || passCount < 15) {
    process.exit(1);
  }

  // --- Step 3: Test 500ms Batching & Deduplication in content-bridge ---
  console.log('\n[2] Testing 500ms Source-Level Batching & Deduplication...');
  const { bufferedSend, flushBuffer } = await import('../content/content-bridge.js');

  const testEvent = {
    category: 'fingerprinting',
    subtype: 'canvas',
    source: { script: 'https://cdn.example.com/fp.js' },
    evidence: { api: 'HTMLCanvasElement.toDataURL', details: {} },
    timestamp: Date.now()
  };

  // Simulate 10 rapid identical calls
  for (let i = 0; i < 10; i++) {
    bufferedSend(testEvent);
  }

  // Simulate 5 calls to a different API
  const testEvent2 = {
    category: 'fingerprinting',
    subtype: 'webgl',
    source: { script: 'https://cdn.example.com/fp.js' },
    evidence: { api: 'WebGLRenderingContext.getParameter', details: { param: 0x1F00 } },
    timestamp: Date.now()
  };
  for (let i = 0; i < 5; i++) {
    bufferedSend(testEvent2);
  }

  // Manually flush buffer to assert batch contents
  flushBuffer();

  console.log(`Relayed ${relayedExtensionMessages.length} batch messages to chrome.runtime.sendMessage.`);
  if (relayedExtensionMessages.length !== 1) {
    console.error('[FAIL] Expected exactly 1 batch message');
    process.exit(1);
  }

  const batch = relayedExtensionMessages[0];
  console.log('Batch payload entries:', batch.payload.length);
  if (batch.payload.length !== 2) {
    console.error('[FAIL] Expected 2 deduplicated items in batch, got:', batch.payload.length);
    process.exit(1);
  }

  const canvasEntry = batch.payload.find(e => e.subtype === 'canvas');
  const webglEntry = batch.payload.find(e => e.subtype === 'webgl');

  console.log(`Canvas count: ${canvasEntry?.count} (expected 10)`);
  console.log(`WebGL count: ${webglEntry?.count} (expected 5)`);

  if (canvasEntry?.count === 10 && webglEntry?.count === 5) {
    console.log('\n [PASS] 500ms Batching & Deduplication verified successfully!');
  } else {
    console.error('[FAIL] Batch counts do not match expected values.');
    process.exit(1);
  }

  console.log('\n=== All Phase 12-18 Automated Tests Passed! ===\n');
}

runTests().catch((err) => {
  console.error('Test runner failed:', err);
  process.exit(1);
});
