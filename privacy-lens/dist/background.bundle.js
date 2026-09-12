(() => {
  // shared/events.js
  var VALID_CATEGORIES = ["fingerprinting", "network", "storage", "identifier"];
  var VALID_SEVERITIES = ["low", "medium", "high"];
  var _counter = 0;
  function nextId() {
    _counter += 1;
    return `evt_${Date.now()}_${_counter}`;
  }
  function createTrackingEvent(fields) {
    if (!VALID_CATEGORIES.includes(fields.category)) {
      throw new Error(`Invalid category: ${fields.category}`);
    }
    if (!VALID_SEVERITIES.includes(fields.severity)) {
      throw new Error(`Invalid severity: ${fields.severity}`);
    }
    if (typeof fields.confidence !== "number" || fields.confidence < 0 || fields.confidence > 1) {
      throw new Error(`Invalid confidence: ${fields.confidence}`);
    }
    return {
      id: nextId(),
      timestamp: Date.now(),
      tabId: fields.tabId ?? null,
      site: fields.site ?? null,
      category: fields.category,
      subtype: fields.subtype,
      source: fields.source ?? {},
      target: fields.target ?? {},
      evidence: fields.evidence ?? {},
      severity: fields.severity,
      confidence: fields.confidence
    };
  }

  // lib/store.js
  var EVENTS_KEY = "pl_events";
  var MAX_EVENTS_IN_MEMORY = 5e3;
  async function hashIdentifier(rawValue) {
    const enc = new TextEncoder().encode(String(rawValue));
    const digest = await crypto.subtle.digest("SHA-256", enc);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  async function appendEvent(event) {
    const { [EVENTS_KEY]: existing = [] } = await chrome.storage.session.get(EVENTS_KEY);
    existing.push(event);
    if (existing.length > MAX_EVENTS_IN_MEMORY) {
      existing.splice(0, existing.length - MAX_EVENTS_IN_MEMORY);
    }
    await chrome.storage.session.set({ [EVENTS_KEY]: existing });
    chrome.runtime.sendMessage({ type: "pl_new_event", event }).catch(() => {
    });
  }
  async function clearEventsForTab(tabId) {
    const { [EVENTS_KEY]: existing = [] } = await chrome.storage.session.get(EVENTS_KEY);
    const remaining = existing.filter((e) => e.tabId !== tabId);
    await chrome.storage.session.set({ [EVENTS_KEY]: remaining });
  }
  async function getPersistentMap(mapKey) {
    const { [mapKey]: existing = {} } = await chrome.storage.local.get(mapKey);
    return existing;
  }
  async function setPersistentMap(mapKey, obj) {
    await chrome.storage.local.set({ [mapKey]: obj });
  }

  // network/tracker-list.js
  var _trackers = null;
  var _allowlist = null;
  async function loadDataset() {
    if (_trackers && _allowlist) return;
    const url = chrome.runtime.getURL("data/tracker-domains.json");
    const res = await fetch(url);
    const data = await res.json();
    _trackers = new Set(data.trackers);
    _allowlist = new Set(data.allowlist);
  }
  function getRegistrableDomain(hostname) {
    const parts = hostname.split(".").filter(Boolean);
    if (parts.length <= 2) return hostname;
    const twoPartTlds = /* @__PURE__ */ new Set(["co.uk", "com.au", "co.in", "co.jp"]);
    const lastTwo = parts.slice(-2).join(".");
    if (twoPartTlds.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return lastTwo;
  }
  async function isKnownTracker(hostname) {
    await loadDataset();
    const domain = getRegistrableDomain(hostname);
    return _trackers.has(domain);
  }
  async function isAllowlisted(hostname) {
    await loadDataset();
    const domain = getRegistrableDomain(hostname);
    return _allowlist.has(domain) || _allowlist.has(hostname);
  }

  // network/etag-detector.js
  var STORE_KEY = "pl_etag_observations";
  var SESSION_REPORTED_KEY = "pl_etag_reported_session";
  var SEVERITY_RANK = { low: 1, medium: 2, high: 3 };
  function scoreReuse({ timesSeen, siteCount }) {
    const reuseComponent = Math.min(timesSeen / 6, 0.6);
    const spreadComponent = Math.min((siteCount - 1) * 0.2, 0.35);
    return Math.min(0.95, 0.05 + reuseComponent + spreadComponent);
  }
  var sessionReportedCache = /* @__PURE__ */ new Map();
  var sessionCacheHydrated = false;
  var hydratePromise = null;
  async function ensureHydrated() {
    if (sessionCacheHydrated) return;
    if (!hydratePromise) {
      hydratePromise = (async () => {
        const { [SESSION_REPORTED_KEY]: reported = {} } = await chrome.storage.session.get(SESSION_REPORTED_KEY);
        for (const [key, severity] of Object.entries(reported)) {
          sessionReportedCache.set(key, severity);
        }
        sessionCacheHydrated = true;
      })();
    }
    await hydratePromise;
  }
  function persistSessionCacheInBackground() {
    chrome.storage.session.set({ [SESSION_REPORTED_KEY]: Object.fromEntries(sessionReportedCache) }).catch((err) => console.error("[PrivacyLens][etag] failed to persist session cache", err));
  }
  async function inspectEtag({ etagValue, requestDomain, topSite, tabId }) {
    if (!etagValue) return;
    const cleaned = etagValue.replace(/^W\//, "").replace(/"/g, "");
    if (cleaned.length < 8) return;
    await ensureHydrated();
    const domainHash = await hashIdentifier(getRegistrableDomain(requestDomain));
    const valueHash = await hashIdentifier(cleaned);
    const mapKey = `${domainHash}:${valueHash}`;
    const observations = await getPersistentMap(STORE_KEY);
    const prior = observations[mapKey] ?? { timesSeen: 0, sites: [], firstSeen: Date.now() };
    prior.timesSeen += 1;
    if (!prior.sites.includes(topSite)) prior.sites.push(topSite);
    observations[mapKey] = prior;
    await setPersistentMap(STORE_KEY, observations);
    if (prior.timesSeen < 2) return;
    const confidence = scoreReuse({ timesSeen: prior.timesSeen, siteCount: prior.sites.length });
    const severity = confidence >= 0.7 ? "high" : confidence >= 0.4 ? "medium" : "low";
    const lastReported = sessionReportedCache.get(mapKey) ?? null;
    if (lastReported && SEVERITY_RANK[severity] <= SEVERITY_RANK[lastReported]) return;
    sessionReportedCache.set(mapKey, severity);
    persistSessionCacheInBackground();
    const event = createTrackingEvent({
      tabId,
      site: topSite,
      category: "identifier",
      subtype: "etag",
      source: { requestDomain },
      target: { domain: getRegistrableDomain(requestDomain) },
      evidence: {
        api: "ETag header",
        valueHash,
        timesSeen: prior.timesSeen,
        distinctSitesSeenOn: prior.sites.length
      },
      severity,
      confidence
    });
    await appendEvent(event);
  }

  // network/cache-detector.js
  var LONG_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
  var TOKEN_LIKE = /[a-f0-9]{16,}|[A-Za-z0-9_-]{24,}/;
  function parseCacheControl(headerValue) {
    const parts = headerValue.toLowerCase().split(",").map((s) => s.trim());
    const result = { immutable: false, maxAge: null, noStore: false };
    for (const part of parts) {
      if (part === "immutable") result.immutable = true;
      if (part === "no-store") result.noStore = true;
      const m = part.match(/^max-age=(\d+)/);
      if (m) result.maxAge = parseInt(m[1], 10);
    }
    return result;
  }
  async function inspectCacheHeaders({ url, cacheControlHeader, topSite, tabId }) {
    if (!cacheControlHeader) return;
    const { immutable, maxAge, noStore } = parseCacheControl(cacheControlHeader);
    if (noStore) return;
    const aggressive = immutable || maxAge !== null && maxAge >= LONG_MAX_AGE_SECONDS;
    if (!aggressive) return;
    let path;
    try {
      path = new URL(url).pathname;
    } catch {
      return;
    }
    const looksLikeToken = TOKEN_LIKE.test(path);
    if (!looksLikeToken) return;
    const requestDomain = new URL(url).hostname;
    const confidence = immutable ? 0.75 : 0.55;
    const severity = confidence >= 0.7 ? "high" : confidence >= 0.4 ? "medium" : "low";
    const event = createTrackingEvent({
      tabId,
      site: topSite,
      category: "identifier",
      subtype: "cache-token",
      source: { url },
      target: { domain: getRegistrableDomain(requestDomain) },
      evidence: {
        api: "Cache-Control header",
        immutable,
        maxAgeSeconds: maxAge,
        pathLooksTokenized: true
      },
      severity,
      confidence
    });
    await appendEvent(event);
  }

  // network/cname-detector.js
  var DOH_TIMEOUT_MS = 1500;
  var cnameCache = /* @__PURE__ */ new Map();
  var CACHE_TTL_MS = 10 * 60 * 1e3;
  async function resolveCnameChain(hostname) {
    const cached = cnameCache.get(hostname);
    if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
      console.log(`[PrivacyLens][cname] cache hit for ${hostname}:`, cached.chain);
      return cached.chain;
    }
    console.log(`[PrivacyLens][cname] attempting DoH lookup for ${hostname}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CNAME`,
        { headers: { Accept: "application/dns-json" }, signal: controller.signal }
      );
      clearTimeout(timer);
      if (!res.ok) {
        console.log(`[PrivacyLens][cname] DoH responded non-OK (${res.status}) for ${hostname}`);
        return null;
      }
      const data = await res.json();
      const chain = (data.Answer ?? []).filter((a) => a.type === 5).map((a) => a.data.replace(/\.$/, ""));
      console.log(`[PrivacyLens][cname] DoH resolved ${hostname} ->`, chain.length ? chain : "(no CNAME record)");
      cnameCache.set(hostname, { chain, ts: Date.now() });
      return chain;
    } catch (err) {
      clearTimeout(timer);
      console.log(`[PrivacyLens][cname] DoH failed/timed out for ${hostname}:`, err.name);
      return null;
    }
  }
  async function inspectForCnameCloaking({ requestHostname, topSite, tabId }) {
    const requestRegDomain = getRegistrableDomain(requestHostname);
    const topRegDomain = getRegistrableDomain(topSite);
    if (requestRegDomain !== topRegDomain) return;
    if (await isAllowlisted(requestHostname)) {
      console.log(`[PrivacyLens][cname] ${requestHostname} is allowlisted, skipping`);
      return;
    }
    const chain = await resolveCnameChain(requestHostname);
    let cloakedTarget = null;
    let confidence = 0;
    let evidenceApi = "DNS-over-HTTPS (cloudflare-dns.com)";
    if (chain && chain.length > 0) {
      for (const cnameTarget of chain) {
        const cnameRegDomain = getRegistrableDomain(cnameTarget);
        if (cnameRegDomain !== topRegDomain && await isKnownTracker(cnameTarget)) {
          cloakedTarget = cnameTarget;
          confidence = 0.9;
          break;
        }
      }
    } else {
      evidenceApi = "bundled tracker list (DoH unavailable)";
      if (await isKnownTracker(requestHostname)) {
        cloakedTarget = requestHostname;
        confidence = 0.35;
      }
    }
    if (!cloakedTarget) {
      console.log(`[PrivacyLens][cname] no cloaking detected for ${requestHostname}`);
      return;
    }
    const event = createTrackingEvent({
      tabId,
      site: topSite,
      category: "network",
      subtype: "cname-cloaking",
      source: { requestHostname },
      target: { domain: cloakedTarget },
      evidence: { api: evidenceApi, cnameChain: chain ?? [] },
      severity: confidence >= 0.7 ? "high" : "medium",
      confidence
    });
    await appendEvent(event);
  }

  // network/thirdparty-detector.js
  var TRACKED_RESOURCE_TYPES = /* @__PURE__ */ new Set(["xmlhttprequest", "ping", "beacon", "image", "script", "sub_frame"]);
  var tabCallCounts = /* @__PURE__ */ new Map();
  var MAX_CALLS_PER_TRACKER_SUBTYPE = 3;
  setInterval(() => {
    if (tabCallCounts.size > 1e3) {
      tabCallCounts.clear();
    }
  }, 60 * 1e3);
  async function inspectThirdPartyCall({ url, initiatorDomain, topSite, resourceType, tabId }) {
    if (!TRACKED_RESOURCE_TYPES.has(resourceType)) return;
    let requestHostname;
    try {
      requestHostname = new URL(url).hostname;
    } catch {
      return;
    }
    const requestRegDomain = getRegistrableDomain(requestHostname);
    const topRegDomain = getRegistrableDomain(topSite);
    if (requestRegDomain === topRegDomain) return;
    if (await isAllowlisted(requestHostname)) return;
    const known = await isKnownTracker(requestHostname);
    if (!known) return;
    const isDataCarrying = resourceType === "ping" || resourceType === "beacon" || resourceType === "xmlhttprequest";
    const confidence = isDataCarrying ? 0.65 : 0.5;
    const subtype = isDataCarrying ? "beacon" : "third-party-load";
    if (tabId != null && tabId >= 0) {
      const throttleKey = `${tabId}:${requestRegDomain}:${subtype}`;
      const count = tabCallCounts.get(throttleKey) || 0;
      if (count >= MAX_CALLS_PER_TRACKER_SUBTYPE) {
        return;
      }
      tabCallCounts.set(throttleKey, count + 1);
    }
    const event = createTrackingEvent({
      tabId,
      site: topSite,
      category: "network",
      subtype,
      source: { script: initiatorDomain ?? null },
      target: { domain: requestRegDomain },
      evidence: { api: resourceType, url },
      severity: "medium",
      confidence
    });
    await appendEvent(event);
  }

  // network/interceptor.js
  var inFlight = /* @__PURE__ */ new Map();
  function safeHostname(urlLike) {
    if (!urlLike || urlLike === "null") return null;
    try {
      return new URL(urlLike).hostname;
    } catch {
      return null;
    }
  }
  function getHeader(headers, name) {
    const lower = name.toLowerCase();
    const found = (headers ?? []).find((h) => h.name.toLowerCase() === lower);
    return found ? found.value : null;
  }
  async function getTopSiteForTab(tabId) {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (!tab?.url) return null;
      const url = new URL(tab.url);
      if (url.protocol === "file:") return "local-file";
      return getRegistrableDomain(url.hostname) || null;
    } catch {
      return null;
    }
  }
  function initInterceptor() {
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => {
        if (details.tabId < 0) return;
        inFlight.set(details.requestId, {
          url: details.url,
          method: details.method,
          initiator: details.initiator ?? null,
          type: details.type,
          tabId: details.tabId,
          timestamp: details.timeStamp
        });
      },
      { urls: ["<all_urls>"] }
    );
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => {
        const record = inFlight.get(details.requestId);
        inFlight.delete(details.requestId);
        if (!record) return;
        handleCompletedRequest({
          ...record,
          status: details.statusCode,
          responseHeaders: details.responseHeaders ?? []
        }).catch((err) => console.error("[PrivacyLens] detector error", err));
      },
      { urls: ["<all_urls>"] },
      ["responseHeaders"]
    );
    setInterval(() => {
      const cutoff = Date.now() - 2 * 60 * 1e3;
      for (const [id, rec] of inFlight) {
        if (rec.timestamp < cutoff) inFlight.delete(id);
      }
    }, 60 * 1e3);
  }
  async function handleCompletedRequest(record) {
    const topSite = await getTopSiteForTab(record.tabId);
    if (!topSite) return;
    let requestHostname;
    try {
      requestHostname = new URL(record.url).hostname;
    } catch {
      return;
    }
    const etag = getHeader(record.responseHeaders, "etag");
    const cacheControl = getHeader(record.responseHeaders, "cache-control");
    const initiatorDomain = safeHostname(record.initiator);
    await Promise.all([
      inspectEtag({
        etagValue: etag,
        requestDomain: requestHostname,
        topSite,
        tabId: record.tabId
      }),
      inspectCacheHeaders({
        url: record.url,
        cacheControlHeader: cacheControl,
        topSite,
        tabId: record.tabId
      }),
      inspectForCnameCloaking({
        requestHostname,
        topSite,
        tabId: record.tabId
      }),
      inspectThirdPartyCall({
        url: record.url,
        initiatorDomain,
        topSite,
        resourceType: record.type,
        tabId: record.tabId
      })
    ]);
  }

  // shared/constants.js
  var MESSAGE_TYPES = {
    TRACKING_EVENT: "PRIVACY_LENS_TRACKING_EVENT",
    BATCH_EVENTS: "PRIVACY_LENS_BATCH_EVENTS"
  };

  // detection/scoring.js
  var VECTOR_TYPES = {
    CANVAS_READBACK: "canvas_readback",
    CANVAS_GEOMETRY: "canvas_geometry",
    WEBGL_UNMASKED_GPU: "webgl_unmasked_gpu",
    WEBGL_PIXEL_READBACK: "webgl_pixel_readback",
    WEBGL_GENERIC_PARAM: "webgl_generic_param",
    WEBGL_CAPABILITY_PARAM: "webgl_capability_param",
    AUDIO_OFFLINE_RENDER: "audio_offline_render",
    AUDIO_COMPRESSOR_OSC: "audio_compressor_osc",
    AUDIO_ANALYSER: "audio_analyser",
    AUDIO_BASIC_NODE: "audio_basic_node",
    FONT_ENUMERATION: "font_enumeration",
    FONT_SINGLE_CHECK: "font_single_check",
    DEVICE_ATTR_SWEEP: "device_attr_sweep",
    DEVICE_SINGLE_ATTR: "device_single_attr",
    STORAGE_CROSS_SYNC: "storage_cross_sync",
    STORAGE_SINGLE: "storage_single",
    BEACON_EXFILTRATION: "beacon_exfiltration"
  };
  var BASE_WEIGHTS = {
    [VECTOR_TYPES.CANVAS_READBACK]: 3,
    [VECTOR_TYPES.CANVAS_GEOMETRY]: 1,
    [VECTOR_TYPES.WEBGL_UNMASKED_GPU]: 4,
    [VECTOR_TYPES.WEBGL_PIXEL_READBACK]: 2.5,
    [VECTOR_TYPES.WEBGL_GENERIC_PARAM]: 1.5,
    [VECTOR_TYPES.WEBGL_CAPABILITY_PARAM]: 0.3,
    [VECTOR_TYPES.AUDIO_OFFLINE_RENDER]: 4,
    [VECTOR_TYPES.AUDIO_COMPRESSOR_OSC]: 3,
    [VECTOR_TYPES.AUDIO_ANALYSER]: 2,
    [VECTOR_TYPES.AUDIO_BASIC_NODE]: 0.5,
    [VECTOR_TYPES.FONT_ENUMERATION]: 3,
    [VECTOR_TYPES.FONT_SINGLE_CHECK]: 0.2,
    [VECTOR_TYPES.DEVICE_ATTR_SWEEP]: 2.5,
    [VECTOR_TYPES.DEVICE_SINGLE_ATTR]: 0.1,
    [VECTOR_TYPES.STORAGE_CROSS_SYNC]: 2,
    [VECTOR_TYPES.STORAGE_SINGLE]: 0.2,
    [VECTOR_TYPES.BEACON_EXFILTRATION]: 3.5
  };
  var PROBING_MULTIPLIERS = {
    SINGLE_BURST: 1,
    // count <= 1
    MODERATE_BURST: 1.25,
    // 2 <= count <= 5
    HIGH_RATE_PROBE: 1.5
    // count > 5
  };
  var SEVERITY_THRESHOLDS = {
    HIGH: 0.7,
    MEDIUM: 0.4
  };
  function calculateConfidenceScore({
    totalWeight,
    vectorCount = 1,
    hasExfiltration = false,
    hasUnmaskedGpu = false,
    hasOfflineAudio = false
  }) {
    if (vectorCount <= 1 && totalWeight <= 0.5) {
      const rawConf = Math.min(0.2, Math.max(0.05, totalWeight * 0.25));
      return {
        confidence: Math.round(rawConf * 100) / 100,
        severity: "low"
      };
    }
    let confidence = 1 - Math.exp(-totalWeight / 4.2);
    if (vectorCount >= 2) {
      confidence = Math.max(confidence, 0.55 + (vectorCount - 2) * 0.12);
    }
    if (vectorCount >= 3) {
      confidence = Math.max(confidence, 0.85);
    }
    if (vectorCount >= 4) {
      confidence = Math.max(confidence, 0.9);
    }
    if (hasUnmaskedGpu && vectorCount >= 2) {
      confidence = Math.max(confidence, 0.75);
    }
    if (hasOfflineAudio && vectorCount >= 2) {
      confidence = Math.max(confidence, 0.8);
    }
    if (hasExfiltration) {
      if (vectorCount >= 3 || vectorCount >= 2 && (hasUnmaskedGpu || hasOfflineAudio)) {
        confidence = Math.max(confidence, 0.95);
      } else if (vectorCount >= 2 || totalWeight >= 3) {
        confidence = Math.max(confidence, 0.88);
      } else {
        confidence = Math.max(confidence, 0.6);
      }
    }
    confidence = Math.min(0.99, Math.max(0.05, Math.round(confidence * 100) / 100));
    let severity = "low";
    if (confidence >= SEVERITY_THRESHOLDS.HIGH) {
      severity = "high";
    } else if (confidence >= SEVERITY_THRESHOLDS.MEDIUM) {
      severity = "medium";
    }
    return { confidence, severity };
  }

  // detection/classifier.js
  var WEBGL_UNMASKED_PARAMS = /* @__PURE__ */ new Set([
    37445,
    // UNMASKED_VENDOR_WEBGL
    37446,
    // UNMASKED_RENDERER_WEBGL
    "UNMASKED_VENDOR_WEBGL",
    "UNMASKED_RENDERER_WEBGL"
  ]);
  var WEBGL_CAPABILITY_PARAMS = /* @__PURE__ */ new Set([
    3379,
    // MAX_TEXTURE_SIZE
    34921,
    // MAX_VERTEX_ATTRIBS
    36344,
    // MAX_VARYING_VECTORS
    36347,
    // MAX_VERTEX_UNIFORM_VECTORS
    36349,
    // MAX_FRAGMENT_UNIFORM_VECTORS
    "MAX_TEXTURE_SIZE",
    "MAX_VERTEX_ATTRIBS",
    "MAX_VARYING_VECTORS",
    "MAX_VERTEX_UNIFORM_VECTORS",
    "MAX_FRAGMENT_UNIFORM_VECTORS"
  ]);
  var DEVICE_PROPERTIES = /* @__PURE__ */ new Set([
    "screen.width",
    "screen.height",
    "screen.availWidth",
    "screen.availHeight",
    "screen.colorDepth",
    "screen.pixelDepth",
    "navigator.hardwareConcurrency",
    "navigator.deviceMemory",
    "navigator.platform",
    "navigator.languages",
    "navigator.plugins",
    "navigator.mimeTypes",
    "navigator.userAgentData"
  ]);
  function classifySignal(event) {
    const subtype = event.subtype || "";
    const evidence = event.evidence || {};
    const api = evidence.api || "";
    const details = evidence.details || evidence;
    const count = event.count || details.count || 1;
    let vectorType = null;
    let vectorGroup = subtype;
    let isUnmaskedGpu = false;
    let isCapabilityCheck = false;
    let isOfflineAudio = false;
    let isFontEnumeration = false;
    let isExfiltration = false;
    let description = "";
    if (subtype === "canvas") {
      vectorGroup = "canvas";
      if (api.includes("toDataURL") || api.includes("toBlob") || api.includes("getImageData")) {
        vectorType = VECTOR_TYPES.CANVAS_READBACK;
        description = `Canvas pixel readback (${api.split(".").pop()})`;
      } else if (api.includes("isPointInPath")) {
        vectorType = VECTOR_TYPES.CANVAS_GEOMETRY;
        description = "Canvas geometry hit testing";
      } else {
        vectorType = VECTOR_TYPES.CANVAS_READBACK;
        description = `Canvas access (${api})`;
      }
    } else if (subtype === "webgl") {
      vectorGroup = "webgl";
      const param = details.param || details.paramName;
      const extension = details.extension || "";
      if (WEBGL_UNMASKED_PARAMS.has(param) || extension === "WEBGL_debug_renderer_info" || String(param).includes("UNMASKED")) {
        vectorType = VECTOR_TYPES.WEBGL_UNMASKED_GPU;
        isUnmaskedGpu = true;
        description = "WebGL unmasked GPU hardware query (debug renderer info)";
      } else if (api.includes("readPixels")) {
        vectorType = VECTOR_TYPES.WEBGL_PIXEL_READBACK;
        description = "WebGL 3D rendered pixel readback";
      } else if (WEBGL_CAPABILITY_PARAMS.has(param)) {
        vectorType = VECTOR_TYPES.WEBGL_CAPABILITY_PARAM;
        isCapabilityCheck = true;
        description = `WebGL capability parameter check (${details.paramName || param})`;
      } else if (api.includes("getParameter") || api.includes("getExtension")) {
        vectorType = VECTOR_TYPES.WEBGL_GENERIC_PARAM;
        description = `WebGL parameter query (${details.paramName || details.extension || api})`;
      } else {
        vectorType = VECTOR_TYPES.WEBGL_GENERIC_PARAM;
        description = `WebGL access (${api})`;
      }
    } else if (subtype === "audio") {
      vectorGroup = "audio";
      if (api.includes("OfflineAudioContext") || api.includes("startRendering")) {
        vectorType = VECTOR_TYPES.AUDIO_OFFLINE_RENDER;
        isOfflineAudio = true;
        description = "Silent OfflineAudioContext rendering (hardware audio fingerprinting)";
      } else if (api.includes("createDynamicsCompressor") || api.includes("createOscillator")) {
        vectorType = VECTOR_TYPES.AUDIO_COMPRESSOR_OSC;
        description = `Audio node pipeline (${api.split(".").pop()})`;
      } else if (api.includes("getFloatFrequencyData") || api.includes("createAnalyser")) {
        vectorType = VECTOR_TYPES.AUDIO_ANALYSER;
        description = `Audio frequency analysis (${api.split(".").pop()})`;
      } else {
        vectorType = VECTOR_TYPES.AUDIO_BASIC_NODE;
        description = `AudioContext access (${api})`;
      }
    } else if (subtype === "font") {
      vectorGroup = "font";
      if (count > 3 || api.includes("FontFaceSet.check") || api.includes("FontFaceSet.load")) {
        vectorType = count > 3 ? VECTOR_TYPES.FONT_ENUMERATION : VECTOR_TYPES.FONT_SINGLE_CHECK;
        isFontEnumeration = count > 3;
        description = count > 3 ? `Rapid font enumeration (${count} fonts checked)` : `Font availability check (${details.font || "font"})`;
      } else {
        vectorType = VECTOR_TYPES.FONT_SINGLE_CHECK;
        description = `Font access (${api})`;
      }
    } else if (subtype === "beacon") {
      vectorGroup = "beacon";
      vectorType = VECTOR_TYPES.BEACON_EXFILTRATION;
      isExfiltration = true;
      description = `Outbound network transmission (${api})`;
    } else if (subtype === "storage") {
      if (DEVICE_PROPERTIES.has(api) || api.startsWith("screen.") || api.startsWith("navigator.")) {
        vectorGroup = "device";
        vectorType = count > 3 ? VECTOR_TYPES.DEVICE_ATTR_SWEEP : VECTOR_TYPES.DEVICE_SINGLE_ATTR;
        description = `Device environment attribute (${api})`;
      } else if (api.includes("cookie") || api.includes("Storage") || api.includes("IDBFactory")) {
        vectorGroup = "storage";
        vectorType = VECTOR_TYPES.STORAGE_SINGLE;
        description = `Client storage access (${api})`;
      } else {
        vectorGroup = "storage";
        vectorType = VECTOR_TYPES.STORAGE_SINGLE;
        description = `Storage access (${api})`;
      }
    } else {
      vectorGroup = subtype || "other";
      vectorType = VECTOR_TYPES.STORAGE_SINGLE;
      description = `API access (${api || subtype})`;
    }
    let multiplier = PROBING_MULTIPLIERS.SINGLE_BURST;
    if (count > 5) {
      multiplier = PROBING_MULTIPLIERS.HIGH_RATE_PROBE;
    } else if (count >= 2) {
      multiplier = PROBING_MULTIPLIERS.MODERATE_BURST;
    }
    const baseWeight = BASE_WEIGHTS[vectorType] || 1;
    const effectiveWeight = baseWeight * multiplier;
    return {
      vectorType,
      vectorGroup,
      baseWeight,
      multiplier,
      effectiveWeight,
      count,
      isUnmaskedGpu,
      isCapabilityCheck,
      isOfflineAudio,
      isFontEnumeration,
      isExfiltration,
      description,
      api
    };
  }

  // detection/confidence-engine.js
  var CORRELATION_WINDOW_MS = 1e4;
  var ConfidenceEngine = class {
    constructor(windowMs = CORRELATION_WINDOW_MS) {
      this.windowMs = windowMs;
      this.sessions = /* @__PURE__ */ new Map();
    }
    /**
     * Generates a correlation lookup key for a script context.
     */
    _sessionKey(site, tabId, scriptUrl) {
      return `${site || "unknown"}:${tabId ?? "0"}:${scriptUrl || "inline"}`;
    }
    /**
     * Retrieves or initializes the correlation session record for a script.
     */
    _getSession(site, tabId, scriptUrl, now = Date.now()) {
      const key = this._sessionKey(site, tabId, scriptUrl);
      let session = this.sessions.get(key);
      if (!session || now - session.lastUpdated > this.windowMs) {
        session = {
          key,
          site,
          tabId,
          scriptUrl,
          firstSeen: now,
          lastUpdated: now,
          vectorGroups: /* @__PURE__ */ new Set(),
          vectorTypes: /* @__PURE__ */ new Set(),
          signals: [],
          deviceAttrs: /* @__PURE__ */ new Set(),
          fontCount: 0,
          storageTypes: /* @__PURE__ */ new Set(),
          hasExfiltration: false,
          hasUnmaskedGpu: false,
          hasOfflineAudio: false,
          exfiltrationTargets: /* @__PURE__ */ new Set(),
          totalWeight: 0
        };
        this.sessions.set(key, session);
      } else {
        session.lastUpdated = now;
      }
      return session;
    }
    /**
     * Cleans up expired sessions from memory.
     */
    pruneStaleSessions(now = Date.now()) {
      for (const [key, session] of this.sessions.entries()) {
        if (now - session.lastUpdated > this.windowMs) {
          this.sessions.delete(key);
        }
      }
    }
    /**
     * Updates a session with a newly classified signal and recalculates accumulated state.
     */
    _recordSignal(session, signal, rawEvidence = {}) {
      session.vectorGroups.add(signal.vectorGroup);
      session.vectorTypes.add(signal.vectorType);
      session.signals.push({
        vectorType: signal.vectorType,
        vectorGroup: signal.vectorGroup,
        api: signal.api,
        weight: signal.effectiveWeight,
        count: signal.count,
        timestamp: Date.now()
      });
      if (signal.isUnmaskedGpu) session.hasUnmaskedGpu = true;
      if (signal.isOfflineAudio) session.hasOfflineAudio = true;
      if (signal.isExfiltration) {
        session.hasExfiltration = true;
        const targetDomain = rawEvidence.targetDomain || rawEvidence.domain;
        if (targetDomain) session.exfiltrationTargets.add(targetDomain);
      }
      if (signal.vectorGroup === "device") {
        session.deviceAttrs.add(signal.api);
      }
      if (signal.vectorGroup === "font") {
        session.fontCount += signal.count || 1;
      }
      if (signal.vectorGroup === "storage") {
        session.storageTypes.add(signal.api);
      }
      let accumulatedWeight = 0;
      const groupMaxWeights = /* @__PURE__ */ new Map();
      for (const sig of session.signals) {
        const current = groupMaxWeights.get(sig.vectorGroup) || 0;
        const additional = Math.max(0, sig.weight - current * 0.4);
        groupMaxWeights.set(sig.vectorGroup, Math.min(8, current + additional));
      }
      for (const weight of groupMaxWeights.values()) {
        accumulatedWeight += weight;
      }
      if (session.deviceAttrs.size >= 3) {
        accumulatedWeight += BASE_WEIGHTS[VECTOR_TYPES.DEVICE_ATTR_SWEEP];
      }
      if (session.fontCount >= 5) {
        accumulatedWeight += BASE_WEIGHTS[VECTOR_TYPES.FONT_ENUMERATION];
      }
      session.totalWeight = accumulatedWeight;
    }
    /**
     * Synthesizes forensic explanation notes based on active vectors.
     */
    _buildForensicNotes(session, currentSignal) {
      const vectorNames = Array.from(session.vectorGroups);
      const parts = [];
      if (session.hasExfiltration && vectorNames.length >= 2) {
        const targets = session.exfiltrationTargets.size > 0 ? ` -> [${Array.from(session.exfiltrationTargets).join(", ")}]` : "";
        parts.push(`Active Multi-Vector Exfiltration Chain${targets}`);
      }
      const vectorDetails = [];
      if (session.vectorGroups.has("canvas")) vectorDetails.push("Canvas");
      if (session.hasUnmaskedGpu) {
        vectorDetails.push("WebGL (Unmasked GPU)");
      } else if (session.vectorGroups.has("webgl")) {
        vectorDetails.push(currentSignal.isCapabilityCheck ? "WebGL (Capability)" : "WebGL");
      }
      if (session.hasOfflineAudio) {
        vectorDetails.push("Offline AudioContext");
      } else if (session.vectorGroups.has("audio")) {
        vectorDetails.push("AudioContext");
      }
      if (session.fontCount >= 5) {
        vectorDetails.push(`Fonts (${session.fontCount} probed)`);
      } else if (session.vectorGroups.has("font")) {
        vectorDetails.push("Font Check");
      }
      if (session.deviceAttrs.size >= 3) {
        vectorDetails.push(`Device Sweep (${session.deviceAttrs.size} attrs)`);
      } else if (session.vectorGroups.has("device")) {
        vectorDetails.push("Device Property");
      }
      if (session.vectorGroups.has("storage")) vectorDetails.push("Storage");
      if (vectorDetails.length > 0) {
        parts.push(`Vectors: ${vectorDetails.join(" + ")}`);
      }
      if (parts.length === 0) {
        return currentSignal.description || "API access";
      }
      return parts.join(" | ");
    }
    /**
     * Evaluates a single draft or event, updating script session state and computing confidence.
     *
     * @param {Object} draft - Raw draft event
     * @param {Object} context - { topSite, tabId }
     * @returns {Object} Final canonical TrackingEvent
     */
    evaluateEvent(draft, { topSite, tabId }) {
      const scriptUrl = draft.source?.script || "inline";
      const session = this._getSession(topSite, tabId, scriptUrl);
      const signal = classifySignal(draft);
      const rawEvidence = {
        ...draft.evidence?.details || draft.evidence || {},
        targetDomain: draft.target?.domain
      };
      this._recordSignal(session, signal, rawEvidence);
      const { confidence, severity } = calculateConfidenceScore({
        totalWeight: session.totalWeight,
        vectorCount: session.vectorGroups.size,
        hasExfiltration: session.hasExfiltration,
        hasUnmaskedGpu: session.hasUnmaskedGpu,
        hasOfflineAudio: session.hasOfflineAudio
      });
      const forensicNotes = this._buildForensicNotes(session, signal);
      const apiName = draft.evidence?.api || signal.api;
      const count = draft.count || 1;
      const details = draft.evidence?.details ?? (draft.evidence ? { ...draft.evidence } : {});
      delete details.api;
      delete details.count;
      const flattenedEvidence = {
        api: apiName,
        ...details,
        ...count > 1 ? { count } : {},
        correlatedVectors: Array.from(session.vectorGroups),
        forensicNotes
      };
      return createTrackingEvent({
        tabId,
        site: topSite,
        category: draft.category || "fingerprinting",
        subtype: draft.subtype,
        source: draft.source || { script: scriptUrl },
        target: draft.target || {},
        evidence: flattenedEvidence,
        severity,
        confidence
      });
    }
    /**
     * Evaluates an entire batch of drafts (from content-bridge.js) in sequence.
     *
     * @param {Array<Object>} drafts
     * @param {Object} context - { topSite, tabId }
     * @returns {Array<Object>} Array of canonical TrackingEvents with refined confidence
     */
    evaluateBatch(drafts, { topSite, tabId }) {
      if (!Array.isArray(drafts) || drafts.length === 0) return [];
      return drafts.map((draft) => this.evaluateEvent(draft, { topSite, tabId }));
    }
    /**
     * Resets all internal session state (useful for test isolation).
     */
    resetState() {
      this.sessions.clear();
    }
    /**
     * Drops correlation sessions belonging to one tab, e.g. on navigation,
     * so leftover signal state from the previous page doesn't bleed into
     * the new page's vector-count / totalWeight calculations.
     */
    resetForTab(tabId) {
      for (const [key, session] of this.sessions.entries()) {
        if (session.tabId === tabId) {
          this.sessions.delete(key);
        }
      }
    }
    /**
     * Gets current correlation state for a script.
     */
    getSession(site, tabId, scriptUrl) {
      const key = this._sessionKey(site, tabId, scriptUrl);
      return this.sessions.get(key) || null;
    }
  };
  var confidenceEngine = new ConfidenceEngine();

  // background.js
  initInterceptor();
  chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true }).catch(() => {
  });
  chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    clearEventsForTab(details.tabId).catch(
      (err) => console.error("[PrivacyLens] failed to clear events for tab", err)
    );
    confidenceEngine.resetForTab(details.tabId);
  });
  function finalizeFingerprintDraft(draft, topSite, tabId) {
    return confidenceEngine.evaluateEvent(draft, { topSite, tabId });
  }
  async function getTopSiteForSenderTab(tab) {
    try {
      if (!tab?.url) return null;
      const url = new URL(tab.url);
      if (url.protocol === "file:") return "local-file";
      return getRegistrableDomain(url.hostname) || null;
    } catch {
      return null;
    }
  }
  chrome.runtime.onMessage.addListener((message, sender) => {
    if (!message?.type) return;
    if (message.type === MESSAGE_TYPES.BATCH_EVENTS) {
      const drafts = message.payload ?? message.events ?? [];
      (async () => {
        const topSite = await getTopSiteForSenderTab(sender.tab);
        const tabId = sender.tab?.id ?? null;
        if (!topSite) return;
        for (const draft of drafts) {
          try {
            const event = finalizeFingerprintDraft(draft, topSite, tabId);
            await appendEvent(event);
          } catch (err) {
            console.error("[PrivacyLens] failed to finalize fingerprint event", err, draft);
          }
        }
      })();
      return;
    }
    if (message.type === MESSAGE_TYPES.TRACKING_EVENT) {
      (async () => {
        const topSite = await getTopSiteForSenderTab(sender.tab);
        const tabId = sender.tab?.id ?? null;
        if (!topSite || !message.event) return;
        try {
          const event = finalizeFingerprintDraft(message.event, topSite, tabId);
          await appendEvent(event);
        } catch (err) {
          console.error("[PrivacyLens] failed to finalize fingerprint event", err, message.event);
        }
      })();
    }
  });
  console.log("[PrivacyLens] background worker started, network interceptor + fingerprint ingestion active");
})();
//# sourceMappingURL=background.bundle.js.map
