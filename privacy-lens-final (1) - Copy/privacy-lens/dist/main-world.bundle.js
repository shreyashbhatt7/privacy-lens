(() => {
  // shared/constants.js
  var MESSAGE_SOURCES = {
    MAIN_WORLD: "PRIVACY_LENS_MAIN_WORLD",
    CONTENT_SCRIPT: "PRIVACY_LENS_CONTENT_SCRIPT",
    BACKGROUND_BUS: "PRIVACY_LENS_BACKGROUND_BUS"
  };

  // shared/events.js
  function parseScriptFromStack(stack) {
    if (!stack || typeof stack !== "string") return "inline";
    const lines = stack.split("\n").slice(1);
    for (const line of lines) {
      if (line.includes("main-world.bundle") || line.includes("main-world.js") || line.includes("content-bridge")) {
        continue;
      }
      const match = line.match(/(https?:\/\/[^\s\)\:]+|file:\/\/[^\s\)\:]+)(?::\d+)?(?::\d+)?/);
      if (match && match[1]) {
        return match[1];
      }
    }
    return "inline";
  }
  function extractDomain(urlStr) {
    if (!urlStr || typeof urlStr !== "string") return void 0;
    try {
      const base = typeof window !== "undefined" && window.location?.href ? window.location.href : "http://localhost";
      const parsed = new URL(urlStr, base);
      return parsed.hostname || void 0;
    } catch (err) {
      return void 0;
    }
  }
  function createFingerprintDraft({
    subtype,
    script = void 0,
    stack = "",
    api,
    details = {},
    targetDomain = void 0
  }) {
    const resolvedScript = script || (stack ? parseScriptFromStack(stack) : "inline");
    return {
      category: "fingerprinting",
      subtype,
      source: {
        script: resolvedScript
      },
      target: targetDomain ? { domain: targetDomain } : void 0,
      evidence: {
        api,
        details: details || {}
      },
      timestamp: Date.now(),
      severity: "low",
      confidence: 0
      // Placeholder: Person 2 does NOT set confidence, Person 3 calculates in correlation engine
    };
  }

  // fingerprint/canvas.js
  function initCanvasHooks() {
    if (typeof window === "undefined") return;
    const emit = (api, details = {}) => {
      if (typeof window.__PL_report === "function") {
        window.__PL_report("canvas", { api, ...details });
      }
    };
    if (typeof HTMLCanvasElement !== "undefined" && HTMLCanvasElement.prototype) {
      const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
      if (origToDataURL) {
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
          emit("HTMLCanvasElement.toDataURL", {
            format: args[0] || "image/png"
          });
          return origToDataURL.apply(this, args);
        };
      }
      const origToBlob = HTMLCanvasElement.prototype.toBlob;
      if (origToBlob) {
        HTMLCanvasElement.prototype.toBlob = function(...args) {
          emit("HTMLCanvasElement.toBlob", {
            format: args[1] || "image/png"
          });
          return origToBlob.apply(this, args);
        };
      }
    }
    if (typeof CanvasRenderingContext2D !== "undefined" && CanvasRenderingContext2D.prototype) {
      const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
      if (origGetImageData) {
        CanvasRenderingContext2D.prototype.getImageData = function(...args) {
          emit("CanvasRenderingContext2D.getImageData", {
            sx: args[0],
            sy: args[1],
            sw: args[2],
            sh: args[3]
          });
          return origGetImageData.apply(this, args);
        };
      }
      const origIsPointInPath = CanvasRenderingContext2D.prototype.isPointInPath;
      if (origIsPointInPath) {
        CanvasRenderingContext2D.prototype.isPointInPath = function(...args) {
          emit("CanvasRenderingContext2D.isPointInPath");
          return origIsPointInPath.apply(this, args);
        };
      }
    }
  }

  // fingerprint/webgl.js
  function initWebGLHooks() {
    if (typeof window === "undefined") return;
    const emit = (api, details = {}) => {
      if (typeof window.__PL_report === "function") {
        window.__PL_report("webgl", { api, ...details });
      }
    };
    const GL_PARAM_NAMES = {
      7936: "VENDOR",
      7937: "RENDERER",
      7938: "VERSION",
      7939: "SHADING_LANGUAGE_VERSION",
      3379: "MAX_TEXTURE_SIZE",
      34921: "MAX_VERTEX_ATTRIBS",
      36344: "MAX_VARYING_VECTORS",
      36347: "MAX_VERTEX_UNIFORM_VECTORS",
      36349: "MAX_FRAGMENT_UNIFORM_VECTORS",
      37445: "UNMASKED_VENDOR_WEBGL",
      37446: "UNMASKED_RENDERER_WEBGL"
    };
    const hookContext = (ContextClass, className) => {
      if (typeof ContextClass === "undefined" || !ContextClass.prototype) return;
      const origGetParameter = ContextClass.prototype.getParameter;
      if (origGetParameter) {
        ContextClass.prototype.getParameter = function(param) {
          const paramName = GL_PARAM_NAMES[param] || String(param);
          emit(`${className}.getParameter`, {
            param,
            paramName
          });
          return origGetParameter.call(this, param);
        };
      }
      const origGetExtension = ContextClass.prototype.getExtension;
      if (origGetExtension) {
        ContextClass.prototype.getExtension = function(name) {
          emit(`${className}.getExtension`, {
            extension: String(name)
          });
          return origGetExtension.call(this, name);
        };
      }
      const origReadPixels = ContextClass.prototype.readPixels;
      if (origReadPixels) {
        ContextClass.prototype.readPixels = function(...args) {
          emit(`${className}.readPixels`, {
            x: args[0],
            y: args[1],
            width: args[2],
            height: args[3]
          });
          return origReadPixels.apply(this, args);
        };
      }
    };
    if (typeof WebGLRenderingContext !== "undefined") {
      hookContext(WebGLRenderingContext, "WebGLRenderingContext");
    }
    if (typeof WebGL2RenderingContext !== "undefined") {
      hookContext(WebGL2RenderingContext, "WebGL2RenderingContext");
    }
  }

  // fingerprint/audio.js
  function initAudioHooks() {
    if (typeof window === "undefined") return;
    const emit = (api, details = {}) => {
      if (typeof window.__PL_report === "function") {
        window.__PL_report("audio", { api, ...details });
      }
    };
    const hookAudioCtx = (CtxClass, className) => {
      if (typeof CtxClass === "undefined" || !CtxClass.prototype) return;
      const origCreateOscillator = CtxClass.prototype.createOscillator;
      if (origCreateOscillator) {
        CtxClass.prototype.createOscillator = function(...args) {
          emit(`${className}.createOscillator`);
          return origCreateOscillator.apply(this, args);
        };
      }
      const origCreateAnalyser = CtxClass.prototype.createAnalyser;
      if (origCreateAnalyser) {
        CtxClass.prototype.createAnalyser = function(...args) {
          emit(`${className}.createAnalyser`);
          return origCreateAnalyser.apply(this, args);
        };
      }
      const origCreateCompressor = CtxClass.prototype.createDynamicsCompressor;
      if (origCreateCompressor) {
        CtxClass.prototype.createDynamicsCompressor = function(...args) {
          emit(`${className}.createDynamicsCompressor`);
          return origCreateCompressor.apply(this, args);
        };
      }
    };
    if (typeof AudioContext !== "undefined") {
      hookAudioCtx(AudioContext, "AudioContext");
    }
    if (typeof webkitAudioContext !== "undefined") {
      hookAudioCtx(webkitAudioContext, "webkitAudioContext");
    }
    const hookOfflineCtx = (OfflineClass, className) => {
      if (typeof OfflineClass === "undefined" || !OfflineClass.prototype) return;
      const origStartRendering = OfflineClass.prototype.startRendering;
      if (origStartRendering) {
        OfflineClass.prototype.startRendering = function(...args) {
          emit(`${className}.startRendering`);
          return origStartRendering.apply(this, args);
        };
      }
    };
    if (typeof OfflineAudioContext !== "undefined") {
      hookOfflineCtx(OfflineAudioContext, "OfflineAudioContext");
    }
    if (typeof webkitOfflineAudioContext !== "undefined") {
      hookOfflineCtx(webkitOfflineAudioContext, "webkitOfflineAudioContext");
    }
    if (typeof AudioBufferSourceNode !== "undefined" && AudioBufferSourceNode.prototype) {
      const origStart = AudioBufferSourceNode.prototype.start;
      if (origStart) {
        AudioBufferSourceNode.prototype.start = function(...args) {
          emit("AudioBufferSourceNode.start");
          return origStart.apply(this, args);
        };
      }
    }
    if (typeof AnalyserNode !== "undefined" && AnalyserNode.prototype) {
      const origGetFloatFreq = AnalyserNode.prototype.getFloatFrequencyData;
      if (origGetFloatFreq) {
        AnalyserNode.prototype.getFloatFrequencyData = function(...args) {
          emit("AnalyserNode.getFloatFrequencyData");
          return origGetFloatFreq.apply(this, args);
        };
      }
    }
  }

  // fingerprint/storage.js
  function initStorageHooks() {
    if (typeof window === "undefined") return;
    const emit = (subtype, api, details = {}) => {
      if (typeof window.__PL_report === "function") {
        window.__PL_report(subtype, { api, ...details });
      }
    };
    try {
      const proto = typeof Document !== "undefined" && Object.getOwnPropertyDescriptor(Document.prototype, "cookie") ? Document.prototype : typeof HTMLDocument !== "undefined" && Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie") ? HTMLDocument.prototype : null;
      if (proto) {
        const cookieDesc = Object.getOwnPropertyDescriptor(proto, "cookie");
        if (cookieDesc && cookieDesc.configurable) {
          Object.defineProperty(proto, "cookie", {
            get() {
              emit("storage", "document.cookie:get");
              return cookieDesc.get ? cookieDesc.get.call(this) : "";
            },
            set(val) {
              emit("storage", "document.cookie:set", {
                key: String(val).split("=")[0]?.trim()
              });
              if (cookieDesc.set) {
                return cookieDesc.set.call(this, val);
              }
            },
            configurable: true,
            enumerable: true
          });
        }
      }
    } catch (err) {
      console.debug("[PrivacyLens] cookie hook error:", err);
    }
    if (typeof Storage !== "undefined" && Storage.prototype) {
      const origGetItem = Storage.prototype.getItem;
      if (origGetItem) {
        Storage.prototype.getItem = function(key) {
          emit("storage", "Storage.getItem", { key: String(key) });
          return origGetItem.call(this, key);
        };
      }
      const origSetItem = Storage.prototype.setItem;
      if (origSetItem) {
        Storage.prototype.setItem = function(key, value) {
          emit("storage", "Storage.setItem", { key: String(key) });
          return origSetItem.call(this, key, value);
        };
      }
    }
    if (typeof navigator !== "undefined" && navigator.sendBeacon) {
      const origSendBeacon = navigator.sendBeacon;
      navigator.sendBeacon = function(url, data) {
        const urlStr = String(url);
        emit("beacon", "navigator.sendBeacon", { url: urlStr });
        return origSendBeacon.call(this, url, data);
      };
    }
    if (typeof window.fetch === "function") {
      const origFetch = window.fetch;
      window.fetch = function(...args) {
        let targetUrl = "";
        if (typeof args[0] === "string") {
          targetUrl = args[0];
        } else if (args[0] && typeof args[0].url === "string") {
          targetUrl = args[0].url;
        }
        if (targetUrl) {
          emit("beacon", "fetch", { url: targetUrl });
        }
        return origFetch.apply(this, args);
      };
    }
    if (typeof XMLHttpRequest !== "undefined" && XMLHttpRequest.prototype) {
      const origXHROpen = XMLHttpRequest.prototype.open;
      if (origXHROpen) {
        XMLHttpRequest.prototype.open = function(method, url, ...rest) {
          emit("beacon", "XMLHttpRequest.open", {
            method: String(method),
            url: String(url)
          });
          return origXHROpen.call(this, method, url, ...rest);
        };
      }
    }
    if (typeof Navigator !== "undefined" && Navigator.prototype) {
      const navProps = ["hardwareConcurrency", "deviceMemory", "userAgent", "platform", "languages", "plugins", "mimeTypes", "userAgentData"];
      navProps.forEach((prop) => {
        try {
          const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
          if (desc && desc.configurable && desc.get) {
            Object.defineProperty(Navigator.prototype, prop, {
              get() {
                emit("storage", `navigator.${prop}`);
                return desc.get.call(this);
              },
              configurable: true,
              enumerable: true
            });
          }
        } catch (err) {
        }
      });
    }
    if (typeof Screen !== "undefined" && Screen.prototype) {
      const screenProps = ["width", "height", "availWidth", "availHeight", "colorDepth", "pixelDepth"];
      screenProps.forEach((prop) => {
        try {
          const desc = Object.getOwnPropertyDescriptor(Screen.prototype, prop);
          if (desc && desc.configurable && desc.get) {
            Object.defineProperty(Screen.prototype, prop, {
              get() {
                emit("storage", `screen.${prop}`);
                return desc.get.call(this);
              },
              configurable: true,
              enumerable: true
            });
          }
        } catch (err) {
        }
      });
    }
    try {
      if (typeof IDBFactory !== "undefined" && IDBFactory.prototype?.open) {
        const origIDBOpen = IDBFactory.prototype.open;
        IDBFactory.prototype.open = function(name, ...args) {
          emit("storage", "IDBFactory.open", { dbName: String(name || "") });
          return origIDBOpen.apply(this, [name, ...args]);
        };
      } else if (typeof window !== "undefined" && window.indexedDB?.open) {
        const origIDBOpen = window.indexedDB.open.bind(window.indexedDB);
        window.indexedDB.open = function(name, ...args) {
          emit("storage", "IDBFactory.open", { dbName: String(name || "") });
          return origIDBOpen(name, ...args);
        };
      }
    } catch (err) {
      console.debug("[PrivacyLens] IDB hook error:", err);
    }
  }

  // fingerprint/fonts.js
  function initFontHooks() {
    if (typeof window === "undefined") return;
    const emit = (api, details = {}) => {
      if (typeof window.__PL_report === "function") {
        window.__PL_report("font", { api, ...details });
      }
    };
    if (typeof document !== "undefined" && document.fonts) {
      if (typeof document.fonts.check === "function") {
        const origCheck = document.fonts.check.bind(document.fonts);
        document.fonts.check = function(...args) {
          emit("FontFaceSet.check", { font: String(args[0] || ""), text: args[1] });
          return origCheck(...args);
        };
      }
      if (typeof document.fonts.load === "function") {
        const origLoad = document.fonts.load.bind(document.fonts);
        document.fonts.load = function(...args) {
          emit("FontFaceSet.load", { font: String(args[0] || ""), text: args[1] });
          return origLoad(...args);
        };
      }
    }
    if (typeof window.FontFace !== "undefined") {
      const OrigFontFace = window.FontFace;
      try {
        window.FontFace = function(family, source, descriptors) {
          emit("FontFace.constructor", { family: String(family) });
          return new OrigFontFace(family, source, descriptors);
        };
        window.FontFace.prototype = OrigFontFace.prototype;
      } catch (err) {
      }
    }
  }

  // fingerprint/main-world.js
  function report(subtype, rawEvidence = {}) {
    try {
      const stack = new Error().stack || "";
      const { api = subtype, url, ...details } = rawEvidence;
      const targetDomain = extractDomain(url);
      const resolvedDetails = url ? { ...details, url } : details;
      const eventDraft = createFingerprintDraft({
        subtype,
        api,
        details: resolvedDetails,
        targetDomain,
        stack
      });
      window.postMessage({
        source: MESSAGE_SOURCES.MAIN_WORLD,
        __privacyLens: true,
        payload: eventDraft,
        event: eventDraft
      }, "*");
    } catch (err) {
      console.debug("[PrivacyLens] report error:", err);
    }
  }
  if (typeof window !== "undefined") {
    window.__PL_report = report;
  }
  (function initializeMainWorldHooks() {
    initCanvasHooks();
    initWebGLHooks();
    initAudioHooks();
    initStorageHooks();
    initFontHooks();
  })();
})();
//# sourceMappingURL=main-world.bundle.js.map
