/**
 * Privacy Lens - Storage, Cookie, Identifier & Network Transmission Hooks
 * Owner: Person 2 (Browser Forensics)
 * 
 * Phase 2-12 & Phase 12-18: Tier 1 & Tier 2 MAIN-world Hooks
 * 
 * Hooks:
 * - document.cookie (getter & setter)
 * - Storage.prototype.getItem & Storage.prototype.setItem (localStorage / sessionStorage)
 * - navigator.sendBeacon (subtype: "beacon")
 * - window.fetch (subtype: "beacon")
 * - XMLHttpRequest.prototype.open (subtype: "beacon")
 * - Navigator properties (userAgent, userAgentData, hardwareConcurrency, deviceMemory, platform, languages, plugins, mimeTypes)
 * - Screen properties (width, height, availWidth, availHeight, colorDepth, pixelDepth)
 * - IDBFactory.prototype.open (IndexedDB database access)
 */

export function initStorageHooks() {
  if (typeof window === 'undefined') return;

  const emit = (subtype, api, details = {}) => {
    if (typeof window.__PL_report === 'function') {
      window.__PL_report(subtype, { api, ...details });
    }
  };

  // 1. document.cookie Getter & Setter
  try {
    const proto = (typeof Document !== 'undefined' && Object.getOwnPropertyDescriptor(Document.prototype, 'cookie'))
      ? Document.prototype
      : (typeof HTMLDocument !== 'undefined' && Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie'))
        ? HTMLDocument.prototype
        : null;

    if (proto) {
      const cookieDesc = Object.getOwnPropertyDescriptor(proto, 'cookie');
      if (cookieDesc && cookieDesc.configurable) {
        Object.defineProperty(proto, 'cookie', {
          get() {
            emit('storage', 'document.cookie:get');
            return cookieDesc.get ? cookieDesc.get.call(this) : '';
          },
          set(val) {
            emit('storage', 'document.cookie:set', {
              key: String(val).split('=')[0]?.trim()
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
    console.debug('[PrivacyLens] cookie hook error:', err);
  }

  // 2. Storage.prototype.getItem & Storage.prototype.setItem
  if (typeof Storage !== 'undefined' && Storage.prototype) {
    const origGetItem = Storage.prototype.getItem;
    if (origGetItem) {
      Storage.prototype.getItem = function(key) {
        emit('storage', 'Storage.getItem', { key: String(key) });
        return origGetItem.call(this, key);
      };
    }

    const origSetItem = Storage.prototype.setItem;
    if (origSetItem) {
      Storage.prototype.setItem = function(key, value) {
        emit('storage', 'Storage.setItem', { key: String(key) });
        return origSetItem.call(this, key, value);
      };
    }
  }

  // 3. navigator.sendBeacon
  if (typeof navigator !== 'undefined' && navigator.sendBeacon) {
    const origSendBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function(url, data) {
      const urlStr = String(url);
      emit('beacon', 'navigator.sendBeacon', { url: urlStr });
      return origSendBeacon.call(this, url, data);
    };
  }

  // 4. window.fetch
  if (typeof window.fetch === 'function') {
    const origFetch = window.fetch;
    window.fetch = function(...args) {
      let targetUrl = '';
      if (typeof args[0] === 'string') {
        targetUrl = args[0];
      } else if (args[0] && typeof args[0].url === 'string') {
        targetUrl = args[0].url;
      }
      if (targetUrl) {
        emit('beacon', 'fetch', { url: targetUrl });
      }
      return origFetch.apply(this, args);
    };
  }

  // 5. XMLHttpRequest.prototype.open
  if (typeof XMLHttpRequest !== 'undefined' && XMLHttpRequest.prototype) {
    const origXHROpen = XMLHttpRequest.prototype.open;
    if (origXHROpen) {
      XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        emit('beacon', 'XMLHttpRequest.open', {
          method: String(method),
          url: String(url)
        });
        return origXHROpen.call(this, method, url, ...rest);
      };
    }
  }

  // 6. Navigator.* properties (hardwareConcurrency, deviceMemory, userAgent, plugins, mimeTypes, userAgentData)
  if (typeof Navigator !== 'undefined' && Navigator.prototype) {
    const navProps = ['hardwareConcurrency', 'deviceMemory', 'userAgent', 'platform', 'languages', 'plugins', 'mimeTypes', 'userAgentData'];
    navProps.forEach((prop) => {
      try {
        const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, prop);
        if (desc && desc.configurable && desc.get) {
          Object.defineProperty(Navigator.prototype, prop, {
            get() {
              emit('storage', `navigator.${prop}`);
              return desc.get.call(this);
            },
            configurable: true,
            enumerable: true
          });
        }
      } catch (err) {
        // Ignore unconfigurable properties
      }
    });
  }

  // 7. Screen properties (width, height, availWidth, availHeight, colorDepth, pixelDepth)
  if (typeof Screen !== 'undefined' && Screen.prototype) {
    const screenProps = ['width', 'height', 'availWidth', 'availHeight', 'colorDepth', 'pixelDepth'];
    screenProps.forEach((prop) => {
      try {
        const desc = Object.getOwnPropertyDescriptor(Screen.prototype, prop);
        if (desc && desc.configurable && desc.get) {
          Object.defineProperty(Screen.prototype, prop, {
            get() {
              emit('storage', `screen.${prop}`);
              return desc.get.call(this);
            },
            configurable: true,
            enumerable: true
          });
        }
      } catch (err) {
        // Ignore unconfigurable properties
      }
    });
  }

  // 8. IndexedDB (IDBFactory.open)
  try {
    if (typeof IDBFactory !== 'undefined' && IDBFactory.prototype?.open) {
      const origIDBOpen = IDBFactory.prototype.open;
      IDBFactory.prototype.open = function(name, ...args) {
        emit('storage', 'IDBFactory.open', { dbName: String(name || '') });
        return origIDBOpen.apply(this, [name, ...args]);
      };
    } else if (typeof window !== 'undefined' && window.indexedDB?.open) {
      const origIDBOpen = window.indexedDB.open.bind(window.indexedDB);
      window.indexedDB.open = function(name, ...args) {
        emit('storage', 'IDBFactory.open', { dbName: String(name || '') });
        return origIDBOpen(name, ...args);
      };
    }
  } catch (err) {
    console.debug('[PrivacyLens] IDB hook error:', err);
  }
}
