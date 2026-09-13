/**
 * Privacy Lens - Font Fingerprint Detector
 * Owner: Person 2 (Browser Forensics)
 * 
 * Phase 12-18: Tier 2 MAIN-world Hooks
 * 
 * Hooks:
 * - document.fonts.check (FontFaceSet.prototype.check)
 * - document.fonts.load (FontFaceSet.prototype.load)
 * - FontFace constructor / queries
 */

export function initFontHooks() {
  if (typeof window === 'undefined') return;

  const emit = (api, details = {}) => {
    if (typeof window.__PL_report === 'function') {
      window.__PL_report('font', { api, ...details });
    }
  };

  // 1. document.fonts (FontFaceSet) hooks
  if (typeof document !== 'undefined' && document.fonts) {
    if (typeof document.fonts.check === 'function') {
      const origCheck = document.fonts.check.bind(document.fonts);
      document.fonts.check = function(...args) {
        emit('FontFaceSet.check', { font: String(args[0] || ''), text: args[1] });
        return origCheck(...args);
      };
    }

    if (typeof document.fonts.load === 'function') {
      const origLoad = document.fonts.load.bind(document.fonts);
      document.fonts.load = function(...args) {
        emit('FontFaceSet.load', { font: String(args[0] || ''), text: args[1] });
        return origLoad(...args);
      };
    }
  }

  // 2. FontFace constructor detection
  if (typeof window.FontFace !== 'undefined') {
    const OrigFontFace = window.FontFace;
    try {
      window.FontFace = function(family, source, descriptors) {
        emit('FontFace.constructor', { family: String(family) });
        return new OrigFontFace(family, source, descriptors);
      };
      window.FontFace.prototype = OrigFontFace.prototype;
    } catch (err) {
      // Ignore if FontFace constructor is non-configurable
    }
  }
}
