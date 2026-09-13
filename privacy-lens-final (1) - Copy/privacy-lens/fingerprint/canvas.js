/**
 * Privacy Lens - Canvas Fingerprint Detector
 * Owner: Person 2 (Browser Forensics)
 * 
 * Phase 2-12: Tier 1 MAIN-world Hooks
 * 
 * Hooks:
 * - HTMLCanvasElement.prototype.toDataURL
 * - HTMLCanvasElement.prototype.toBlob
 * - CanvasRenderingContext2D.prototype.getImageData
 * - CanvasRenderingContext2D.prototype.isPointInPath
 */

export function initCanvasHooks() {
  if (typeof window === 'undefined') return;

  const emit = (api, details = {}) => {
    if (typeof window.__PL_report === 'function') {
      window.__PL_report('canvas', { api, ...details });
    }
  };

  // 1. HTMLCanvasElement.prototype.toDataURL
  if (typeof HTMLCanvasElement !== 'undefined' && HTMLCanvasElement.prototype) {
    const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    if (origToDataURL) {
      HTMLCanvasElement.prototype.toDataURL = function(...args) {
        emit('HTMLCanvasElement.toDataURL', {
          format: args[0] || 'image/png'
        });
        return origToDataURL.apply(this, args);
      };
    }

    // 2. HTMLCanvasElement.prototype.toBlob
    const origToBlob = HTMLCanvasElement.prototype.toBlob;
    if (origToBlob) {
      HTMLCanvasElement.prototype.toBlob = function(...args) {
        emit('HTMLCanvasElement.toBlob', {
          format: args[1] || 'image/png'
        });
        return origToBlob.apply(this, args);
      };
    }
  }

  // 3. CanvasRenderingContext2D.prototype.getImageData
  if (typeof CanvasRenderingContext2D !== 'undefined' && CanvasRenderingContext2D.prototype) {
    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    if (origGetImageData) {
      CanvasRenderingContext2D.prototype.getImageData = function(...args) {
        emit('CanvasRenderingContext2D.getImageData', {
          sx: args[0],
          sy: args[1],
          sw: args[2],
          sh: args[3]
        });
        return origGetImageData.apply(this, args);
      };
    }

    // 4. CanvasRenderingContext2D.prototype.isPointInPath
    const origIsPointInPath = CanvasRenderingContext2D.prototype.isPointInPath;
    if (origIsPointInPath) {
      CanvasRenderingContext2D.prototype.isPointInPath = function(...args) {
        emit('CanvasRenderingContext2D.isPointInPath');
        return origIsPointInPath.apply(this, args);
      };
    }
  }
}
