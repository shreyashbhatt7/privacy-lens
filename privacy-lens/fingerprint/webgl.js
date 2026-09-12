/**
 * Privacy Lens - WebGL Fingerprint Detector
 * Owner: Person 2 (Browser Forensics)
 * 
 * Phase 2-12: Tier 1 MAIN-world Hooks
 * 
 * Hooks:
 * - WebGLRenderingContext.prototype.getParameter
 * - WebGL2RenderingContext.prototype.getParameter
 * - WebGLRenderingContext.prototype.getExtension
 * - WebGL2RenderingContext.prototype.getExtension
 * - WebGLRenderingContext.prototype.readPixels
 * 
 * Note: Never assign severity here. WebGL parameter queries are common in legitimate
 * apps; raw evidence is collected and passed to Person 3's correlation engine.
 */

export function initWebGLHooks() {
  if (typeof window === 'undefined') return;

  const emit = (api, details = {}) => {
    if (typeof window.__PL_report === 'function') {
      window.__PL_report('webgl', { api, ...details });
    }
  };

  // Helper mapping for common WebGL fingerprinting parameter enums
  const GL_PARAM_NAMES = {
    0x1F00: 'VENDOR',
    0x1F01: 'RENDERER',
    0x1F02: 'VERSION',
    0x1F03: 'SHADING_LANGUAGE_VERSION',
    0x0D33: 'MAX_TEXTURE_SIZE',
    0x8869: 'MAX_VERTEX_ATTRIBS',
    0x8DF8: 'MAX_VARYING_VECTORS',
    0x8DFB: 'MAX_VERTEX_UNIFORM_VECTORS',
    0x8DFD: 'MAX_FRAGMENT_UNIFORM_VECTORS',
    0x9245: 'UNMASKED_VENDOR_WEBGL',
    0x9246: 'UNMASKED_RENDERER_WEBGL'
  };

  const hookContext = (ContextClass, className) => {
    if (typeof ContextClass === 'undefined' || !ContextClass.prototype) return;

    // 1. getParameter
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

    // 2. getExtension
    const origGetExtension = ContextClass.prototype.getExtension;
    if (origGetExtension) {
      ContextClass.prototype.getExtension = function(name) {
        emit(`${className}.getExtension`, {
          extension: String(name)
        });
        return origGetExtension.call(this, name);
      };
    }

    // 3. readPixels
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

  if (typeof WebGLRenderingContext !== 'undefined') {
    hookContext(WebGLRenderingContext, 'WebGLRenderingContext');
  }

  if (typeof WebGL2RenderingContext !== 'undefined') {
    hookContext(WebGL2RenderingContext, 'WebGL2RenderingContext');
  }
}
