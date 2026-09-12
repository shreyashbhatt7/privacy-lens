/**
 * Privacy Lens - AudioContext Fingerprint Detector
 * Owner: Person 2 (Browser Forensics)
 * 
 * Phase 2-12: Tier 1 MAIN-world Hooks
 * 
 * Hooks:
 * - AudioContext.prototype.createOscillator
 * - AudioContext.prototype.createAnalyser
 * - AudioContext.prototype.createDynamicsCompressor
 * - OfflineAudioContext.prototype.startRendering
 * - AudioBufferSourceNode.prototype.start
 * - AnalyserNode.prototype.getFloatFrequencyData
 */

export function initAudioHooks() {
  if (typeof window === 'undefined') return;

  const emit = (api, details = {}) => {
    if (typeof window.__PL_report === 'function') {
      window.__PL_report('audio', { api, ...details });
    }
  };

  const hookAudioCtx = (CtxClass, className) => {
    if (typeof CtxClass === 'undefined' || !CtxClass.prototype) return;

    // 1. createOscillator
    const origCreateOscillator = CtxClass.prototype.createOscillator;
    if (origCreateOscillator) {
      CtxClass.prototype.createOscillator = function(...args) {
        emit(`${className}.createOscillator`);
        return origCreateOscillator.apply(this, args);
      };
    }

    // 2. createAnalyser
    const origCreateAnalyser = CtxClass.prototype.createAnalyser;
    if (origCreateAnalyser) {
      CtxClass.prototype.createAnalyser = function(...args) {
        emit(`${className}.createAnalyser`);
        return origCreateAnalyser.apply(this, args);
      };
    }

    // 3. createDynamicsCompressor
    const origCreateCompressor = CtxClass.prototype.createDynamicsCompressor;
    if (origCreateCompressor) {
      CtxClass.prototype.createDynamicsCompressor = function(...args) {
        emit(`${className}.createDynamicsCompressor`);
        return origCreateCompressor.apply(this, args);
      };
    }
  };

  // Standard and webkit prefixed AudioContext
  if (typeof AudioContext !== 'undefined') {
    hookAudioCtx(AudioContext, 'AudioContext');
  }
  if (typeof webkitAudioContext !== 'undefined') {
    hookAudioCtx(webkitAudioContext, 'webkitAudioContext');
  }

  // OfflineAudioContext
  const hookOfflineCtx = (OfflineClass, className) => {
    if (typeof OfflineClass === 'undefined' || !OfflineClass.prototype) return;
    const origStartRendering = OfflineClass.prototype.startRendering;
    if (origStartRendering) {
      OfflineClass.prototype.startRendering = function(...args) {
        emit(`${className}.startRendering`);
        return origStartRendering.apply(this, args);
      };
    }
  };

  if (typeof OfflineAudioContext !== 'undefined') {
    hookOfflineCtx(OfflineAudioContext, 'OfflineAudioContext');
  }
  if (typeof webkitOfflineAudioContext !== 'undefined') {
    hookOfflineCtx(webkitOfflineAudioContext, 'webkitOfflineAudioContext');
  }

  // AudioBufferSourceNode.prototype.start
  if (typeof AudioBufferSourceNode !== 'undefined' && AudioBufferSourceNode.prototype) {
    const origStart = AudioBufferSourceNode.prototype.start;
    if (origStart) {
      AudioBufferSourceNode.prototype.start = function(...args) {
        emit('AudioBufferSourceNode.start');
        return origStart.apply(this, args);
      };
    }
  }

  // AnalyserNode.prototype.getFloatFrequencyData
  if (typeof AnalyserNode !== 'undefined' && AnalyserNode.prototype) {
    const origGetFloatFreq = AnalyserNode.prototype.getFloatFrequencyData;
    if (origGetFloatFreq) {
      AnalyserNode.prototype.getFloatFrequencyData = function(...args) {
        emit('AnalyserNode.getFloatFrequencyData');
        return origGetFloatFreq.apply(this, args);
      };
    }
  }
}
