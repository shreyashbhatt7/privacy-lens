// detection/classifier.js
//
// Classifies raw API events from fingerprint/*.js into fine-grained threat vectors,
// identifying benign capability checks vs. fingerprinting probes.

import { VECTOR_TYPES, BASE_WEIGHTS, PROBING_MULTIPLIERS } from './scoring.js';

const WEBGL_UNMASKED_PARAMS = new Set([
  0x9245, // UNMASKED_VENDOR_WEBGL
  0x9246, // UNMASKED_RENDERER_WEBGL
  'UNMASKED_VENDOR_WEBGL',
  'UNMASKED_RENDERER_WEBGL'
]);

const WEBGL_CAPABILITY_PARAMS = new Set([
  0x0D33, // MAX_TEXTURE_SIZE
  0x8869, // MAX_VERTEX_ATTRIBS
  0x8DF8, // MAX_VARYING_VECTORS
  0x8DFB, // MAX_VERTEX_UNIFORM_VECTORS
  0x8DFD, // MAX_FRAGMENT_UNIFORM_VECTORS
  'MAX_TEXTURE_SIZE',
  'MAX_VERTEX_ATTRIBS',
  'MAX_VARYING_VECTORS',
  'MAX_VERTEX_UNIFORM_VECTORS',
  'MAX_FRAGMENT_UNIFORM_VECTORS'
]);

const DEVICE_PROPERTIES = new Set([
  'screen.width',
  'screen.height',
  'screen.availWidth',
  'screen.availHeight',
  'screen.colorDepth',
  'screen.pixelDepth',
  'navigator.hardwareConcurrency',
  'navigator.deviceMemory',
  'navigator.platform',
  'navigator.languages',
  'navigator.plugins',
  'navigator.mimeTypes',
  'navigator.userAgentData'
]);

/**
 * Classifies an individual tracking draft or event into a threat vector descriptor.
 *
 * @param {Object} event - Draft or canonical event
 * @returns {Object} Classified signal descriptor
 */
export function classifySignal(event) {
  const subtype = event.subtype || '';
  const evidence = event.evidence || {};
  const api = evidence.api || '';
  const details = evidence.details || evidence; // support both draft (nested) and flat evidence
  const count = event.count || details.count || 1;

  let vectorType = null;
  let vectorGroup = subtype; // high-level group: 'canvas' | 'webgl' | 'audio' | 'font' | 'storage' | 'device' | 'beacon'
  let isUnmaskedGpu = false;
  let isCapabilityCheck = false;
  let isOfflineAudio = false;
  let isFontEnumeration = false;
  let isExfiltration = false;
  let description = '';

  // 1. Canvas Vectors
  if (subtype === 'canvas') {
    vectorGroup = 'canvas';
    if (api.includes('toDataURL') || api.includes('toBlob') || api.includes('getImageData')) {
      vectorType = VECTOR_TYPES.CANVAS_READBACK;
      description = `Canvas pixel readback (${api.split('.').pop()})`;
    } else if (api.includes('isPointInPath')) {
      vectorType = VECTOR_TYPES.CANVAS_GEOMETRY;
      description = 'Canvas geometry hit testing';
    } else {
      vectorType = VECTOR_TYPES.CANVAS_READBACK;
      description = `Canvas access (${api})`;
    }
  }

  // 2. WebGL Vectors
  else if (subtype === 'webgl') {
    vectorGroup = 'webgl';
    const param = details.param || details.paramName;
    const extension = details.extension || '';

    if (
      WEBGL_UNMASKED_PARAMS.has(param) ||
      extension === 'WEBGL_debug_renderer_info' ||
      String(param).includes('UNMASKED')
    ) {
      vectorType = VECTOR_TYPES.WEBGL_UNMASKED_GPU;
      isUnmaskedGpu = true;
      description = 'WebGL unmasked GPU hardware query (debug renderer info)';
    } else if (api.includes('readPixels')) {
      vectorType = VECTOR_TYPES.WEBGL_PIXEL_READBACK;
      description = 'WebGL 3D rendered pixel readback';
    } else if (WEBGL_CAPABILITY_PARAMS.has(param)) {
      vectorType = VECTOR_TYPES.WEBGL_CAPABILITY_PARAM;
      isCapabilityCheck = true;
      description = `WebGL capability parameter check (${details.paramName || param})`;
    } else if (api.includes('getParameter') || api.includes('getExtension')) {
      vectorType = VECTOR_TYPES.WEBGL_GENERIC_PARAM;
      description = `WebGL parameter query (${details.paramName || details.extension || api})`;
    } else {
      vectorType = VECTOR_TYPES.WEBGL_GENERIC_PARAM;
      description = `WebGL access (${api})`;
    }
  }

  // 3. Audio Vectors
  else if (subtype === 'audio') {
    vectorGroup = 'audio';
    if (api.includes('OfflineAudioContext') || api.includes('startRendering')) {
      vectorType = VECTOR_TYPES.AUDIO_OFFLINE_RENDER;
      isOfflineAudio = true;
      description = 'Silent OfflineAudioContext rendering (hardware audio fingerprinting)';
    } else if (api.includes('createDynamicsCompressor') || api.includes('createOscillator')) {
      vectorType = VECTOR_TYPES.AUDIO_COMPRESSOR_OSC;
      description = `Audio node pipeline (${api.split('.').pop()})`;
    } else if (api.includes('getFloatFrequencyData') || api.includes('createAnalyser')) {
      vectorType = VECTOR_TYPES.AUDIO_ANALYSER;
      description = `Audio frequency analysis (${api.split('.').pop()})`;
    } else {
      vectorType = VECTOR_TYPES.AUDIO_BASIC_NODE;
      description = `AudioContext access (${api})`;
    }
  }

  // 4. Font Vectors
  else if (subtype === 'font') {
    vectorGroup = 'font';
    if (count > 3 || api.includes('FontFaceSet.check') || api.includes('FontFaceSet.load')) {
      vectorType = count > 3 ? VECTOR_TYPES.FONT_ENUMERATION : VECTOR_TYPES.FONT_SINGLE_CHECK;
      isFontEnumeration = count > 3;
      description = count > 3 ? `Rapid font enumeration (${count} fonts checked)` : `Font availability check (${details.font || 'font'})`;
    } else {
      vectorType = VECTOR_TYPES.FONT_SINGLE_CHECK;
      description = `Font access (${api})`;
    }
  }

  // 5. Storage / Device / Network Transmission Vectors
  else if (subtype === 'beacon') {
    vectorGroup = 'beacon';
    vectorType = VECTOR_TYPES.BEACON_EXFILTRATION;
    isExfiltration = true;
    description = `Outbound network transmission (${api})`;
  } else if (subtype === 'storage') {
    if (DEVICE_PROPERTIES.has(api) || api.startsWith('screen.') || api.startsWith('navigator.')) {
      vectorGroup = 'device';
      vectorType = count > 3 ? VECTOR_TYPES.DEVICE_ATTR_SWEEP : VECTOR_TYPES.DEVICE_SINGLE_ATTR;
      description = `Device environment attribute (${api})`;
    } else if (api.includes('cookie') || api.includes('Storage') || api.includes('IDBFactory')) {
      vectorGroup = 'storage';
      vectorType = VECTOR_TYPES.STORAGE_SINGLE;
      description = `Client storage access (${api})`;
    } else {
      vectorGroup = 'storage';
      vectorType = VECTOR_TYPES.STORAGE_SINGLE;
      description = `Storage access (${api})`;
    }
  } else {
    // Fallback
    vectorGroup = subtype || 'other';
    vectorType = VECTOR_TYPES.STORAGE_SINGLE;
    description = `API access (${api || subtype})`;
  }

  // Determine probing multiplier based on call frequency
  let multiplier = PROBING_MULTIPLIERS.SINGLE_BURST;
  if (count > 5) {
    multiplier = PROBING_MULTIPLIERS.HIGH_RATE_PROBE;
  } else if (count >= 2) {
    multiplier = PROBING_MULTIPLIERS.MODERATE_BURST;
  }

  const baseWeight = BASE_WEIGHTS[vectorType] || 1.0;
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
    api,
  };
}
