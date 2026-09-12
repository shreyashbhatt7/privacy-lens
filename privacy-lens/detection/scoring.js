// detection/scoring.js
//
// Scoring constants, vector weights, and confidence formulas for Person 3's
// Intelligence & Correlation Engine.
//
// Refines signal combinations across fingerprint/*.js hooks:
//  - Distinguishes individually benign hooks (e.g. getParameter(MAX_TEXTURE_SIZE)
//    or screen.width for layout) from suspicious combinations.
//  - Combines multiple vector weights, applies rapid probing multipliers
//    (e.g. count > 5), and detects exfiltration chains.

import { correlateCrossLayerBeacons } from '../lib/correlate.js';

export const VECTOR_TYPES = {
  CANVAS_READBACK: 'canvas_readback',
  CANVAS_GEOMETRY: 'canvas_geometry',
  WEBGL_UNMASKED_GPU: 'webgl_unmasked_gpu',
  WEBGL_PIXEL_READBACK: 'webgl_pixel_readback',
  WEBGL_GENERIC_PARAM: 'webgl_generic_param',
  WEBGL_CAPABILITY_PARAM: 'webgl_capability_param',
  AUDIO_OFFLINE_RENDER: 'audio_offline_render',
  AUDIO_COMPRESSOR_OSC: 'audio_compressor_osc',
  AUDIO_ANALYSER: 'audio_analyser',
  AUDIO_BASIC_NODE: 'audio_basic_node',
  FONT_ENUMERATION: 'font_enumeration',
  FONT_SINGLE_CHECK: 'font_single_check',
  DEVICE_ATTR_SWEEP: 'device_attr_sweep',
  DEVICE_SINGLE_ATTR: 'device_single_attr',
  STORAGE_CROSS_SYNC: 'storage_cross_sync',
  STORAGE_SINGLE: 'storage_single',
  BEACON_EXFILTRATION: 'beacon_exfiltration',
};

export const BASE_WEIGHTS = {
  [VECTOR_TYPES.CANVAS_READBACK]: 3.0,
  [VECTOR_TYPES.CANVAS_GEOMETRY]: 1.0,
  [VECTOR_TYPES.WEBGL_UNMASKED_GPU]: 4.0,
  [VECTOR_TYPES.WEBGL_PIXEL_READBACK]: 2.5,
  [VECTOR_TYPES.WEBGL_GENERIC_PARAM]: 1.5,
  [VECTOR_TYPES.WEBGL_CAPABILITY_PARAM]: 0.3,
  [VECTOR_TYPES.AUDIO_OFFLINE_RENDER]: 4.0,
  [VECTOR_TYPES.AUDIO_COMPRESSOR_OSC]: 3.0,
  [VECTOR_TYPES.AUDIO_ANALYSER]: 2.0,
  [VECTOR_TYPES.AUDIO_BASIC_NODE]: 0.5,
  [VECTOR_TYPES.FONT_ENUMERATION]: 3.0,
  [VECTOR_TYPES.FONT_SINGLE_CHECK]: 0.2,
  [VECTOR_TYPES.DEVICE_ATTR_SWEEP]: 2.5,
  [VECTOR_TYPES.DEVICE_SINGLE_ATTR]: 0.1,
  [VECTOR_TYPES.STORAGE_CROSS_SYNC]: 2.0,
  [VECTOR_TYPES.STORAGE_SINGLE]: 0.2,
  [VECTOR_TYPES.BEACON_EXFILTRATION]: 3.5,
};

// High-frequency probing multipliers (per ARCHITECTURE_LOCK.md)
export const PROBING_MULTIPLIERS = {
  SINGLE_BURST: 1.0,      // count <= 1
  MODERATE_BURST: 1.25,   // 2 <= count <= 5
  HIGH_RATE_PROBE: 1.5,   // count > 5
};

export const SEVERITY_THRESHOLDS = {
  HIGH: 0.70,
  MEDIUM: 0.40,
};

export const PRIVACY_GRADE_THRESHOLDS = {
  A: { minScore: 90, grade: 'A', rating: 'Excellent', color: '#22c55e' },
  B: { minScore: 75, grade: 'B', rating: 'Good', color: '#3b82f6' },
  C: { minScore: 55, grade: 'C', rating: 'Moderate Risk', color: '#eab308' },
  D: { minScore: 35, grade: 'D', rating: 'High Risk', color: '#f97316' },
  F: { minScore: 0,  grade: 'F', rating: 'Severe Risk', color: '#ef4444' },
};

/**
 * Calculates a confidence score (0.0 to 1.0) based on accumulated threat weight,
 * vector diversity, probing multipliers, and exfiltration status.
 *
 * @param {Object} params
 * @param {number} params.totalWeight - Sum of threat weights for active vectors
 * @param {number} params.vectorCount - Number of distinct high-level vector groups involved
 * @param {boolean} params.hasExfiltration - Whether a beacon/fetch/xhr was sent by the same script
 * @param {boolean} params.hasUnmaskedGpu - Whether unmasked GPU hardware info was queried
 * @param {boolean} params.hasOfflineAudio - Whether OfflineAudioContext rendering was triggered
 * @returns {{ confidence: number, severity: 'low'|'medium'|'high' }}
 */
export function calculateConfidenceScore({
  totalWeight,
  vectorCount = 1,
  hasExfiltration = false,
  hasUnmaskedGpu = false,
  hasOfflineAudio = false,
}) {
  // If only a single isolated benign capability check occurred (e.g. screen.width or MAX_TEXTURE_SIZE)
  if (vectorCount <= 1 && totalWeight <= 0.5) {
    const rawConf = Math.min(0.20, Math.max(0.05, totalWeight * 0.25));
    return {
      confidence: Math.round(rawConf * 100) / 100,
      severity: 'low',
    };
  }

  // Base confidence using smooth saturation curve: 1 - exp(-totalWeight / 4.2)
  let confidence = 1 - Math.exp(-totalWeight / 4.2);

  // Vector diversity bonus: combining distinct vectors (Canvas + WebGL + Audio) increases certainty
  if (vectorCount >= 2) {
    confidence = Math.max(confidence, 0.55 + (vectorCount - 2) * 0.12);
  }
  if (vectorCount >= 3) {
    confidence = Math.max(confidence, 0.85);
  }
  if (vectorCount >= 4) {
    confidence = Math.max(confidence, 0.90);
  }

  // Specific high-risk signature boosts
  if (hasUnmaskedGpu && vectorCount >= 2) {
    confidence = Math.max(confidence, 0.75);
  }
  if (hasOfflineAudio && vectorCount >= 2) {
    confidence = Math.max(confidence, 0.80);
  }

  // Exfiltration chain completion: Fingerprint vectors + network beacon/fetch/xhr
  if (hasExfiltration) {
    if (vectorCount >= 3 || (vectorCount >= 2 && (hasUnmaskedGpu || hasOfflineAudio))) {
      confidence = Math.max(confidence, 0.95);
    } else if (vectorCount >= 2 || totalWeight >= 3.0) {
      confidence = Math.max(confidence, 0.88);
    } else {
      confidence = Math.max(confidence, 0.60);
    }
  }

  // Cap confidence at 0.99
  confidence = Math.min(0.99, Math.max(0.05, Math.round(confidence * 100) / 100));

  let severity = 'low';
  if (confidence >= SEVERITY_THRESHOLDS.HIGH) {
    severity = 'high';
  } else if (confidence >= SEVERITY_THRESHOLDS.MEDIUM) {
    severity = 'medium';
  }

  return { confidence, severity };
}

/**
 * Computes a holistic site Privacy Score (0-100) and letter grade (A-F) based on
 * observed tracking events, weighting severity distribution, confidence,
 * cross-layer corroboration, vector diversity, and active exfiltration.
 *
 * @param {Array<Object>} events - Array of canonical or display TrackingEvents
 * @returns {{
 *   score: number,
 *   grade: 'A'|'B'|'C'|'D'|'F',
 *   rating: string,
 *   color: string,
 *   breakdown: {
 *     highCount: number,
 *     mediumCount: number,
 *     lowCount: number,
 *     crossLayerCount: number,
 *     distinctMethods: number,
 *     distinctTrackers: number,
 *     deductions: number
 *   }
 * }}
 */
export function calculatePrivacyScore(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return {
      score: 100,
      grade: 'A',
      rating: 'Excellent',
      color: '#22c55e',
      breakdown: {
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        crossLayerCount: 0,
        distinctMethods: 0,
        distinctTrackers: 0,
        deductions: 0,
      },
    };
  }

  // Ensure cross-layer correlation is evaluated
  const correlated = correlateCrossLayerBeacons(events);

  let rawHighSum = 0;
  let rawMedSum = 0;
  let rawLowSum = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let crossLayerCount = 0;
  const methods = new Set();
  const trackers = new Set();
  let hasActiveExfil = false;

  // Track occurrences per entity key (domain + category:subtype + severity)
  // to apply diminishing returns for repetitive calls from the same tracker.
  const occurrenceCountMap = new Map();

  for (const evt of correlated) {
    if (!evt) continue;
    const sev = (evt.severity || 'low').toLowerCase();
    const conf = typeof evt.confidence === 'number' && evt.confidence > 0
      ? evt.confidence
      : (sev === 'high' ? 0.85 : sev === 'medium' ? 0.55 : 0.20);

    const domain = evt.target?.domain || evt.domain || evt.source?.requestDomain;
    if (domain) {
      trackers.add(domain);
    }

    if (evt.category && evt.subtype) {
      methods.add(`${evt.category}:${evt.subtype}`);
    }

    // Determine repetition multiplier:
    // First occurrence from a tracker/method receives full 1.0 weight.
    // Subsequent occurrences taper off: 2nd = 0.35, 3rd = 0.20, 4th+ = 0.10.
    const entityKey = `${domain || evt.source?.script || 'inline'}::${evt.category || 'cat'}::${evt.subtype || 'sub'}::${sev}`;
    const seen = (occurrenceCountMap.get(entityKey) || 0) + 1;
    occurrenceCountMap.set(entityKey, seen);

    const repeatWeight = seen === 1 ? 1.0 : (seen === 2 ? 0.35 : (seen === 3 ? 0.20 : 0.10));

    if (sev === 'high') {
      highCount++;
      rawHighSum += 15 * conf * repeatWeight;
    } else if (sev === 'medium') {
      mediumCount++;
      rawMedSum += 7 * conf * repeatWeight;
    } else {
      lowCount++;
      rawLowSum += 2 * conf * repeatWeight;
    }

    if (evt.crossLayerConfirmed) {
      crossLayerCount++;
    }

    // Active exfiltration: actual data beacons, exfiltration notes, or cross-layer beacons
    // (script downloads 'third-party-load' are NOT data exfiltration).
    if (
      evt.subtype === 'beacon' ||
      evt.evidence?.forensicNotes?.toLowerCase()?.includes('exfiltration') ||
      (evt.crossLayerConfirmed && evt.category === 'network')
    ) {
      hasActiveExfil = true;
    }
  }

  // Diminishing returns curves for severity penalties
  // Max High penalty: 55 points
  const penaltyHigh = 55 * (1 - Math.exp(-rawHighSum / 35));
  // Max Medium penalty: 25 points
  const penaltyMed = 25 * (1 - Math.exp(-rawMedSum / 25));
  // Max Low penalty: 12 points
  const penaltyLow = 12 * (1 - Math.exp(-rawLowSum / 15));

  // Cross-layer confirmation bonus penalty (max 20 points)
  // Cross-layer proves independent wiretap + DOM hook corroboration of exfiltration
  const penaltyCrossLayer = crossLayerCount > 0
    ? 20 * (1 - Math.exp(-(crossLayerCount * 7) / 20))
    : 0;

  // Vector / Method diversity penalty (max 10 points)
  let penaltyDiversity = 0;
  if (methods.size >= 5) {
    penaltyDiversity = 10;
  } else if (methods.size >= 3) {
    penaltyDiversity = 5;
  } else if (methods.size >= 2) {
    penaltyDiversity = 2;
  }

  // Active exfiltration penalty
  const penaltyExfil = hasActiveExfil && (highCount > 0 || mediumCount > 0) ? 8 : 0;

  const totalDeductions = penaltyHigh + penaltyMed + penaltyLow + penaltyCrossLayer + penaltyDiversity + penaltyExfil;
  const score = Math.max(0, Math.min(100, Math.round(100 - totalDeductions)));

  let gradeInfo = PRIVACY_GRADE_THRESHOLDS.F;
  if (score >= PRIVACY_GRADE_THRESHOLDS.A.minScore) {
    gradeInfo = PRIVACY_GRADE_THRESHOLDS.A;
  } else if (score >= PRIVACY_GRADE_THRESHOLDS.B.minScore) {
    gradeInfo = PRIVACY_GRADE_THRESHOLDS.B;
  } else if (score >= PRIVACY_GRADE_THRESHOLDS.C.minScore) {
    gradeInfo = PRIVACY_GRADE_THRESHOLDS.C;
  } else if (score >= PRIVACY_GRADE_THRESHOLDS.D.minScore) {
    gradeInfo = PRIVACY_GRADE_THRESHOLDS.D;
  }

  return {
    score,
    grade: gradeInfo.grade,
    rating: gradeInfo.rating,
    color: gradeInfo.color,
    breakdown: {
      highCount,
      mediumCount,
      lowCount,
      crossLayerCount,
      distinctMethods: methods.size,
      distinctTrackers: trackers.size,
      deductions: Math.round(totalDeductions * 10) / 10,
    },
  };
}
