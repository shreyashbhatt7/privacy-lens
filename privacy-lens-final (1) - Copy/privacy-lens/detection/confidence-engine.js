// detection/confidence-engine.js
//
// Confidence & Correlation Engine (Phase 24-32 / Person 3 Intelligence Layer)
//
// Analyzes combinations of fingerprint hooks firing from the same script and page context
// within a sliding temporal window (10s).
//
// Refines signal combinations:
//  - WebGL MAX_TEXTURE_SIZE or screen.width alone -> low confidence (< 0.20), low severity (benign)
//  - canvas.toDataURL + webgl.getParameter(UNMASKED_RENDERER) -> high confidence (0.75+), high severity
//  - canvas + webgl + audio + sendBeacon -> very high confidence (0.95+), high severity (exfiltration chain)
//  - High frequency probing (count > 5) -> frequency multiplier boost

import { classifySignal } from './classifier.js';
import { calculateConfidenceScore, VECTOR_TYPES, BASE_WEIGHTS } from './scoring.js';
import { createTrackingEvent } from '../shared/events.js';

const CORRELATION_WINDOW_MS = 10000; // 10-second sliding correlation window

export class ConfidenceEngine {
  constructor(windowMs = CORRELATION_WINDOW_MS) {
    this.windowMs = windowMs;
    // Map of sessionKey -> ScriptSessionRecord
    // sessionKey = `${site}:${tabId}:${scriptUrl}`
    this.sessions = new Map();
  }

  /**
   * Generates a correlation lookup key for a script context.
   */
  _sessionKey(site, tabId, scriptUrl) {
    return `${site || 'unknown'}:${tabId ?? '0'}:${scriptUrl || 'inline'}`;
  }

  /**
   * Retrieves or initializes the correlation session record for a script.
   */
  _getSession(site, tabId, scriptUrl, now = Date.now()) {
    const key = this._sessionKey(site, tabId, scriptUrl);
    let session = this.sessions.get(key);

    if (!session || (now - session.lastUpdated > this.windowMs)) {
      session = {
        key,
        site,
        tabId,
        scriptUrl,
        firstSeen: now,
        lastUpdated: now,
        vectorGroups: new Set(),
        vectorTypes: new Set(),
        signals: [],
        deviceAttrs: new Set(),
        fontCount: 0,
        storageTypes: new Set(),
        hasExfiltration: false,
        hasUnmaskedGpu: false,
        hasOfflineAudio: false,
        exfiltrationTargets: new Set(),
        totalWeight: 0,
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
      timestamp: Date.now(),
    });

    if (signal.isUnmaskedGpu) session.hasUnmaskedGpu = true;
    if (signal.isOfflineAudio) session.hasOfflineAudio = true;
    if (signal.isExfiltration) {
      session.hasExfiltration = true;
      const targetDomain = rawEvidence.targetDomain || rawEvidence.domain;
      if (targetDomain) session.exfiltrationTargets.add(targetDomain);
    }

    if (signal.vectorGroup === 'device') {
      session.deviceAttrs.add(signal.api);
    }
    if (signal.vectorGroup === 'font') {
      session.fontCount += (signal.count || 1);
    }
    if (signal.vectorGroup === 'storage') {
      session.storageTypes.add(signal.api);
    }

    // Recalculate distinct vector-based accumulated weight
    // Rather than raw sum of infinite loops, we cap repetitive single-vector weights
    // while giving high weight to vector diversity
    let accumulatedWeight = 0;
    const groupMaxWeights = new Map();

    for (const sig of session.signals) {
      const current = groupMaxWeights.get(sig.vectorGroup) || 0;
      // Diminishing returns within the same vector group, full weight across distinct groups
      const additional = Math.max(0, sig.weight - current * 0.4);
      groupMaxWeights.set(sig.vectorGroup, Math.min(8.0, current + additional));
    }

    for (const weight of groupMaxWeights.values()) {
      accumulatedWeight += weight;
    }

    // If multi-device attribute sweep occurred, add composite boost
    if (session.deviceAttrs.size >= 3) {
      accumulatedWeight += BASE_WEIGHTS[VECTOR_TYPES.DEVICE_ATTR_SWEEP];
    }

    // If font enumeration occurred
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
      const targets = session.exfiltrationTargets.size > 0
        ? ` -> [${Array.from(session.exfiltrationTargets).join(', ')}]`
        : '';
      parts.push(`Active Multi-Vector Exfiltration Chain${targets}`);
    }

    const vectorDetails = [];
    if (session.vectorGroups.has('canvas')) vectorDetails.push('Canvas');
    if (session.hasUnmaskedGpu) {
      vectorDetails.push('WebGL (Unmasked GPU)');
    } else if (session.vectorGroups.has('webgl')) {
      vectorDetails.push(currentSignal.isCapabilityCheck ? 'WebGL (Capability)' : 'WebGL');
    }
    if (session.hasOfflineAudio) {
      vectorDetails.push('Offline AudioContext');
    } else if (session.vectorGroups.has('audio')) {
      vectorDetails.push('AudioContext');
    }
    if (session.fontCount >= 5) {
      vectorDetails.push(`Fonts (${session.fontCount} probed)`);
    } else if (session.vectorGroups.has('font')) {
      vectorDetails.push('Font Check');
    }
    if (session.deviceAttrs.size >= 3) {
      vectorDetails.push(`Device Sweep (${session.deviceAttrs.size} attrs)`);
    } else if (session.vectorGroups.has('device')) {
      vectorDetails.push('Device Property');
    }
    if (session.vectorGroups.has('storage')) vectorDetails.push('Storage');

    if (vectorDetails.length > 0) {
      parts.push(`Vectors: ${vectorDetails.join(' + ')}`);
    }

    if (parts.length === 0) {
      return currentSignal.description || 'API access';
    }

    return parts.join(' | ');
  }

  /**
   * Evaluates a single draft or event, updating script session state and computing confidence.
   *
   * @param {Object} draft - Raw draft event
   * @param {Object} context - { topSite, tabId }
   * @returns {Object} Final canonical TrackingEvent
   */
  evaluateEvent(draft, { topSite, tabId }) {
    const scriptUrl = draft.source?.script || 'inline';
    const session = this._getSession(topSite, tabId, scriptUrl);
    const signal = classifySignal(draft);

    const rawEvidence = {
      ...(draft.evidence?.details || draft.evidence || {}),
      targetDomain: draft.target?.domain,
    };

    this._recordSignal(session, signal, rawEvidence);

    // Compute confidence and severity
    const { confidence, severity } = calculateConfidenceScore({
      totalWeight: session.totalWeight,
      vectorCount: session.vectorGroups.size,
      hasExfiltration: session.hasExfiltration,
      hasUnmaskedGpu: session.hasUnmaskedGpu,
      hasOfflineAudio: session.hasOfflineAudio,
    });

    const forensicNotes = this._buildForensicNotes(session, signal);
    const apiName = draft.evidence?.api || signal.api;
    const count = draft.count || 1;

    // Flatten evidence per Option B contract
    const details = draft.evidence?.details ?? (draft.evidence ? { ...draft.evidence } : {});
    delete details.api;
    delete details.count;

    const flattenedEvidence = {
      api: apiName,
      ...details,
      ...(count > 1 ? { count } : {}),
      correlatedVectors: Array.from(session.vectorGroups),
      forensicNotes,
    };

    return createTrackingEvent({
      tabId,
      site: topSite,
      category: draft.category || 'fingerprinting',
      subtype: draft.subtype,
      source: draft.source || { script: scriptUrl },
      target: draft.target || {},
      evidence: flattenedEvidence,
      severity,
      confidence,
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
}

// Global singleton instance for service worker lifetime
export const confidenceEngine = new ConfidenceEngine();
