/**
 * Privacy Lens - Shared Constants & Integration Tokens
 * Locked in Phase 0-2 for Person 1, Person 2, and Person 3
 */

export const MESSAGE_SOURCES = {
  MAIN_WORLD: 'PRIVACY_LENS_MAIN_WORLD',
  CONTENT_SCRIPT: 'PRIVACY_LENS_CONTENT_SCRIPT',
  BACKGROUND_BUS: 'PRIVACY_LENS_BACKGROUND_BUS'
};

export const MESSAGE_TYPES = {
  TRACKING_EVENT: 'PRIVACY_LENS_TRACKING_EVENT',
  BATCH_EVENTS: 'PRIVACY_LENS_BATCH_EVENTS'
};

export const EVENT_CATEGORIES = {
  FINGERPRINTING: 'fingerprinting',
  NETWORK: 'network',
  STORAGE: 'storage',
  IDENTIFIER: 'identifier'
};

export const FINGERPRINT_SUBTYPES = {
  CANVAS: 'canvas',
  WEBGL: 'webgl',
  AUDIO: 'audio',
  STORAGE: 'storage',
  BEACON: 'beacon',
  FONT: 'font'
};

export const SEVERITY_LEVELS = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high'
};
