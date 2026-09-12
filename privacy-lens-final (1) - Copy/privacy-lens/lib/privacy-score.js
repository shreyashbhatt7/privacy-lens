// lib/privacy-score.js
//
// Privacy Lens - Holistic Site Privacy Score & Grade Engine
// Owner: Person 3 (Intelligence & Side Panel UI)
//
// Provides calculatePrivacyScore(events) to compute a 0-100 score and A-F grade
// based on observed tracking events, weighting severity, confidence, cross-layer
// corroboration, vector diversity, and active exfiltration.

export {
  calculatePrivacyScore,
  PRIVACY_GRADE_THRESHOLDS,
} from '../detection/scoring.js';
