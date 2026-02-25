/**
 * VIGIL Configuration
 * Settings and thresholds for the threat scanner
 */

const path = require('path');

const config = {
  // Severity thresholds
  thresholds: {
    allow: 2,      // 0-2: Clean → ALLOW
    challenge: 5,  // 3-5: Suspicious → CHALLENGE
    block: 6,      // 6-10: Threat → BLOCK
  },

  // Scoring weights
  weights: {
    injection: 10,
    exfil: 10,
    manipulation: 10,
    obfuscation: 5,
    dangerousOps: 8,
    suspiciousURLs: 7,
  },

  // Critical categories (immediate BLOCK regardless of score)
  criticalCategories: ['injection', 'exfil', 'manipulation'],

  // Alert log path
  alertLogPath: path.join(__dirname, 'vigil-alerts.jsonl'),

  // Event emission settings
  emitOnAllow: false,     // Don't spam events for clean content
  emitOnChallenge: true,  // Emit events for suspicious content
  emitOnBlock: true,      // Always emit events for threats

  // Scanner settings
  scanner: {
    maxTextLength: 100000, // Max chars to scan
    caseSensitive: false,
  },
};

module.exports = config;
