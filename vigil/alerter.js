/**
 * VIGIL Alerter - Alert System with Hash Chaining
 * Append-only JSONL alert log with cryptographic hash chaining like CORD
 */

const fs = require('fs');
const crypto = require('crypto');
const config = require('./config');

/**
 * Hash chaining state
 */
let lastHash = '0000000000000000000000000000000000000000000000000000000000000000'; // Genesis hash

/**
 * Initialize the alerter (load last hash from log)
 */
function initialize() {
  // Reset to genesis hash
  lastHash = '0000000000000000000000000000000000000000000000000000000000000000';

  if (!fs.existsSync(config.alertLogPath)) {
    return;
  }

  try {
    const content = fs.readFileSync(config.alertLogPath, 'utf8');
    const lines = content.trim().split('\n').filter(l => l.length > 0);

    if (lines.length > 0) {
      const lastEntry = JSON.parse(lines[lines.length - 1]);
      lastHash = lastEntry.hash;
    }
  } catch (err) {
    console.error('VIGIL Alerter: Failed to load last hash:', err.message);
  }
}

/**
 * Compute SHA-256 hash
 */
function computeHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Log an alert with hash chaining
 * @param {Object} scanResult - Result from scanner.scan()
 * @param {string} text - Original text that was scanned
 */
function logAlert(scanResult, text) {
  const timestamp = new Date().toISOString();

  const alert = {
    timestamp,
    severity: scanResult.severity,
    decision: scanResult.decision,
    summary: scanResult.summary,
    threats: scanResult.threats,
    textPreview: text.substring(0, 200), // First 200 chars
    textHash: computeHash(text),
    previousHash: lastHash,
  };

  // Compute current hash (chain it)
  const alertString = JSON.stringify({
    timestamp: alert.timestamp,
    severity: alert.severity,
    decision: alert.decision,
    textHash: alert.textHash,
    previousHash: alert.previousHash,
  });

  const currentHash = computeHash(alertString);
  alert.hash = currentHash;

  // Append to log
  try {
    fs.appendFileSync(config.alertLogPath, JSON.stringify(alert) + '\n', 'utf8');
    lastHash = currentHash;
  } catch (err) {
    console.error('VIGIL Alerter: Failed to write alert:', err.message);
  }

  return alert;
}

/**
 * Get all alerts
 */
function getAllAlerts() {
  if (!fs.existsSync(config.alertLogPath)) {
    return [];
  }

  try {
    const content = fs.readFileSync(config.alertLogPath, 'utf8');
    return content
      .trim()
      .split('\n')
      .filter(l => l.length > 0)
      .map(line => JSON.parse(line));
  } catch (err) {
    console.error('VIGIL Alerter: Failed to read alerts:', err.message);
    return [];
  }
}

/**
 * Verify hash chain integrity
 */
function verifyChain() {
  const alerts = getAllAlerts();

  if (alerts.length === 0) {
    return { valid: true, message: 'No alerts to verify' };
  }

  let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';

  for (let i = 0; i < alerts.length; i++) {
    const alert = alerts[i];

    // Check previous hash matches
    if (alert.previousHash !== expectedPrevHash) {
      return {
        valid: false,
        message: `Chain broken at alert ${i}: expected previousHash ${expectedPrevHash}, got ${alert.previousHash}`,
      };
    }

    // Recompute hash
    const alertString = JSON.stringify({
      timestamp: alert.timestamp,
      severity: alert.severity,
      decision: alert.decision,
      textHash: alert.textHash,
      previousHash: alert.previousHash,
    });

    const computedHash = computeHash(alertString);

    if (computedHash !== alert.hash) {
      return {
        valid: false,
        message: `Hash mismatch at alert ${i}: expected ${computedHash}, got ${alert.hash}`,
      };
    }

    expectedPrevHash = alert.hash;
  }

  return { valid: true, message: `Chain verified: ${alerts.length} alerts` };
}

// Initialize on load
initialize();

module.exports = {
  logAlert,
  getAllAlerts,
  verifyChain,
  initialize,
};
