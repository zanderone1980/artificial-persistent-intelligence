/**
 * VIGIL Scanner - Threat Analysis Engine
 * Scans text for threats and returns severity assessment
 */

const { patterns, categoryWeights, criticalCategories } = require('./patterns');
const config = require('./config');

/**
 * Scan text for threats
 * @param {string} text - Text to analyze
 * @returns {Object} - { severity: 0-10, decision: ALLOW|CHALLENGE|BLOCK, threats: [], summary: string }
 */
function scan(text) {
  if (!text || typeof text !== 'string') {
    return {
      severity: 0,
      decision: 'ALLOW',
      threats: [],
      summary: 'No content to scan',
    };
  }

  // Truncate if too long
  if (text.length > config.scanner.maxTextLength) {
    text = text.substring(0, config.scanner.maxTextLength);
  }

  const threats = [];
  const detectedCategories = new Set();
  let totalScore = 0;
  let hasCriticalThreat = false;

  // Scan each category
  for (const [category, regexList] of Object.entries(patterns)) {
    const categoryMatches = [];

    for (const regex of regexList) {
      const matches = text.match(regex);
      if (matches) {
        categoryMatches.push(...matches.map(m => m.trim()));
      }
    }

    if (categoryMatches.length > 0) {
      detectedCategories.add(category);
      const weight = categoryWeights[category] || 5;
      const categoryScore = Math.min(10, categoryMatches.length * weight);
      totalScore += categoryScore;

      threats.push({
        category,
        weight,
        matches: [...new Set(categoryMatches)], // Deduplicate
        score: categoryScore,
      });

      // Check if critical category
      if (criticalCategories.includes(category)) {
        hasCriticalThreat = true;
      }
    }
  }

  // Normalize severity to 0-10 scale
  const severity = Math.min(10, Math.round(totalScore / Math.max(1, detectedCategories.size)));

  // Determine decision
  let decision;
  if (hasCriticalThreat || severity >= config.thresholds.block) {
    decision = 'BLOCK';
  } else if (severity > config.thresholds.allow) {
    decision = 'CHALLENGE';
  } else {
    decision = 'ALLOW';
  }

  // Generate summary
  const summary = generateSummary(decision, severity, threats, hasCriticalThreat);

  return {
    severity,
    decision,
    threats,
    summary,
    hasCriticalThreat,
  };
}

/**
 * Generate human-readable summary
 */
function generateSummary(decision, severity, threats, hasCriticalThreat) {
  if (threats.length === 0) {
    return 'Clean content - no threats detected';
  }

  const categories = threats.map(t => t.category).join(', ');
  const matchCount = threats.reduce((sum, t) => sum + t.matches.length, 0);

  if (hasCriticalThreat) {
    return `CRITICAL THREAT: Detected ${categories} (${matchCount} matches) - severity ${severity}/10`;
  }

  if (decision === 'BLOCK') {
    return `THREAT: Detected ${categories} (${matchCount} matches) - severity ${severity}/10`;
  }

  if (decision === 'CHALLENGE') {
    return `SUSPICIOUS: Detected ${categories} (${matchCount} matches) - severity ${severity}/10`;
  }

  return `Low-risk patterns detected: ${categories} - severity ${severity}/10`;
}

module.exports = {
  scan,
};
