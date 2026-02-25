/**
 * VIGIL Canary Token System — Proactive Extraction Detection
 *
 * Plants invisible markers in system prompts. If those markers
 * appear in agent output, the system prompt was extracted.
 *
 * This flips the model from reactive (detect attacks as they happen)
 * to proactive (set the trap, confirm the breach with certainty).
 *
 * Three canary types:
 *   1. UUID canary     — unique ID embedded in prompt as "internal ref"
 *   2. Zero-width canary — invisible Unicode sequence, detectable in output
 *   3. Honey phrase    — a realistic-looking fake secret lure
 *
 * Zero external dependencies.
 */

const crypto = require('crypto');

// Zero-width Unicode characters used for steganographic canaries
// These are invisible in rendered text but present in raw strings
const ZW_CHARS = [
  '\u200B', // Zero Width Space
  '\u200C', // Zero Width Non-Joiner
  '\u200D', // Zero Width Joiner
  '\uFEFF', // Zero Width No-Break Space
];

// Map bit value → zero-width char
const ZW_MAP = { '0': ZW_CHARS[0], '1': ZW_CHARS[1] };
// Separator between canary bits
const ZW_SEP = ZW_CHARS[2];
// Canary start/end markers
const ZW_START = ZW_CHARS[3];
const ZW_END = '\u200C\u200B'; // ZWNJ + ZWSP combination

/**
 * Encode a short string as a zero-width character sequence.
 * @param {string} data - Data to encode (keep short — <16 chars)
 * @returns {string} Zero-width encoded string
 */
function encodeZeroWidth(data) {
  const bits = Buffer.from(data).toString('binary')
    .split('')
    .map(c => c.charCodeAt(0).toString(2).padStart(8, '0'))
    .join('');
  return ZW_START + bits.split('').map(b => ZW_MAP[b]).join(ZW_SEP) + ZW_END;
}

/**
 * Detect zero-width canary sequence in text.
 * @param {string} text
 * @returns {string|null} Decoded canary string, or null if not found
 */
function detectZeroWidth(text) {
  const startIdx = text.indexOf(ZW_START);
  const endMarker = text.indexOf(ZW_END);
  if (startIdx === -1 || endMarker === -1 || endMarker <= startIdx) return null;

  const payload = text.slice(startIdx + ZW_START.length, endMarker);
  const bits = payload.split(ZW_SEP).map(c => {
    if (c === ZW_MAP['0']) return '0';
    if (c === ZW_MAP['1']) return '1';
    return null;
  });

  if (bits.includes(null) || bits.length % 8 !== 0) return null;

  try {
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8).join(''), 2));
    }
    return Buffer.from(bytes).toString('binary');
  } catch {
    return null;
  }
}

/**
 * Generate a short unique canary ID.
 * @returns {string} 8-char hex ID
 */
function generateCanaryId() {
  return crypto.randomBytes(4).toString('hex');
}

/**
 * Honey phrase templates — realistic-looking fake secrets.
 * These lure extraction attempts and confirm breach on detection.
 */
const HONEY_TEMPLATES = [
  (id) => `INTERNAL_REF:${id}`,
  (id) => `sk-vigil-${id}-canary`,
  (id) => `sys_token_${id}`,
  (id) => `__vigil_marker_${id}__`,
];

/**
 * Canary Token Registry
 * Tracks all planted canaries. One instance per VIGIL session.
 */
class CanaryRegistry {
  constructor() {
    // Map of canaryId → canary metadata
    this.canaries = new Map();
    // Detection events
    this.detections = [];
  }

  /**
   * Plant a new canary — generate tokens to embed in a system prompt.
   * Returns the tokens to inject AND metadata to track them.
   *
   * @param {object} [options]
   * @param {string} [options.sessionId] — session to associate this canary with
   * @param {string[]} [options.types]  — which canary types to use ['uuid', 'zero-width', 'honey']
   * @returns {object} { canaryId, tokens: { uuid, zeroWidth, honey }, injectText }
   */
  plant(options = {}) {
    const canaryId = generateCanaryId();
    const types = options.types || ['uuid', 'zeroWidth', 'honey'];
    const sessionId = options.sessionId || 'default';

    const templateFn = HONEY_TEMPLATES[Math.floor(Math.random() * HONEY_TEMPLATES.length)];

    const tokens = {};

    if (types.includes('uuid')) {
      tokens.uuid = `vigil-${canaryId}`;
    }

    if (types.includes('zeroWidth')) {
      tokens.zeroWidth = encodeZeroWidth(canaryId);
    }

    if (types.includes('honey')) {
      tokens.honey = templateFn(canaryId);
    }

    // Build inject text — what you actually embed in the system prompt
    const injectParts = [];
    if (tokens.zeroWidth) {
      // Silent — goes before visible text, invisible in rendered output
      injectParts.push(tokens.zeroWidth);
    }
    if (tokens.uuid) {
      // Disguised as an internal reference comment
      injectParts.push(`<!-- ref:${tokens.uuid} -->`);
    }
    if (tokens.honey) {
      // A realistic-looking fake secret the attacker would want to extract
      injectParts.push(tokens.honey);
    }

    const canary = {
      canaryId,
      sessionId,
      types,
      tokens,
      injectText: injectParts.join(''),
      plantedAt: Date.now(),
      triggered: false,
      detectedAt: null,
      detectedIn: null,
    };

    this.canaries.set(canaryId, canary);

    return {
      canaryId,
      tokens,
      injectText: canary.injectText,
    };
  }

  /**
   * Scan text for any planted canaries.
   * Call this on every agent output before it leaves the system.
   *
   * @param {string} text — text to scan (agent output, tool result, etc.)
   * @param {string} [context] — where this text came from
   * @returns {object} { triggered: boolean, detections: array, severity: number }
   */
  scan(text, context = 'output') {
    const triggered = [];

    for (const [canaryId, canary] of this.canaries) {
      if (canary.triggered) continue; // Already flagged, don't double-count

      let detected = false;
      const matchedTypes = [];

      // Check UUID canary
      if (canary.tokens.uuid && text.includes(canary.tokens.uuid)) {
        detected = true;
        matchedTypes.push('uuid');
      }

      // Check honey phrase
      if (canary.tokens.honey && text.includes(canary.tokens.honey)) {
        detected = true;
        matchedTypes.push('honey');
      }

      // Check zero-width canary
      if (canary.tokens.zeroWidth) {
        const decoded = detectZeroWidth(text);
        if (decoded === canaryId) {
          detected = true;
          matchedTypes.push('zeroWidth');
        }
      }

      if (detected) {
        canary.triggered = true;
        canary.detectedAt = Date.now();
        canary.detectedIn = context;

        const detection = {
          canaryId,
          sessionId: canary.sessionId,
          matchedTypes,
          context,
          plantedAt: canary.plantedAt,
          detectedAt: canary.detectedAt,
          latencyMs: canary.detectedAt - canary.plantedAt,
          severity: 10, // Canary detection is always max severity
          threat: 'SYSTEM_PROMPT_EXTRACTION',
          message: `Canary triggered: system prompt content detected in ${context}. ` +
            `Matched ${matchedTypes.join(', ')} canary type(s). ` +
            `Planted ${Math.round(canary.latencyMs / 1000)}s ago.`,
        };

        triggered.push(detection);
        this.detections.push(detection);
      }
    }

    return {
      triggered: triggered.length > 0,
      detections: triggered,
      severity: triggered.length > 0 ? 10 : 0,
      // Hard block — canary triggered means confirmed extraction, no debate
      decision: triggered.length > 0 ? 'BLOCK' : null,
    };
  }

  /**
   * Get all canaries planted this session.
   */
  getCanaries() {
    return Array.from(this.canaries.values());
  }

  /**
   * Get all triggered detections.
   */
  getDetections() {
    return [...this.detections];
  }

  /**
   * Total canaries planted.
   */
  get count() {
    return this.canaries.size;
  }

  /**
   * Total triggered.
   */
  get triggeredCount() {
    return this.detections.length;
  }

  /**
   * Clear all canaries (new session).
   */
  clear() {
    this.canaries.clear();
    this.detections = [];
  }
}

// Singleton registry
const registry = new CanaryRegistry();

module.exports = {
  CanaryRegistry,
  registry,
  encodeZeroWidth,
  detectZeroWidth,
  generateCanaryId,
};
