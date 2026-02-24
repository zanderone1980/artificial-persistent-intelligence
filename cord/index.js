/**
 * CORD — Counter-Operations & Risk Detection
 * Public API v3
 *
 * The complete surface. Import this, not cord.js directly.
 *
 * Quick start:
 *   const cord = require('cord-engine');
 *
 *   // Evaluate any text proposal
 *   const result = cord.evaluate({ text: "rm -rf /" });
 *   console.log(result.decision);       // "BLOCK"
 *   console.log(result.explanation.summary);  // plain English reason
 *
 *   // Wrap OpenAI client
 *   const openai = cord.wrapOpenAI(new OpenAI({ apiKey }));
 *
 *   // Wrap Anthropic client
 *   const anthropic = cord.wrapAnthropic(new Anthropic({ apiKey }));
 *
 *   // Start a session with intent lock
 *   cord.session.start("Build unit tests for cord.js");
 */

const cordEngine  = require("./cord");
const { explain, formatExplanation, DIMENSION_EXPLANATIONS, DECISION_CONTEXT } = require("./explain");
const mw          = require("./middleware");
const { setIntentLock, loadIntentLock, verifyPassphrase, LOCK_PATH } = require("./intentLock");
const { appendLog, LOG_PATH } = require("./logger");

// ── Core evaluation ───────────────────────────────────────────────────────────

/**
 * Evaluate a proposal and return result + plain English explanation.
 *
 * @param {object|string} input — Proposal object or plain text string
 * @returns {object} { decision, score, risks, reasons, hardBlock, log_id, explanation }
 */
function evaluate(input) {
  const normalized = typeof input === "string" ? { text: input } : input;
  const result = cordEngine.evaluateProposal(normalized);
  const explanation = explain(result, normalized.text || normalized.proposal || "");
  return { ...result, explanation };
}

// ── Session management ────────────────────────────────────────────────────────

const session = {
  /**
   * Start a new CORD session with an intent lock.
   * All subsequent evaluate() calls will be checked against this scope.
   *
   * @param {string} goal           — What this session is for
   * @param {object} [scope]        — { allowPaths, allowCommands, allowNetworkTargets }
   * @param {string} [passphrase]   — Session passphrase (auto-generated if not provided)
   */
  start(goal, scope = {}, passphrase) {
    const sessionPassphrase = passphrase || `cord_${Date.now()}`;
    const defaultScope = {
      allowPaths: [require("path").resolve(__dirname, "..")],
      allowCommands: [
        { __regex: "^git\\s", flags: "" },
        { __regex: "^npm\\s", flags: "" },
        { __regex: "^node\\s", flags: "" },
      ],
      allowNetworkTargets: ["api.anthropic.com", "api.openai.com"],
      ...scope,
    };

    setIntentLock({
      user_id: "cord_session",
      passphrase: sessionPassphrase,
      intent_text: goal,
      scope: defaultScope,
    });

    console.log(`\n⚡ CORD Session started`);
    console.log(`   Goal:  ${goal}`);
    console.log(`   Lock:  ${LOCK_PATH}\n`);

    return { goal, passphrase: sessionPassphrase, scope: defaultScope };
  },

  /** Return the current intent lock, or null if not set. */
  current: () => loadIntentLock(),

  /** Verify a session passphrase. */
  verify: (passphrase) => verifyPassphrase(passphrase),
};

// ── Re-exports ────────────────────────────────────────────────────────────────

module.exports = {
  // Core
  evaluate,
  session,

  // Middleware / client wrappers
  middleware:    mw.middleware,
  wrapOpenAI:    mw.wrapOpenAI,
  wrapAnthropic: mw.wrapAnthropic,

  // Explanation utilities
  explain,
  formatExplanation,
  DIMENSION_EXPLANATIONS,
  DECISION_CONTEXT,

  // Raw engine (for advanced use)
  engine: cordEngine,

  // Logging
  LOG_PATH,
};
