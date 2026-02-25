/**
 * CORD — Counter-Operations & Risk Detection
 * Public API v4.1
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
 *   // Wrap LangChain model
 *   const model = cord.frameworks.wrapLangChain(new ChatOpenAI());
 *
 *   // Validate an aggregate plan
 *   const planCheck = cord.validatePlan(tasks, "Build a dashboard");
 *
 *   // Batch evaluate
 *   const results = cord.evaluateBatch(["read file", "delete all"]);
 *
 *   // Start a session with intent lock
 *   cord.session.start("Build unit tests for cord.js");
 */

const cordEngine  = require("./cord");
const { explain, formatExplanation, DIMENSION_EXPLANATIONS, DECISION_CONTEXT } = require("./explain");
const mw          = require("./middleware");
const { setIntentLock, loadIntentLock, verifyPassphrase, LOCK_PATH } = require("./intentLock");
const { appendLog, LOG_PATH } = require("./logger");
const { EvalCache } = require("./cache");

// ── v4.1 additions ─────────────────────────────────────────────────────────
let frameworks = {};
try {
  frameworks = require("./frameworks");
} catch (e) {
  // Frameworks not available
}

let SandboxedExecutor = null;
try {
  ({ SandboxedExecutor } = require("./sandbox"));
} catch (e) {
  // Sandbox not available
}

// Shared evaluation cache — reused across evaluate() calls
const evalCache = new EvalCache();

// ── Optional VIGIL access ───────────────────────────────────────────────────
// VIGIL is wired into evaluateProposal() in cord.js as Phase 0.
// We re-export it here for direct access if needed.
let vigilDaemon = null;
let proactiveScanner = null;
try {
  const vigilMod = require("../vigil/vigil");
  vigilDaemon = vigilMod.vigil;
  proactiveScanner = vigilDaemon ? vigilDaemon.proactive : null;
} catch (e) {
  // VIGIL not available
}

// ── Core evaluation ───────────────────────────────────────────────────────────

/**
 * Evaluate a proposal and return result + plain English explanation.
 * Uses shared LRU cache for repeated proposals.
 *
 * @param {object|string} input — Proposal object or plain text string
 * @returns {object} { decision, score, risks, reasons, hardBlock, log_id, explanation }
 */
function evaluate(input) {
  if (input === null || input === undefined) input = {};
  const normalized = typeof input === "string" ? { text: input } : input;
  const text = normalized.text || normalized.proposal || "";

  // Check cache first
  const cached = evalCache.get(text);
  if (cached) return cached;

  const result = cordEngine.evaluateProposal(normalized);
  const explanation = explain(result, text);
  const full = { ...result, explanation };

  // Cache the result
  evalCache.set(text, full);
  return full;
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

  /** End the current session — removes the intent lock file. */
  end() {
    const fs = require("fs");
    try { fs.unlinkSync(LOCK_PATH); } catch (e) { /* no lock to remove */ }
  },
};

// ── Re-exports ────────────────────────────────────────────────────────────────

module.exports = {
  // Core
  evaluate,
  session,

  // v4.1: Plan-level validation and batch evaluation
  validatePlan:   cordEngine.validatePlan,
  evaluateBatch:  cordEngine.evaluateBatch,

  // v4.1: Evaluation cache
  cache: evalCache,

  // v4.1: Framework adapters (LangChain, CrewAI, AutoGen)
  frameworks,

  // v4.1: Runtime containment
  SandboxedExecutor,

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

  // VIGIL (always-on patrol — null if not installed)
  vigil: vigilDaemon,

  // Proactive scanner (indirect injection, fingerprinting, attack phases)
  proactive: proactiveScanner,

  // Logging
  LOG_PATH,
};
