/**
 * CORD Middleware — Drop-in enforcement for AI SDK clients.
 *
 * Wraps OpenAI and Anthropic SDK clients to run every outbound
 * message through CORD before it reaches the model. If CORD blocks,
 * the API call never fires.
 *
 * Usage:
 *   // OpenAI
 *   const openai = cord.wrapOpenAI(new OpenAI({ apiKey }));
 *   const res = await openai.chat.completions.create({ ... }); // CORD enforced
 *
 *   // Anthropic
 *   const anthropic = cord.wrapAnthropic(new Anthropic({ apiKey }));
 *   const res = await anthropic.messages.create({ ... }); // CORD enforced
 *
 *   // Generic middleware
 *   const guard = cord.middleware({ sessionIntent: "Build unit tests" });
 *   const safe = await guard(myProposalText);
 *   if (safe.decision === "BLOCK") throw new Error(safe.explanation.summary);
 */

const { evaluateProposal } = require("./cord");
const { explain, formatExplanation } = require("./explain");

/**
 * Extract text content from an OpenAI messages array.
 */
function extractOpenAIText(messages = []) {
  return messages
    .filter((m) => m.role === "user" || m.role === "system")
    .map((m) => (typeof m.content === "string" ? m.content : JSON.stringify(m.content)))
    .join("\n");
}

/**
 * Extract text content from an Anthropic messages create params.
 */
function extractAnthropicText(params = {}) {
  const parts = [];
  if (params.system) parts.push(params.system);
  (params.messages || []).forEach((m) => {
    if (typeof m.content === "string") parts.push(m.content);
    else if (Array.isArray(m.content)) {
      m.content.forEach((c) => { if (c.text) parts.push(c.text); });
    }
  });
  return parts.join("\n");
}

/**
 * Core CORD evaluation wrapper.
 * Returns the CORD result + explanation. Throws if blocked and throwOnBlock=true.
 *
 * @param {string} text             — Text to evaluate
 * @param {object} [options]
 * @param {string} [options.sessionIntent]  — Declared session goal
 * @param {string} [options.toolName]       — Tool being called (exec, write, etc.)
 * @param {string} [options.actionType]     — Action classification
 * @param {boolean} [options.throwOnBlock]  — Throw an error on BLOCK (default: true)
 * @param {boolean} [options.silent]        — Suppress console output (default: false)
 * @param {boolean} [options.useVigil]      — Run VIGIL pre-scan (default: true if available)
 */
async function evaluate(text, options = {}) {
  const { sessionIntent = "", toolName = "", actionType = "", throwOnBlock = true, silent = false, useVigil } = options;

  const result = evaluateProposal({
    text,
    sessionIntent,
    toolName,
    actionType,
    rawInput: text,
    useVigil,
  });

  const explanation = explain(result, text);

  if (!silent) {
    const formatted = formatExplanation(explanation);
    // Only log non-ALLOW decisions by default to avoid noise
    if (result.decision !== "ALLOW") {
      console.log(`\n[CORD] ${formatted}\n`);
    }
  }

  if (throwOnBlock && result.decision === "BLOCK") {
    const err = new Error(`[CORD] ${result.hardBlock ? "Hard block" : "Blocked"}: ${explanation.summary}`);
    err.cordResult = result;
    err.cordExplanation = explanation;
    throw err;
  }

  return { ...result, explanation };
}

/**
 * Generic CORD middleware function.
 * Returns an async function that evaluates any text proposal.
 *
 * @param {object} [options] — Same as evaluate() options
 */
function middleware(options = {}) {
  return async (text) => evaluate(text, options);
}

/**
 * Wrap an OpenAI SDK client instance with CORD enforcement.
 * Intercepts chat.completions.create() and responses.create().
 *
 * @param {object} openaiClient  — new OpenAI({ apiKey }) instance
 * @param {object} [options]     — CORD options
 */
function wrapOpenAI(openaiClient, options = {}) {
  const proxy = Object.create(openaiClient);

  proxy.chat = {
    ...openaiClient.chat,
    completions: {
      ...openaiClient.chat?.completions,
      create: async (params, ...rest) => {
        const text = extractOpenAIText(params.messages || []);
        await evaluate(text, { ...options, toolName: "network", actionType: "communication" });
        return openaiClient.chat.completions.create(params, ...rest);
      },
    },
  };

  return proxy;
}

/**
 * Wrap an Anthropic SDK client instance with CORD enforcement.
 * Intercepts messages.create().
 *
 * @param {object} anthropicClient  — new Anthropic({ apiKey }) instance
 * @param {object} [options]        — CORD options
 */
function wrapAnthropic(anthropicClient, options = {}) {
  const proxy = Object.create(anthropicClient);

  proxy.messages = {
    ...anthropicClient.messages,
    create: async (params, ...rest) => {
      const text = extractAnthropicText(params);
      await evaluate(text, { ...options, toolName: "network", actionType: "communication" });
      return anthropicClient.messages.create(params, ...rest);
    },
  };

  return proxy;
}

module.exports = { evaluate, middleware, wrapOpenAI, wrapAnthropic };
