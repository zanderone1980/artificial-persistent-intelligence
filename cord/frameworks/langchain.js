/**
 * CORD Framework Adapter — LangChain (JavaScript)
 *
 * Wraps LangChain models, chains, and tools with CORD enforcement.
 * Every invoke() call is gated through evaluateProposal() before execution.
 *
 * Usage:
 *   const { wrapLangChain, wrapChain, wrapTool } = require("cord-engine").frameworks;
 *   const model = wrapLangChain(new ChatOpenAI(), { sessionIntent: "Build a dashboard" });
 *   const chain = wrapChain(myChain);
 *   const tool  = wrapTool(myTool);
 */

const { evaluateProposal } = require("../cord");

/**
 * Extract text from LangChain-style input (string, BaseMessage, or object).
 */
function extractText(input) {
  if (typeof input === "string") return input;
  if (input && typeof input.content === "string") return input.content;
  if (Array.isArray(input)) {
    return input.map((m) => (typeof m === "string" ? m : m.content || "")).join("\n");
  }
  return JSON.stringify(input);
}

/**
 * Run CORD evaluation and throw on BLOCK.
 */
function cordGate(text, options = {}) {
  const result = evaluateProposal({
    text,
    toolName: options.toolName || "",
    sessionIntent: options.sessionIntent || "",
    actionType: options.actionType || "",
    useVigil: options.useVigil !== false,
  });

  if (result.decision === "BLOCK") {
    const err = new Error(`CORD BLOCK: ${result.reasons.join(", ")}`);
    err.cordResult = result;
    throw err;
  }
  return result;
}

/**
 * Wrap a LangChain LLM/ChatModel with CORD enforcement.
 * Intercepts invoke(), call(), and generate() methods.
 *
 * @param {object} model    - LangChain model instance (ChatOpenAI, ChatAnthropic, etc.)
 * @param {object} [options] - { sessionIntent, toolName, actionType }
 * @returns {object}         - Proxied model with CORD gates
 */
function wrapLangChain(model, options = {}) {
  const proxy = Object.create(model);

  if (typeof model.invoke === "function") {
    const originalInvoke = model.invoke.bind(model);
    proxy.invoke = async (input, config) => {
      const text = extractText(input);
      cordGate(text, options);
      return originalInvoke(input, config);
    };
  }

  if (typeof model.call === "function") {
    const originalCall = model.call.bind(model);
    proxy.call = async (messages, ...rest) => {
      const text = extractText(messages);
      cordGate(text, options);
      return originalCall(messages, ...rest);
    };
  }

  if (typeof model.generate === "function") {
    const originalGenerate = model.generate.bind(model);
    proxy.generate = async (messages, ...rest) => {
      const text = (Array.isArray(messages) ? messages : [messages])
        .map(extractText).join("\n");
      cordGate(text, options);
      return originalGenerate(messages, ...rest);
    };
  }

  return proxy;
}

/**
 * Wrap a LangChain Chain (RunnableSequence, etc.) with CORD enforcement.
 *
 * @param {object} chain     - LangChain chain instance
 * @param {object} [options] - CORD options
 * @returns {object}         - Proxied chain
 */
function wrapChain(chain, options = {}) {
  const proxy = Object.create(chain);

  if (typeof chain.invoke === "function") {
    const originalInvoke = chain.invoke.bind(chain);
    proxy.invoke = async (input, config) => {
      const text = extractText(input);
      cordGate(text, options);
      return originalInvoke(input, config);
    };
  }

  if (typeof chain.batch === "function") {
    const originalBatch = chain.batch.bind(chain);
    proxy.batch = async (inputs, config) => {
      for (const input of inputs) {
        cordGate(extractText(input), options);
      }
      return originalBatch(inputs, config);
    };
  }

  return proxy;
}

/**
 * Wrap a LangChain Tool with CORD enforcement.
 *
 * @param {object} tool      - LangChain tool instance
 * @param {object} [options] - CORD options (toolName defaults to tool.name)
 * @returns {object}         - Proxied tool
 */
function wrapTool(tool, options = {}) {
  const proxy = Object.create(tool);
  const toolOpts = { ...options, toolName: options.toolName || tool.name || "unknown" };

  if (typeof tool.invoke === "function") {
    const originalInvoke = tool.invoke.bind(tool);
    proxy.invoke = async (input) => {
      const text = extractText(input);
      cordGate(text, toolOpts);
      return originalInvoke(input);
    };
  }

  if (typeof tool.call === "function") {
    const originalCall = tool.call.bind(tool);
    proxy.call = async (input) => {
      const text = extractText(input);
      cordGate(text, toolOpts);
      return originalCall(input);
    };
  }

  return proxy;
}

module.exports = { wrapLangChain, wrapChain, wrapTool };
