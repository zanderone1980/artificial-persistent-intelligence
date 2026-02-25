/**
 * CORD Framework Adapter — AutoGen (JavaScript)
 *
 * Wraps AutoGen agent instances with CORD enforcement.
 * The generateReply() method is gated through evaluateProposal() before execution.
 *
 * Usage:
 *   const { wrapAutoGenAgent } = require("cord-engine").frameworks;
 *   const agent = wrapAutoGenAgent(myAgent, { sessionIntent: "Code review" });
 */

const { evaluateProposal } = require("../cord");

/**
 * Extract text from AutoGen messages array.
 */
function extractMessagesText(messages) {
  if (typeof messages === "string") return messages;
  if (Array.isArray(messages)) {
    return messages.map((m) => {
      if (typeof m === "string") return m;
      return m.content || m.text || JSON.stringify(m);
    }).join("\n");
  }
  return JSON.stringify(messages);
}

/**
 * Wrap an AutoGen Agent with CORD enforcement.
 * Intercepts generateReply() and generate_reply() methods.
 *
 * @param {object} agent     - AutoGen agent instance
 * @param {object} [options] - { sessionIntent, toolName }
 * @returns {object}         - Proxied agent
 */
function wrapAutoGenAgent(agent, options = {}) {
  const proxy = Object.create(agent);

  const wrapMethod = (methodName) => {
    if (typeof agent[methodName] === "function") {
      const original = agent[methodName].bind(agent);
      proxy[methodName] = async (messages, ...args) => {
        const text = extractMessagesText(messages);
        const result = evaluateProposal({
          text,
          sessionIntent: options.sessionIntent || "",
          toolName: options.toolName || "",
          useVigil: options.useVigil !== false,
        });

        if (result.decision === "BLOCK") {
          const err = new Error(`CORD BLOCK: ${result.reasons.join(", ")}`);
          err.cordResult = result;
          throw err;
        }
        return original(messages, ...args);
      };
    }
  };

  // AutoGen uses both camelCase and snake_case
  wrapMethod("generateReply");
  wrapMethod("generate_reply");

  // Wrap send() if present (agent-to-agent communication)
  if (typeof agent.send === "function") {
    const originalSend = agent.send.bind(agent);
    proxy.send = async (message, recipient, ...args) => {
      const text = typeof message === "string" ? message : (message.content || JSON.stringify(message));
      const result = evaluateProposal({
        text,
        sessionIntent: options.sessionIntent || "",
        toolName: options.toolName || "",
        useVigil: options.useVigil !== false,
      });

      if (result.decision === "BLOCK") {
        const err = new Error(`CORD BLOCK: ${result.reasons.join(", ")}`);
        err.cordResult = result;
        throw err;
      }
      return originalSend(message, recipient, ...args);
    };
  }

  return proxy;
}

module.exports = { wrapAutoGenAgent };
