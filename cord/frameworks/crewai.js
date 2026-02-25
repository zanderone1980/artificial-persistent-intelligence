/**
 * CORD Framework Adapter — CrewAI (JavaScript)
 *
 * Wraps CrewAI agent instances with CORD enforcement.
 * The execute() method is gated through evaluateProposal() before execution.
 *
 * Usage:
 *   const { wrapCrewAgent } = require("cord-engine").frameworks;
 *   const agent = wrapCrewAgent(myCrewAgent, { sessionIntent: "Research task" });
 */

const { evaluateProposal } = require("../cord");

/**
 * Extract text from a CrewAI task object or string.
 */
function extractTaskText(task) {
  if (typeof task === "string") return task;
  if (task && task.description) return task.description;
  if (task && task.expected_output) return `${task.description || ""}\n${task.expected_output}`;
  return JSON.stringify(task);
}

/**
 * Wrap a CrewAI Agent with CORD enforcement.
 * Intercepts execute() and execute_task() methods.
 *
 * @param {object} agent     - CrewAI agent instance
 * @param {object} [options] - { sessionIntent, toolName }
 * @returns {object}         - Proxied agent
 */
function wrapCrewAgent(agent, options = {}) {
  const proxy = Object.create(agent);

  if (typeof agent.execute === "function") {
    const originalExecute = agent.execute.bind(agent);
    proxy.execute = async (task, ...args) => {
      const text = extractTaskText(task);
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
      return originalExecute(task, ...args);
    };
  }

  if (typeof agent.execute_task === "function") {
    const originalExecuteTask = agent.execute_task.bind(agent);
    proxy.execute_task = async (task, context, tools) => {
      const text = extractTaskText(task);
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
      return originalExecuteTask(task, context, tools);
    };
  }

  return proxy;
}

module.exports = { wrapCrewAgent };
