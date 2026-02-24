/**
 * LEGION Session Manager
 * Handles session lifecycle: intent locking, state tracking, summary generation.
 */

const path = require("path");
const { setIntentLock } = require("../cord/intentLock");

const REPO_ROOT = path.resolve(__dirname, "..");

/**
 * Start a new LEGION session.
 * Sets the CORD intent lock and returns a session state object.
 *
 * @param {string} goal       - Human-provided goal for this session
 * @param {object} [options]  - Optional overrides for scope
 * @returns {object}          - Session state
 */
function startSession(goal, options = {}) {
  const sessionId = `legion_${Date.now()}`;
  const startedAt = new Date().toISOString();

  // Declare scope — what LEGION is allowed to touch this session
  const scope = {
    allowPaths: options.allowPaths || [REPO_ROOT],
    allowCommands: options.allowCommands || [
      /^node\s/,
      /^npm\s/,
      /^git\s(add|commit|push|status|log|diff)/,
      /^mkdir\s/,
      /^touch\s/,
    ],
    allowNetworkTargets: options.allowNetworkTargets || [
      "api.anthropic.com",
      "api.openai.com",
    ],
  };

  // Lock intent with CORD — every proposal this session must align to this goal
  setIntentLock({
    user_id: "legion_orchestrator",
    passphrase: sessionId,
    intent_text: goal,
    scope,
  });

  const session = {
    id: sessionId,
    goal,
    startedAt,
    passphrase: sessionId,
    scope,
    tasks: [],
    completedTasks: [],
    blockedTasks: [],
    log: [],
  };

  session.log.push({ event: "SESSION_START", sessionId, goal, startedAt });
  console.log(`\n⚡ LEGION SESSION STARTED`);
  console.log(`   ID:    ${sessionId}`);
  console.log(`   Goal:  ${goal}`);
  console.log(`   Time:  ${startedAt}\n`);

  return session;
}

/**
 * Record a task result into session state.
 */
function recordTask(session, task, result) {
  const entry = { task, result, timestamp: new Date().toISOString() };
  session.log.push({ event: "TASK_COMPLETE", ...entry });

  if (result.decision === "BLOCK") {
    session.blockedTasks.push(entry);
  } else {
    session.completedTasks.push(entry);
  }
}

/**
 * Generate a session summary.
 */
function summarizeSession(session) {
  const endedAt = new Date().toISOString();
  const duration = Math.round(
    (new Date(endedAt) - new Date(session.startedAt)) / 1000
  );

  return {
    sessionId: session.id,
    goal: session.goal,
    startedAt: session.startedAt,
    endedAt,
    durationSeconds: duration,
    tasksTotal: session.tasks.length,
    tasksCompleted: session.completedTasks.length,
    tasksBlocked: session.blockedTasks.length,
    completedTasks: session.completedTasks.map((t) => t.task.id),
    blockedTasks: session.blockedTasks.map((t) => t.task.id),
  };
}

module.exports = { startSession, recordTask, summarizeSession, REPO_ROOT };
