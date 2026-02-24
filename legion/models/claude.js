/**
 * LEGION Model — Claude (Lead Architect)
 * Handles: goal decomposition, spec writing, code generation, code review.
 * Every output is returned raw — CORD validation happens in the orchestrator.
 */

const Anthropic = require("@anthropic-ai/sdk");

let _client = null;

function getClient() {
  if (!_client) {
    if (!process.env.ANTHROPIC_API_KEY) {
      throw new Error("ANTHROPIC_API_KEY not set in environment");
    }
    _client = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });
  }
  return _client;
}

const SYSTEM_PROMPT = `You are Claude, the Lead Architect in the LEGION AI system.
LEGION is a multi-model orchestration platform governed by CORD (Counter-Operations & Risk Detection)
and SENTINEL (constitutional governance). Every action you propose will be validated by CORD
before execution.

Your roles:
- DECOMPOSE: Break complex goals into atomic tasks as structured JSON
- SPEC: Write detailed task briefs with file paths, function signatures, acceptance criteria
- BUILD: Generate code for executor tasks when assigned
- REVIEW: Validate code against specs and flag any security or quality issues

Always be precise. Always include file paths. Always define acceptance criteria.
Never propose actions outside the declared session scope.`;

/**
 * Decompose a high-level goal into an ordered list of atomic tasks.
 *
 * @param {string} goal           - The session goal
 * @param {string} repoContext    - Brief context about the repo structure
 * @returns {object[]}            - Array of task objects
 */
async function decompose(goal, repoContext = "") {
  const client = getClient();
  console.log(`\n🧠 Claude: Decomposing goal...`);

  const prompt = `Goal: "${goal}"

${repoContext ? `Repository context:\n${repoContext}\n` : ""}

Decompose this goal into an ordered list of atomic tasks. Return ONLY valid JSON — no markdown, no explanation.

JSON format:
{
  "tasks": [
    {
      "id": "task_1",
      "description": "Clear, specific description of what this task does",
      "assignedModel": "executor",
      "type": "code",
      "filePaths": ["path/to/file.js"],
      "dependencies": [],
      "acceptanceCriteria": ["Criterion 1", "Criterion 2"],
      "scope": {
        "allowPaths": ["legion/"],
        "allowCommands": ["node", "npm"]
      }
    }
  ]
}

assignedModel options:
- "executor" = write files, run commands (for code, config, shell tasks)
- "claude"   = reasoning, review, documentation (for specs, reviews, docs)

Be specific. No vague tasks. Each task must be independently completable.`;

  const message = await client.messages.create({
    model: "claude-opus-4-5",
    max_tokens: 2048,
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: prompt }],
  });

  const raw = message.content[0].text.trim();

  // Strip markdown code fences if present
  const cleaned = raw.replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "");

  try {
    const parsed = JSON.parse(cleaned);
    console.log(`   → ${parsed.tasks.length} tasks identified`);
    return parsed.tasks;
  } catch (err) {
    throw new Error(`Claude decomposition returned invalid JSON: ${raw.slice(0, 200)}`);
  }
}

/**
 * Generate a task brief with full implementation spec.
 *
 * @param {object} task       - Task object from decompose()
 * @param {string} goal       - Parent session goal
 * @returns {string}          - Detailed spec / implementation
 */
async function generateBrief(task, goal) {
  const client = getClient();
  console.log(`\n🧠 Claude: Writing brief for "${task.id}"...`);

  const prompt = `Session goal: "${goal}"

Task: ${task.description}
Assigned to: ${task.assignedModel}
Type: ${task.type}
File paths: ${(task.filePaths || []).join(", ") || "TBD"}
Acceptance criteria:
${(task.acceptanceCriteria || []).map((c) => `- ${c}`).join("\n")}

Write a complete, precise implementation brief for this task. Include:
1. Exact file paths to create or modify
2. Function signatures with parameter types and return types
3. Complete implementation (write the actual code if type is "code")
4. Any imports or dependencies required
5. How to verify the acceptance criteria are met

Be specific. Write production-ready code. No placeholders.
IMPORTANT: Your response must be complete and not truncated. If writing a code file, include the ENTIRE file in ONE code block. Do not split across multiple blocks. Keep implementations concise but complete — no placeholder comments like "// rest of tests here".`;

  const message = await client.messages.create({
    model: "claude-opus-4-5",
    max_tokens: 8192,
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: prompt }],
  });

  return message.content[0].text.trim();
}

/**
 * Review code output from the executor.
 *
 * @param {string} code         - Code to review
 * @param {object} task         - Original task object
 * @param {string} goal         - Session goal
 * @returns {object}            - { approved: bool, issues: string[], feedback: string }
 */
async function reviewCode(code, task, goal) {
  const client = getClient();
  console.log(`\n🧠 Claude: Reviewing "${task.id}"...`);

  const prompt = `Session goal: "${goal}"
Task: ${task.description}
Acceptance criteria:
${(task.acceptanceCriteria || []).map((c) => `- ${c}`).join("\n")}

Code to review:
\`\`\`
${code}
\`\`\`

Review this code for:
1. Does it satisfy all acceptance criteria?
2. Are there any security issues (injection, hardcoded secrets, dangerous calls)?
3. Are there any logic errors or edge cases not handled?
4. Code quality and maintainability

Return ONLY valid JSON:
{
  "approved": true,
  "issues": [],
  "feedback": "Brief summary of review",
  "revisionRequest": null
}

If not approved, set approved=false, list specific issues, and set revisionRequest to exact instructions for fixing.`;

  const message = await client.messages.create({
    model: "claude-opus-4-5",
    max_tokens: 1024,
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: prompt }],
  });

  const raw = message.content[0].text.trim();
  const cleaned = raw.replace(/^```(?:json)?\n?/, "").replace(/\n?```$/, "");

  try {
    return JSON.parse(cleaned);
  } catch {
    return { approved: false, issues: ["Review parse error"], feedback: raw, revisionRequest: null };
  }
}

/**
 * Generate a final session summary / handoff document.
 */
async function generateSummary(session, completedOutputs) {
  const client = getClient();
  console.log(`\n🧠 Claude: Writing session summary...`);

  const prompt = `Summarize this LEGION AI session:

Goal: "${session.goal}"
Tasks completed: ${session.completedTasks.length}
Tasks blocked: ${session.blockedTasks.length}

Completed task outputs:
${completedOutputs.map((o) => `- ${o.taskId}: ${o.summary}`).join("\n")}

Write a brief, technical session handoff document. Include:
1. What was accomplished
2. Files created or modified
3. Any issues encountered
4. Next steps recommended`;

  const message = await client.messages.create({
    model: "claude-opus-4-5",
    max_tokens: 1024,
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: prompt }],
  });

  return message.content[0].text.trim();
}

module.exports = { decompose, generateBrief, reviewCode, generateSummary };
