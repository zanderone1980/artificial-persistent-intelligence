/**
 * LEGION Model — Executor (OpenClaw / Local Builder)
 * Handles: writing files, running commands, git operations.
 * CORD validation happens BEFORE any action in the orchestrator.
 * This module only executes pre-approved actions.
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { REPO_ROOT } = require("../session");

/**
 * Write content to a file (pre-approved by CORD).
 * Creates parent directories if needed.
 *
 * @param {string} filePath   - Path to write (relative to repo root or absolute)
 * @param {string} content    - File content
 * @returns {object}          - { success, filePath, bytesWritten }
 */
function writeFile(filePath, content) {
  const abs = path.isAbsolute(filePath)
    ? filePath
    : path.join(REPO_ROOT, filePath);

  // Verify still inside repo root (belt + suspenders — CORD already checked)
  if (!abs.startsWith(REPO_ROOT)) {
    throw new Error(`EXECUTOR: Path escape attempt blocked: ${abs}`);
  }

  const dir = path.dirname(abs);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(abs, content, "utf8");
  const stat = fs.statSync(abs);

  console.log(`   ✅ Wrote ${stat.size} bytes → ${path.relative(REPO_ROOT, abs)}`);
  return { success: true, filePath: abs, bytesWritten: stat.size };
}

/**
 * Run a shell command (pre-approved by CORD).
 * Runs in repo root, captures output.
 *
 * @param {string} command    - Shell command to execute
 * @param {object} [options]  - execSync options override
 * @returns {object}          - { success, stdout, stderr }
 */
function runCommand(command, options = {}) {
  console.log(`   ⚙️  Exec: ${command}`);
  try {
    const stdout = execSync(command, {
      cwd: REPO_ROOT,
      encoding: "utf8",
      timeout: 30000,
      ...options,
    });
    console.log(`   ✅ Done`);
    return { success: true, stdout: stdout || "", stderr: "" };
  } catch (err) {
    console.error(`   ❌ Command failed: ${err.message}`);
    return { success: false, stdout: "", stderr: err.message };
  }
}

/**
 * Extract code blocks from a brief string (Claude output).
 * Returns an array of { language, code } objects.
 * Handles both closed blocks (``` ... ```) and unclosed blocks
 * (truncated responses where closing ``` never arrives).
 *
 * @param {string} text - Raw text potentially containing ```code blocks
 * @returns {Array<{language: string, code: string}>}
 */
function extractCodeBlocks(text) {
  const blocks = [];

  // Closed blocks first
  const re = /```(\w+)?\n([\s\S]*?)```/g;
  let match;
  while ((match = re.exec(text)) !== null) {
    blocks.push({
      language: match[1] || "text",
      code: match[2].trim(),
    });
  }

  // If no closed blocks found, look for an unclosed opening (truncated response)
  if (blocks.length === 0) {
    const openRe = /```(\w+)?\n([\s\S]+)$/;
    const openMatch = text.match(openRe);
    if (openMatch) {
      blocks.push({
        language: openMatch[1] || "text",
        code: openMatch[2].trim(),
        truncated: true,
      });
    }
  }

  return blocks;
}

/**
 * Pick the best code block from a brief for a given file path.
 * Strategy: prefer blocks whose language matches the file extension.
 * Falls back to the largest block if no language match found.
 *
 * @param {Array<{language, code}>} blocks  - Extracted code blocks
 * @param {string} filePath                 - Target file path
 * @returns {{language, code}|null}
 */
function bestBlockForFile(blocks, filePath) {
  if (blocks.length === 0) return null;

  const ext = filePath.split(".").pop().toLowerCase();
  const langMap = {
    js: ["javascript", "js", "node"],
    ts: ["typescript", "ts"],
    py: ["python", "py"],
    json: ["json"],
    md: ["markdown", "md"],
    sh: ["bash", "sh", "shell"],
    css: ["css"],
    html: ["html"],
  };
  const targetLangs = langMap[ext] || [];

  // First: exact language match
  const langMatch = blocks.find((b) => targetLangs.includes(b.language.toLowerCase()));
  if (langMatch) return langMatch;

  // Second: largest block (most likely to be the real implementation)
  return blocks.reduce((best, b) => (b.code.length > best.code.length ? b : best), blocks[0]);
}

/**
 * Parse a brief and execute approved file writes.
 * Extracts code blocks and matches them to file paths by language/size heuristic.
 *
 * @param {string} brief        - Claude-generated brief (may contain code blocks)
 * @param {object} task         - Task object with filePaths
 * @returns {Array<object>}     - Array of write results
 */
function executeBrief(brief, task) {
  const filePaths = task.filePaths || [];
  const blocks = extractCodeBlocks(brief);
  const results = [];

  if (filePaths.length === 0 || blocks.length === 0) {
    console.log(`   ℹ️  No files to write for "${task.id}"`);
    return results;
  }

  for (const filePath of filePaths) {
    const block = bestBlockForFile(blocks, filePath);
    if (block) {
      const result = writeFile(filePath, block.code);
      results.push({ filePath, ...result });
    } else {
      console.log(`   ⚠️  No matching code block found for ${filePath}`);
    }
  }

  return results;
}

/**
 * Stage and commit all changes to git.
 *
 * @param {string} message    - Commit message
 * @returns {object}          - Command result
 */
function gitCommit(message) {
  console.log(`\n📦 Git: Staging all changes...`);
  runCommand("git add -A");
  console.log(`📦 Git: Committing...`);
  return runCommand(`git commit -m "${message.replace(/"/g, '\\"')}"`);
}

module.exports = { writeFile, runCommand, executeBrief, extractCodeBlocks, gitCommit };
