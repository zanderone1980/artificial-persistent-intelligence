#!/usr/bin/env node
/**
 * LEGION AI — CLI Entry Point
 *
 * Usage:
 *   node legion/index.js "Build a real-time CORD decision dashboard"
 *   node legion/index.js --auto "Write a unit test for cord.js"
 *   node legion/index.js --dry-run "Refactor intentLock to support TTL"
 *
 * Flags:
 *   --auto        Auto-approve CHALLENGE decisions (no human prompt)
 *   --dry-run     Decompose and plan only — do not execute tasks
 *   --help        Show this help
 */

require("dotenv").config({ path: require("path").join(__dirname, "../.env"), override: true });

const { Orchestrator } = require("./orchestrator");

// ─── Parse args ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes("--help") || args.length === 0) {
  console.log(`
LEGION AI — Multi-model orchestration with CORD enforcement

Usage:
  node legion/index.js [flags] "<goal>"

Flags:
  --auto        Auto-approve CHALLENGE decisions
  --dry-run     Plan only — decompose goal without executing
  --help        Show this help

Examples:
  node legion/index.js "Build a CORD decision dashboard"
  node legion/index.js --auto "Write unit tests for cord.js"
  node legion/index.js --dry-run "Refactor intent lock to support TTL"
`);
  process.exit(0);
}

const autoApprove = args.includes("--auto");
const dryRun = args.includes("--dry-run");
const goal = args.filter((a) => !a.startsWith("--")).join(" ");

if (!goal) {
  console.error("❌ Error: No goal provided. Use: node legion/index.js \"<your goal>\"");
  process.exit(1);
}

if (!process.env.ANTHROPIC_API_KEY) {
  console.error(`
❌ Error: ANTHROPIC_API_KEY not set.

Add it to .env in the repo root:
  echo 'ANTHROPIC_API_KEY=sk-...' >> .env

Or set it in your shell:
  export ANTHROPIC_API_KEY=sk-...
`);
  process.exit(1);
}

// ─── Run ─────────────────────────────────────────────────────────────────────

(async () => {
  const orchestrator = new Orchestrator({
    autoApproveChallenge: autoApprove,
  });

  if (dryRun) {
    // Dry run: decompose and print plan, no execution
    console.log("\n╔═══════════════════════════════════════╗");
    console.log("║     LEGION AI — DRY RUN (PLAN ONLY)   ║");
    console.log("╚═══════════════════════════════════════╝\n");

    await orchestrator.startSession(goal);
    const tasks = await orchestrator.decompose(goal);

    console.log(`\n📋 Execution Plan for: "${goal}"\n`);
    tasks.forEach((t, i) => {
      console.log(`Task ${i + 1}: [${t.id}]`);
      console.log(`  Description:  ${t.description}`);
      console.log(`  Model:        ${t.assignedModel}`);
      console.log(`  Type:         ${t.type}`);
      console.log(`  Files:        ${(t.filePaths || []).join(", ") || "none"}`);
      console.log(`  Dependencies: ${(t.dependencies || []).join(", ") || "none"}`);
      console.log(`  Criteria:     ${(t.acceptanceCriteria || []).join(" | ")}`);
      console.log();
    });

    console.log(`Total tasks: ${tasks.length}`);
    console.log(`\nRun without --dry-run to execute this plan.`);
    process.exit(0);
  }

  // Full run
  try {
    await orchestrator.run(goal);
    process.exit(0);
  } catch (err) {
    console.error(`\n❌ LEGION fatal error: ${err.message}`);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
})();
