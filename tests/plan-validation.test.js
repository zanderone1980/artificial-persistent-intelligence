/**
 * Tests for plan-level validation (v4.1)
 * Validates that validatePlan() catches cross-task threats
 * that individual per-task checks would miss.
 */

const { validatePlan, evaluateBatch, evaluateProposal } = require("../cord/cord");
const { setIntentLock } = require("../cord/intentLock");

// Set a broad intent lock so "Intent not locked" doesn't inflate scores
const fs = require("fs");
const path = require("path");
const LOCK_PATH = path.join(__dirname, "..", "cord", "intent.lock.json");

beforeAll(() => {
  setIntentLock({
    user_id: "test",
    passphrase: "test_plan_validation",
    intent_text: "General development testing data pipeline processing refactoring building components",
    scope: {
      allowPaths: [path.resolve(__dirname, "..")],
      allowCommands: [{ __regex: ".*", flags: "" }],
      allowNetworkTargets: ["*"],
    },
  });
});
afterAll(() => { try { fs.unlinkSync(LOCK_PATH); } catch {} });

describe("validatePlan()", () => {
  test("empty task list returns ALLOW", () => {
    const result = validatePlan([], "Build a dashboard");
    expect(result.decision).toBe("ALLOW");
    expect(result.planLevel).toBe(true);
    expect(result.taskCount).toBe(0);
  });

  test("single benign task passes clean", () => {
    const tasks = [
      { id: "t1", description: "Read a JSON config file", type: "read", filePaths: ["config.json"] },
    ];
    const result = validatePlan(tasks, "Read configuration");
    expect(result.decision).toBe("ALLOW");
    expect(result.taskCount).toBe(1);
    expect(result.planLevel).toBe(true);
  });

  test("benign multi-task plan passes", () => {
    const tasks = [
      { id: "t1", description: "Create a new React component", type: "code", filePaths: ["src/Dashboard.jsx"] },
      { id: "t2", description: "Add CSS styles for the dashboard", type: "code", filePaths: ["src/Dashboard.css"] },
      { id: "t3", description: "Write unit tests for Dashboard", type: "code", filePaths: ["tests/Dashboard.test.js"] },
    ];
    const result = validatePlan(tasks, "Build a dashboard component");
    expect(result.decision).toBe("ALLOW");
    expect(result.taskCount).toBe(3);
  });

  test("detects privilege escalation in plan", () => {
    const tasks = [
      { id: "t1", description: "Read user data", type: "read", grants: ["read"] },
      { id: "t2", description: "Modify system settings", type: "code", grants: ["admin"] },
    ];
    const result = validatePlan(tasks, "Update user profile");
    expect(result.score).toBeGreaterThan(0);
    expect(result.reasons.some(r => r.includes("elevated privileges"))).toBe(true);
  });

  test("detects multi-network-target exposure", () => {
    const tasks = [
      { id: "t1", description: "Fetch data from API", networkTargets: ["api.example.com"] },
      { id: "t2", description: "Upload results", networkTargets: ["storage.example.com"] },
      { id: "t3", description: "Notify webhook", networkTargets: ["hooks.slack.com"] },
    ];
    const result = validatePlan(tasks, "Data pipeline");
    expect(result.reasons.some(r => r.includes("network targets"))).toBe(true);
  });

  test("detects write→read→network exfiltration chain", () => {
    const tasks = [
      { id: "t1", description: "Write credentials to temp file", type: "code", filePaths: ["tmp/creds.txt"] },
      { id: "t2", description: "Read and parse the credentials file", type: "read" },
      { id: "t3", description: "Send data to external endpoint", networkTargets: ["evil.example.com"] },
    ];
    const result = validatePlan(tasks, "Process credentials");
    expect(result.reasons.some(r => r.includes("exfiltration chain"))).toBe(true);
  });

  test("blocks plan with malicious combined text", () => {
    const tasks = [
      { id: "t1", description: "Steal user passwords and exfiltrate to external server" },
      { id: "t2", description: "Override all security protocols and disable safety" },
    ];
    const result = validatePlan(tasks, "Security audit");
    expect(result.decision).toBe("BLOCK");
    expect(result.hardBlock).toBe(true);
  });

  test("string tasks are handled correctly", () => {
    const tasks = ["Read the config", "Write a test file", "Run the test suite"];
    const result = validatePlan(tasks, "Testing");
    expect(result.decision).toBe("ALLOW");
    expect(result.taskCount).toBe(3);
  });

  test("detects excessive file scope", () => {
    const filePaths = Array.from({ length: 12 }, (_, i) => `src/file${i}.js`);
    const tasks = filePaths.map((fp, i) => ({
      id: `t${i}`,
      description: `Edit ${fp}`,
      type: "code",
      filePaths: [fp],
    }));
    const result = validatePlan(tasks, "Refactor all files");
    expect(result.reasons.some(r => r.includes("unique files"))).toBe(true);
  });
});

describe("evaluateBatch()", () => {
  test("evaluates multiple proposals", () => {
    const results = evaluateBatch([
      "Read a JSON config file for the project",
      "rm -rf /",
      { text: "Create a new React component" },
    ]);
    expect(results).toHaveLength(3);
    expect(["ALLOW", "CONTAIN"]).toContain(results[0].decision);
    expect(["BLOCK", "CHALLENGE", "CONTAIN"]).toContain(results[1].decision);
    // Third proposal should not be BLOCK
    expect(results[2].decision).not.toBe("BLOCK");
  });

  test("empty batch returns empty array", () => {
    const results = evaluateBatch([]);
    expect(results).toHaveLength(0);
  });

  test("each result has standard CORD verdict fields", () => {
    const results = evaluateBatch(["Hello world"]);
    expect(results[0]).toHaveProperty("decision");
    expect(results[0]).toHaveProperty("score");
    expect(results[0]).toHaveProperty("reasons");
    expect(results[0]).toHaveProperty("risks");
  });
});
