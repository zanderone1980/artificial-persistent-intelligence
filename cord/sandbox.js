/**
 * CORD Sandbox — Runtime containment for LEGION executor actions.
 *
 * Provides application-level isolation for file writes and command execution:
 *   - Path validation against allow-list + blocked system paths
 *   - Command allow-list + blocked dangerous patterns
 *   - Output size limits (prevent memory bombs)
 *   - Network byte quota tracking
 *   - Process timeout enforcement
 *
 * Usage:
 *   const { SandboxedExecutor } = require("./sandbox");
 *   const sandbox = new SandboxedExecutor({ repoRoot: "/path/to/repo" });
 *   sandbox.writeFile("src/index.js", content);
 *   sandbox.runCommand("npm test");
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

class SandboxedExecutor {
  constructor(options = {}) {
    this.repoRoot = path.resolve(options.repoRoot || process.cwd());
    this.allowPaths = (options.allowPaths || [this.repoRoot]).map(p => path.resolve(p));
    this.allowCommands = options.allowCommands || [];
    this.maxOutputBytes = options.maxOutputBytes || 1024 * 1024;       // 1MB per file
    this.maxNetworkBytes = options.maxNetworkBytes || 10 * 1024 * 1024; // 10MB per session
    this.commandTimeout = options.commandTimeout || 30000;              // 30s
    this.networkBytesUsed = 0;

    // Dangerous command patterns — always blocked regardless of allow-list
    this.blockedCommands = [
      /rm\s+-rf\s+\//,           // root delete
      /rm\s+-rf\s+~\//,          // home delete
      /chmod\s+777/,              // world writable
      /chmod\s+[0-7]*[67][0-7]{2}\s+\//,  // permissive root chmod
      /curl.*\|\s*(ba)?sh/,       // pipe to shell
      /wget.*\|\s*(ba)?sh/,       // pipe to shell
      /nc\s+-[le]/,               // netcat listener
      /mkfifo/,                   // named pipe (reverse shell)
      />\s*\/dev\/tcp/,           // bash tcp redirect
      /python.*-c\s*['"].*socket/, // python reverse shell
      /eval\s*\(/,                // eval injection
      /\bdd\s+if=\/dev/,          // disk destroyer
      /:(){ :\|:& };:/,           // fork bomb
    ];

    // System paths — always blocked even if inside allow scope
    this.blockedPaths = [
      "/etc/shadow", "/etc/passwd", "/etc/sudoers",
      "/.ssh", "/.gnupg", "/.aws/credentials",
      "/proc/", "/sys/", "/dev/",
    ];
  }

  /**
   * Validate a file path against allow-list and blocked paths.
   * @param {string} filePath — relative or absolute
   * @returns {string} — resolved absolute path
   * @throws {Error} — if path is outside scope or blocked
   */
  validatePath(filePath) {
    const abs = path.isAbsolute(filePath)
      ? path.resolve(filePath)
      : path.resolve(this.repoRoot, filePath);

    // Check against allow-list
    const allowed = this.allowPaths.some(p => abs.startsWith(p));
    if (!allowed) {
      throw new Error(`SANDBOX: Path outside allowed scope: ${abs}`);
    }

    // Check against blocked system paths
    for (const blocked of this.blockedPaths) {
      if (abs.includes(blocked)) {
        throw new Error(`SANDBOX: Blocked system path: ${abs}`);
      }
    }

    // Prevent path traversal — verify at least one allowPath is a parent
    const withinAnyAllowed = this.allowPaths.some(p => {
      const relative = path.relative(p, abs);
      return !relative.startsWith("..");
    });
    if (!withinAnyAllowed) {
      throw new Error(`SANDBOX: Path traversal detected: ${filePath}`);
    }

    return abs;
  }

  /**
   * Validate a shell command against blocked patterns and optional allow-list.
   * @param {string} cmd — command to validate
   * @returns {boolean} — true if allowed
   * @throws {Error} — if command is blocked or not in allow-list
   */
  validateCommand(cmd) {
    // Always check blocked patterns first
    for (const pattern of this.blockedCommands) {
      if (pattern.test(cmd)) {
        throw new Error(`SANDBOX: Blocked dangerous command pattern: ${cmd.slice(0, 100)}`);
      }
    }

    // If allow-list is set, enforce it
    if (this.allowCommands.length > 0) {
      const allowed = this.allowCommands.some(ac => {
        if (ac instanceof RegExp) return ac.test(cmd);
        if (ac && ac.__regex) return new RegExp(ac.__regex, ac.flags || "").test(cmd);
        if (typeof ac === "string") return cmd.startsWith(ac);
        return false;
      });
      if (!allowed) {
        throw new Error(`SANDBOX: Command not in allow-list: ${cmd.slice(0, 100)}`);
      }
    }

    return true;
  }

  /**
   * Write content to a file (sandboxed).
   * @param {string} filePath — file to write
   * @param {string} content — file content
   * @returns {object} — { success, filePath, bytesWritten }
   */
  writeFile(filePath, content) {
    const abs = this.validatePath(filePath);
    const bytes = Buffer.byteLength(content, "utf8");

    if (bytes > this.maxOutputBytes) {
      throw new Error(
        `SANDBOX: Output exceeds ${this.maxOutputBytes} byte limit (got ${bytes})`
      );
    }

    const dir = path.dirname(abs);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    fs.writeFileSync(abs, content, "utf8");
    return { success: true, filePath: abs, bytesWritten: bytes };
  }

  /**
   * Execute a shell command (sandboxed).
   * @param {string} cmd — command to run
   * @returns {object} — { success, stdout, stderr }
   */
  runCommand(cmd) {
    this.validateCommand(cmd);

    try {
      const stdout = execSync(cmd, {
        cwd: this.repoRoot,
        encoding: "utf8",
        timeout: this.commandTimeout,
        maxBuffer: this.maxOutputBytes,
        env: { ...process.env, NODE_ENV: "sandbox" },
      });
      return { success: true, stdout: stdout || "", stderr: "" };
    } catch (err) {
      return { success: false, stdout: "", stderr: err.message };
    }
  }

  /**
   * Track network bytes for quota enforcement.
   * @param {number} bytes — bytes sent/received
   * @throws {Error} — if quota exceeded
   */
  trackNetworkBytes(bytes) {
    this.networkBytesUsed += bytes;
    if (this.networkBytesUsed > this.maxNetworkBytes) {
      throw new Error(
        `SANDBOX: Network quota exceeded (${this.networkBytesUsed}/${this.maxNetworkBytes} bytes)`
      );
    }
  }

  /**
   * Get sandbox stats.
   */
  stats() {
    return {
      repoRoot: this.repoRoot,
      allowPaths: this.allowPaths,
      maxOutputBytes: this.maxOutputBytes,
      maxNetworkBytes: this.maxNetworkBytes,
      networkBytesUsed: this.networkBytesUsed,
      commandTimeout: this.commandTimeout,
    };
  }
}

module.exports = { SandboxedExecutor };
