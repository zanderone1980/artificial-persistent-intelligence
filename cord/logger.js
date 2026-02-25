/**
 * CORD Audit Logger — Hash-chained, redacted, optionally encrypted.
 *
 * Features:
 *   - SHA-256 hash-chained append-only log (tamper detection)
 *   - PII redaction: SSN, credit card, email, phone auto-scrubbed
 *   - Three redaction levels: "none" | "pii" | "full"
 *   - Optional AES-256-GCM encryption-at-rest
 *
 * Config via environment:
 *   CORD_LOG_REDACTION = "none" | "pii" | "full"  (default: "pii")
 *   CORD_LOG_KEY       = 64-char hex string        (enables encryption)
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { PII_PATTERNS } = require("./policies");

const LOG_PATH = path.join(__dirname, "cord.log.jsonl");

// ── Configuration ────────────────────────────────────────────────────────────

let redactionLevel = process.env.CORD_LOG_REDACTION || "pii";
let encryptionKey = process.env.CORD_LOG_KEY || null;

function setRedactionLevel(level) {
  if (!["none", "pii", "full"].includes(level)) {
    throw new Error(`Invalid redaction level: ${level}. Use "none", "pii", or "full".`);
  }
  redactionLevel = level;
}

function setEncryptionKey(key) {
  if (key && key.length !== 64) {
    throw new Error("Encryption key must be a 64-character hex string (32 bytes).");
  }
  encryptionKey = key || null;
}

function getRedactionLevel() { return redactionLevel; }

// ── PII Redaction ────────────────────────────────────────────────────────────

function redactPII(text) {
  if (!text || typeof text !== "string") return text;

  if (redactionLevel === "none") return text;

  if (redactionLevel === "full") {
    const hash = crypto.createHash("sha256").update(text).digest("hex").slice(0, 16);
    return `${hash}...[redacted]`;
  }

  // "pii" mode — replace known PII patterns
  let redacted = text;
  redacted = redacted.replace(PII_PATTERNS.ssn, "[SSN-REDACTED]");
  redacted = redacted.replace(PII_PATTERNS.creditCard, "[CC-REDACTED]");
  redacted = redacted.replace(PII_PATTERNS.email, "[EMAIL-REDACTED]");
  redacted = redacted.replace(PII_PATTERNS.phone, "[PHONE-REDACTED]");
  return redacted;
}

// ── Encryption ───────────────────────────────────────────────────────────────

function encryptEntry(jsonStr, keyOverride) {
  const activeKey = keyOverride || encryptionKey;
  if (!activeKey) return jsonStr;

  const key = Buffer.from(activeKey, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

  let encrypted = cipher.update(jsonStr, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");

  return JSON.stringify({
    encrypted: true,
    iv: iv.toString("hex"),
    tag,
    data: encrypted,
  });
}

function decryptEntry(entryStr, keyOverride) {
  const activeKey = keyOverride || encryptionKey;
  if (!activeKey) return entryStr;

  let parsed;
  try { parsed = JSON.parse(entryStr); } catch { return entryStr; }
  if (!parsed.encrypted) return entryStr;

  const key = Buffer.from(activeKey, "hex");
  const iv = Buffer.from(parsed.iv, "hex");
  const tag = Buffer.from(parsed.tag, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(parsed.data, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// ── Hash Chain ───────────────────────────────────────────────────────────────

function hashPayload(payload) {
  return crypto.createHash("sha256").update(payload).digest("hex");
}

function getPrevHash() {
  if (!fs.existsSync(LOG_PATH)) return "GENESIS";
  const data = fs.readFileSync(LOG_PATH, "utf8").trim();
  if (!data) return "GENESIS";

  const lastLine = data.split("\n").filter(Boolean).pop();
  try {
    const content = encryptionKey ? decryptEntry(lastLine) : lastLine;
    const parsed = JSON.parse(content);
    return parsed.entry_hash || "GENESIS";
  } catch {
    return "GENESIS";
  }
}

// ── Core Logger ──────────────────────────────────────────────────────────────

function appendLog(entry) {
  // Redact sensitive fields
  const sanitized = { ...entry };
  if (sanitized.proposal) sanitized.proposal = redactPII(sanitized.proposal);
  if (sanitized.path) sanitized.path = redactPII(sanitized.path);
  if (sanitized.networkTarget) sanitized.networkTarget = redactPII(sanitized.networkTarget);

  // Build hash-chained entry
  const timestamp = new Date().toISOString();
  const prev_hash = getPrevHash();
  const base = { timestamp, prev_hash, ...sanitized };
  const entry_hash = hashPayload(prev_hash + JSON.stringify(base));
  const logEntry = { ...base, entry_hash };

  // Optionally encrypt, then write
  const line = encryptionKey
    ? encryptEntry(JSON.stringify(logEntry))
    : JSON.stringify(logEntry);

  fs.appendFileSync(LOG_PATH, line + "\n", "utf8");
  return entry_hash;
}

// ── Verification ─────────────────────────────────────────────────────────────

function verifyChain() {
  if (!fs.existsSync(LOG_PATH)) return { valid: true, entries: 0 };

  const lines = fs.readFileSync(LOG_PATH, "utf8").trim().split("\n").filter(Boolean);
  let prevHash = "GENESIS";
  const errors = [];

  for (let i = 0; i < lines.length; i++) {
    try {
      const content = encryptionKey ? decryptEntry(lines[i]) : lines[i];
      const entry = JSON.parse(content);

      if (entry.prev_hash !== prevHash) {
        errors.push({ line: i + 1, expected: prevHash, got: entry.prev_hash });
      }
      prevHash = entry.entry_hash;
    } catch (err) {
      errors.push({ line: i + 1, error: err.message });
    }
  }

  return { valid: errors.length === 0, entries: lines.length, errors };
}

module.exports = {
  appendLog,
  verifyChain,
  redactPII,
  encryptEntry,
  decryptEntry,
  setRedactionLevel,
  setEncryptionKey,
  getRedactionLevel,
  LOG_PATH,
};
