const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const LOG_PATH = path.join(__dirname, "cord.log.jsonl");

function hashPayload(payload) {
  const h = crypto.createHash("sha256");
  h.update(payload);
  return h.digest("hex");
}

function getPrevHash() {
  if (!fs.existsSync(LOG_PATH)) return "GENESIS";
  const data = fs.readFileSync(LOG_PATH, "utf8").trim();
  if (!data) return "GENESIS";
  const lastLine = data.split("\n").filter(Boolean).pop();
  try {
    const parsed = JSON.parse(lastLine);
    return parsed.entry_hash || "GENESIS";
  } catch {
    return "GENESIS";
  }
}

function appendLog(entry) {
  const timestamp = new Date().toISOString();
  const prev_hash = getPrevHash();
  const base = { timestamp, prev_hash, ...entry };
  const entry_hash = hashPayload(prev_hash + JSON.stringify(base));
  const logEntry = { ...base, entry_hash };

  fs.appendFileSync(LOG_PATH, JSON.stringify(logEntry) + "\n", "utf8");
  return entry_hash;
}

module.exports = { appendLog, LOG_PATH };
