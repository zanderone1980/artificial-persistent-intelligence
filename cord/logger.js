const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const LOG_PATH = path.join(__dirname, "cord.log.jsonl");

function hashPayload(payload) {
  const h = crypto.createHash("sha256");
  h.update(JSON.stringify(payload));
  return h.digest("hex");
}

function appendLog(entry) {
  const timestamp = new Date().toISOString();
  const logEntry = { timestamp, ...entry };
  logEntry.hash = hashPayload(logEntry);

  fs.appendFileSync(LOG_PATH, JSON.stringify(logEntry) + "\n", "utf8");
  return logEntry.hash;
}

module.exports = { appendLog, LOG_PATH };
