const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const LOCK_PATH = path.join(__dirname, "intent.lock.json");

function sha(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function setIntentLock({ user_id, passphrase, intent_text, scope }) {
  if (!user_id || !passphrase || !intent_text || !scope) {
    throw new Error("Missing required fields for intent lock");
  }
  const payload = {
    user_id,
    intent_text,
    scope,
    passphrase_hash: sha(passphrase),
    created_at: new Date().toISOString(),
  };
  fs.writeFileSync(LOCK_PATH, JSON.stringify(payload, null, 2), "utf8");
  return payload;
}

function loadIntentLock() {
  if (!fs.existsSync(LOCK_PATH)) return null;
  try {
    const data = fs.readFileSync(LOCK_PATH, "utf8");
    return JSON.parse(data);
  } catch {
    return null;
  }
}

function verifyPassphrase(passphrase_attempt) {
  const lock = loadIntentLock();
  if (!lock) return false;
  return sha(passphrase_attempt) === lock.passphrase_hash;
}

module.exports = {
  setIntentLock,
  loadIntentLock,
  verifyPassphrase,
  LOCK_PATH,
};
