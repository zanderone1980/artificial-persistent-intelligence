#!/usr/bin/env node
/**
 * OpenClaw Command Center — Server
 *
 * Zero-dependency Node.js server that reads OpenClaw config from ~/.openclaw/
 * and serves a real-time management dashboard.
 *
 * Usage:  node server.js [--port 3001]
 */

const http = require("http");
const fs   = require("fs");
const path = require("path");
const url  = require("url");
const os   = require("os");
const { execSync } = require("child_process");

// ── Paths ──────────────────────────────────────────────────────────────────
const HOME           = os.homedir();
const OC_ROOT        = path.join(HOME, ".openclaw");
const OC_CONFIG      = path.join(OC_ROOT, "openclaw.json");
const OC_AGENTS_DIR  = path.join(OC_ROOT, "agents");
const OC_SKILLS_DIR  = path.join(OC_ROOT, "skills");
const OC_CRON        = path.join(OC_ROOT, "cron", "jobs.json");
const OC_DEVICES     = path.join(OC_ROOT, "devices", "paired.json");
const OC_AUDIT_LOG   = path.join(OC_ROOT, "logs", "config-audit.jsonl");
const BUNDLED_SKILLS = "/opt/homebrew/lib/node_modules/openclaw/skills";
const REPO_ROOT      = path.resolve(__dirname, "..");
const CORD_LOG       = path.join(REPO_ROOT, "cord", "cord.log.jsonl");

// Gateway writes structured JSON logs to /tmp/openclaw/ with date-stamped files
const OC_GW_LOG_DIR  = "/tmp/openclaw";

/** Find the most recent gateway log file. OpenClaw writes to /tmp/openclaw/openclaw-YYYY-MM-DD.log */
function getActiveGatewayLog() {
  try {
    const files = fs.readdirSync(OC_GW_LOG_DIR)
      .filter(f => f.startsWith("openclaw-") && f.endsWith(".log"))
      .sort()
      .reverse();
    return files.length ? path.join(OC_GW_LOG_DIR, files[0]) : null;
  } catch { return null; }
}

// ── CLI args ───────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const portIdx = args.indexOf("--port");
const PORT = portIdx !== -1 ? parseInt(args[portIdx + 1]) : 3001;

// ── Helpers ────────────────────────────────────────────────────────────────
function readJSON(filepath) {
  try { return JSON.parse(fs.readFileSync(filepath, "utf8")); }
  catch { return null; }
}

function readFile(filepath) {
  try { return fs.readFileSync(filepath, "utf8"); }
  catch { return null; }
}

function fileExists(filepath) {
  try { return fs.statSync(filepath).isFile(); }
  catch { return false; }
}

function dirExists(dirpath) {
  try { return fs.statSync(dirpath).isDirectory(); }
  catch { return false; }
}

function listDirs(dirpath) {
  try { return fs.readdirSync(dirpath).filter(f => dirExists(path.join(dirpath, f))); }
  catch { return []; }
}

/** Redact tokens, keys, passwords from an object (deep clone). */
function sanitize(obj) {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === "string") return obj;
  if (Array.isArray(obj)) return obj.map(sanitize);
  if (typeof obj !== "object") return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const lower = k.toLowerCase();
    if (lower.includes("token") || lower.includes("apikey") || lower.includes("api_key") ||
        lower.includes("password") || lower.includes("secret") || lower.includes("privatekey") ||
        lower === "privatekeypem") {
      out[k] = typeof v === "string" ? v.slice(0, 6) + "••••••" : "••••••";
    } else {
      out[k] = sanitize(v);
    }
  }
  return out;
}

// ── Config helpers ─────────────────────────────────────────────────────────
function getConfig() {
  return readJSON(OC_CONFIG) || {};
}

function getAgents() {
  const config = getConfig();
  const list = config.agents?.list || [{ id: "main" }];
  const defaults = config.agents?.defaults || {};

  return list.map(agent => {
    const id = agent.id;
    const wsPath = agent.workspace || defaults.workspace || path.join(OC_ROOT, "workspace");
    const agentDir = agent.agentDir || path.join(OC_AGENTS_DIR, id, "agent");
    const sessionsDir = path.join(OC_AGENTS_DIR, id, "sessions");

    // Read identity
    const identityRaw = readFile(path.join(wsPath, "IDENTITY.md")) || "";
    const nameMatch = identityRaw.match(/\*\*Name:\*\*\s*(.+)/);
    const emojiMatch = identityRaw.match(/\*\*Emoji:\*\*\s*(.+)/);
    const vibeMatch = identityRaw.match(/\*\*Vibe:\*\*\s*(.+)/);

    // Count sessions
    const sessionsFile = readJSON(path.join(sessionsDir, "sessions.json"));
    const sessionCount = sessionsFile ? Object.keys(sessionsFile).length : 0;

    // Model
    const model = agent.model || defaults.model?.primary || "unknown";

    return {
      id,
      name: nameMatch ? nameMatch[1].trim() : id,
      emoji: emojiMatch ? emojiMatch[1].trim() : "🤖",
      vibe: vibeMatch ? vibeMatch[1].trim() : "",
      workspace: wsPath,
      agentDir,
      model: typeof model === "string" ? model : model.primary || "unknown",
      sessionCount,
    };
  });
}

function getAgentFiles(agentId) {
  const agents = getAgents();
  const agent = agents.find(a => a.id === agentId);
  if (!agent) return null;

  const ws = agent.workspace;
  const files = {};
  for (const name of ["IDENTITY.md", "SOUL.md", "USER.md", "HEARTBEAT.md", "TOOLS.md", "AGENTS.md"]) {
    files[name] = readFile(path.join(ws, name)) || "";
  }
  return { agent, files };
}

function getSkills() {
  const skills = [];

  // Bundled skills
  if (dirExists(BUNDLED_SKILLS)) {
    for (const name of listDirs(BUNDLED_SKILLS)) {
      const skillMd = readFile(path.join(BUNDLED_SKILLS, name, "SKILL.md"));
      if (skillMd) {
        const desc = extractSkillMeta(skillMd);
        skills.push({ name, source: "bundled", ...desc });
      }
    }
  }

  // Shared skills (~/.openclaw/skills/)
  if (dirExists(OC_SKILLS_DIR)) {
    for (const name of listDirs(OC_SKILLS_DIR)) {
      const skillMd = readFile(path.join(OC_SKILLS_DIR, name, "SKILL.md"));
      if (skillMd) {
        const desc = extractSkillMeta(skillMd);
        skills.push({ name, source: "shared", ...desc });
      }
    }
  }

  // Workspace skills
  const agents = getAgents();
  for (const agent of agents) {
    const wsSkills = path.join(agent.workspace, "skills");
    if (dirExists(wsSkills)) {
      for (const name of listDirs(wsSkills)) {
        const skillMd = readFile(path.join(wsSkills, name, "SKILL.md"));
        if (skillMd) {
          const desc = extractSkillMeta(skillMd);
          skills.push({ name, source: `workspace:${agent.id}`, ...desc });
        }
      }
    }
  }

  return skills;
}

function extractSkillMeta(md) {
  const descMatch = md.match(/description:\s*(.+)/);
  const emojiMatch = md.match(/"emoji":\s*"([^"]+)"/);
  return {
    description: descMatch ? descMatch[1].trim() : "",
    emoji: emojiMatch ? emojiMatch[1] : "🔧",
    content: md,
  };
}

function getChannels() {
  const config = getConfig();
  return sanitize(config.channels || {});
}

function getSessions(agentId) {
  const sessionsFile = path.join(OC_AGENTS_DIR, agentId, "sessions", "sessions.json");
  const data = readJSON(sessionsFile);
  if (!data) return [];

  return Object.entries(data).map(([key, val]) => ({
    key,
    sessionId: val.sessionId,
    updatedAt: val.updatedAt,
    channel: val.lastChannel || val.deliveryContext?.channel || "direct",
    chatType: val.chatType || "direct",
    aborted: val.abortedLastRun || false,
  })).sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
}

function getGatewayStatus() {
  try {
    const result = execSync("lsof -ti :18789 2>/dev/null", { encoding: "utf8" }).trim();
    const pid = result.split("\n")[0];
    return { running: true, pid: parseInt(pid), port: 18789 };
  } catch {
    return { running: false, pid: null, port: 18789 };
  }
}

function getCron() {
  return readJSON(OC_CRON) || { version: 1, jobs: [] };
}

function getDevices() {
  const data = readJSON(OC_DEVICES);
  return data ? sanitize(data) : {};
}

function getLogs(count = 50) {
  const logFile = getActiveGatewayLog();
  if (!logFile) return [];
  try {
    // Read the last chunk of the file (avoid loading 38MB+ into memory)
    const stat = fs.statSync(logFile);
    const readSize = Math.min(stat.size, 512 * 1024); // last 512KB
    const fd = fs.openSync(logFile, "r");
    const buf = Buffer.alloc(readSize);
    fs.readSync(fd, buf, 0, readSize, Math.max(0, stat.size - readSize));
    fs.closeSync(fd);
    const raw = buf.toString("utf8");
    const lines = raw.split("\n").filter(Boolean);

    // Parse structured JSON log lines → readable strings
    const parsed = [];
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        const time = entry.time || entry._meta?.date || "";
        const level = entry._meta?.logLevelName || "INFO";
        const subsystem = (entry["0"] || "").replace(/[{}"\s]/g, "").replace("subsystem:", "");
        const msg = entry["1"] || "";
        const ts = time ? new Date(time).toLocaleTimeString("en-US", { hour12: false }) : "";
        parsed.push(`${ts} [${level}] [${subsystem}] ${msg}`);
      } catch {
        // Not JSON — use line as-is (fallback for plain-text log files)
        parsed.push(line);
      }
    }
    return parsed.slice(-count);
  } catch { return []; }
}

// ── CORD log ───────────────────────────────────────────────────────────────
function readCordLog() {
  if (!fileExists(CORD_LOG)) return [];
  try {
    return fs.readFileSync(CORD_LOG, "utf8")
      .split("\n").filter(Boolean)
      .map(line => JSON.parse(line))
      .reverse();
  } catch { return []; }
}

function computeCordStats(entries) {
  const total = entries.length;
  const counts = { ALLOW: 0, CONTAIN: 0, CHALLENGE: 0, BLOCK: 0 };
  let hardBlocks = 0;
  const dimHits = {};
  for (const e of entries) {
    counts[e.decision] = (counts[e.decision] || 0) + 1;
    if (e.hardBlock) hardBlocks++;
    for (const r of (e.reasons || [])) { dimHits[r] = (dimHits[r] || 0) + 1; }
  }
  const blockRate = total > 0 ? ((counts.BLOCK / total) * 100).toFixed(1) : "0.0";
  const topDimensions = Object.entries(dimHits)
    .sort(([, a], [, b]) => b - a).slice(0, 5)
    .map(([name, count]) => ({ name, count }));
  return { total, counts, hardBlocks, blockRate, topDimensions };
}

// ── SSE ────────────────────────────────────────────────────────────────────
const sseClients = new Set();

function sendSSE(client, event, data) {
  try { client.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); }
  catch { sseClients.delete(client); }
}

function broadcastSSE(event, data) {
  for (const c of sseClients) sendSSE(c, event, data);
}

// Watch CORD log
let cordSize = fileExists(CORD_LOG) ? fs.statSync(CORD_LOG).size : 0;
if (fileExists(CORD_LOG)) {
  fs.watchFile(CORD_LOG, { interval: 500 }, (curr) => {
    if (curr.size <= cordSize) return;
    try {
      const fd = fs.openSync(CORD_LOG, "r");
      const buf = Buffer.alloc(curr.size - cordSize);
      fs.readSync(fd, buf, 0, buf.length, cordSize);
      fs.closeSync(fd);
      cordSize = curr.size;
      const lines = buf.toString("utf8").split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          broadcastSSE("decision", entry);
        } catch {}
      }
      broadcastSSE("cord-stats", computeCordStats(readCordLog()));
    } catch {}
  });
}

// Watch gateway log — find the real active log in /tmp/openclaw/
let gwLogFile = getActiveGatewayLog();
let gwSize = (gwLogFile && fileExists(gwLogFile)) ? fs.statSync(gwLogFile).size : 0;

function watchGatewayLog() {
  if (!gwLogFile || !fileExists(gwLogFile)) {
    gwLogFile = getActiveGatewayLog();
    if (!gwLogFile) return;
    gwSize = fs.statSync(gwLogFile).size;
  }
  fs.watchFile(gwLogFile, { interval: 1000 }, (curr) => {
    if (curr.size <= gwSize) return;
    try {
      const fd = fs.openSync(gwLogFile, "r");
      const buf = Buffer.alloc(curr.size - gwSize);
      fs.readSync(fd, buf, 0, buf.length, gwSize);
      fs.closeSync(fd);
      gwSize = curr.size;
      const lines = buf.toString("utf8").split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          const time = entry.time || entry._meta?.date || "";
          const level = entry._meta?.logLevelName || "INFO";
          const subsystem = (entry["0"] || "").replace(/[{}"\s]/g, "").replace("subsystem:", "");
          const msg = entry["1"] || "";
          const ts = time ? new Date(time).toLocaleTimeString("en-US", { hour12: false }) : "";
          broadcastSSE("log", `${ts} [${level}] [${subsystem}] ${msg}`);
        } catch {
          broadcastSSE("log", line);
        }
      }
    } catch {}
  });
}
watchGatewayLog();

// Re-check for new log file at midnight (new date = new file)
setInterval(() => {
  const newFile = getActiveGatewayLog();
  if (newFile && newFile !== gwLogFile) {
    if (gwLogFile) fs.unwatchFile(gwLogFile);
    gwLogFile = newFile;
    gwSize = fileExists(gwLogFile) ? fs.statSync(gwLogFile).size : 0;
    watchGatewayLog();
  }
}, 60000);

// ── HTTP Server ────────────────────────────────────────────────────────────
const STATIC_DIR = __dirname;
const ALLOWED_FILES = new Set(["IDENTITY.md", "SOUL.md", "USER.md", "HEARTBEAT.md", "TOOLS.md", "AGENTS.md"]);

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, PUT, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") { res.writeHead(200); res.end(); return; }

  // ── SSE Stream ──
  if (pathname === "/api/stream") {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
    });
    res.write("retry: 3000\n\n");

    // Send initial data
    const entries = readCordLog();
    sendSSE(res, "init", {
      entries: entries.slice(0, 50),
      stats: computeCordStats(entries),
    });

    sseClients.add(res);
    req.on("close", () => sseClients.delete(res));
    return;
  }

  // ── REST API ──
  if (req.method === "GET") {
    if (pathname === "/api/agents") {
      return json(res, getAgents());
    }

    const agentFilesMatch = pathname.match(/^\/api\/agents\/([^/]+)\/files$/);
    if (agentFilesMatch) {
      const data = getAgentFiles(agentFilesMatch[1]);
      return data ? json(res, data) : notFound(res);
    }

    if (pathname === "/api/skills") {
      return json(res, getSkills());
    }

    if (pathname === "/api/channels") {
      return json(res, getChannels());
    }

    const sessionsMatch = pathname.match(/^\/api\/sessions\/([^/]+)$/);
    if (sessionsMatch) {
      return json(res, getSessions(sessionsMatch[1]));
    }

    if (pathname === "/api/config") {
      return json(res, sanitize(getConfig()));
    }

    if (pathname === "/api/gateway/status") {
      return json(res, getGatewayStatus());
    }

    if (pathname === "/api/cron") {
      return json(res, getCron());
    }

    if (pathname === "/api/devices") {
      return json(res, getDevices());
    }

    if (pathname === "/api/logs") {
      const count = parseInt(parsed.query.count) || 50;
      return json(res, getLogs(count));
    }

    if (pathname === "/api/cord/stats") {
      return json(res, computeCordStats(readCordLog()));
    }

    // Static files
    if (pathname === "/" || pathname === "/index.html") {
      return serveFile(res, path.join(STATIC_DIR, "index.html"), "text/html");
    }
  }

  // ── PUT: Save workspace file ──
  if (req.method === "PUT") {
    const putMatch = pathname.match(/^\/api\/agents\/([^/]+)\/files$/);
    if (putMatch) {
      let body = "";
      req.on("data", chunk => { body += chunk; });
      req.on("end", () => {
        try {
          const { filename, content } = JSON.parse(body);
          if (!ALLOWED_FILES.has(filename)) {
            res.writeHead(403);
            return res.end(JSON.stringify({ error: "File not allowed" }));
          }
          const agents = getAgents();
          const agent = agents.find(a => a.id === putMatch[1]);
          if (!agent) return notFound(res);

          const filepath = path.join(agent.workspace, filename);
          fs.writeFileSync(filepath, content, "utf8");
          return json(res, { ok: true, saved: filename });
        } catch (err) {
          res.writeHead(400);
          return res.end(JSON.stringify({ error: err.message }));
        }
      });
      return;
    }
  }

  notFound(res);
});

function json(res, data) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function notFound(res) {
  res.writeHead(404);
  res.end(JSON.stringify({ error: "Not found" }));
}

function serveFile(res, filepath, contentType) {
  try {
    const content = fs.readFileSync(filepath);
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
}

server.listen(PORT, () => {
  console.log(`\n🦞 OpenClaw Command Center`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Config: ${OC_CONFIG}`);
  console.log(`   CORD log: ${CORD_LOG}`);
  console.log(`   Gateway log: ${gwLogFile || "none found"}\n`);
});
