#!/usr/bin/env node
/**
 * CORD Dashboard Server
 *
 * Serves the real-time CORD decision dashboard.
 * Reads from cord/cord.log.jsonl and streams updates via SSE.
 *
 * Usage:
 *   node dashboard/server.js [--port 3000] [--log path/to/cord.log.jsonl]
 */

const http    = require("http");
const fs      = require("fs");
const path    = require("path");
const url     = require("url");

const REPO_ROOT = path.resolve(__dirname, "..");
const DEFAULT_LOG = path.join(REPO_ROOT, "cord", "cord.log.jsonl");
const DEFAULT_PORT = 3000;

// Parse CLI args
const args = process.argv.slice(2);
const portArg  = args.indexOf("--port");
const logArg   = args.indexOf("--log");
const PORT     = portArg  !== -1 ? parseInt(args[portArg + 1])  : DEFAULT_PORT;
const LOG_PATH = logArg   !== -1 ? path.resolve(args[logArg + 1]) : DEFAULT_LOG;

// ── Log parsing ───────────────────────────────────────────────────────────────

function readLog() {
  if (!fs.existsSync(LOG_PATH)) return [];
  try {
    return fs.readFileSync(LOG_PATH, "utf8")
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line))
      .reverse(); // newest first
  } catch {
    return [];
  }
}

function computeStats(entries) {
  const total = entries.length;
  const counts = { ALLOW: 0, CONTAIN: 0, CHALLENGE: 0, BLOCK: 0 };
  let hardBlocks = 0;
  const dimensionHits = {};

  for (const e of entries) {
    counts[e.decision] = (counts[e.decision] || 0) + 1;
    if (e.hardBlock) hardBlocks++;
    for (const reason of (e.reasons || [])) {
      dimensionHits[reason] = (dimensionHits[reason] || 0) + 1;
    }
  }

  const blockRate = total > 0 ? ((counts.BLOCK / total) * 100).toFixed(1) : "0.0";
  const topDimensions = Object.entries(dimensionHits)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  return { total, counts, hardBlocks, blockRate, topDimensions };
}

// ── SSE helpers ───────────────────────────────────────────────────────────────

const sseClients = new Set();

function sendSSE(client, event, data) {
  try {
    client.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  } catch {
    sseClients.delete(client);
  }
}

function broadcastSSE(event, data) {
  for (const client of sseClients) {
    sendSSE(client, event, data);
  }
}

// Watch log file for new entries
let lastSize = 0;
if (fs.existsSync(LOG_PATH)) lastSize = fs.statSync(LOG_PATH).size;

fs.watchFile(LOG_PATH, { interval: 500 }, (curr) => {
  if (curr.size <= lastSize) return;
  try {
    const fd = fs.openSync(LOG_PATH, "r");
    const buf = Buffer.alloc(curr.size - lastSize);
    fs.readSync(fd, buf, 0, buf.length, lastSize);
    fs.closeSync(fd);
    lastSize = curr.size;

    const newLines = buf.toString("utf8").split("\n").filter(Boolean);
    for (const line of newLines) {
      try {
        const entry = JSON.parse(line);
        broadcastSSE("decision", entry);
        if (entry.decision === "BLOCK") {
          broadcastSSE("block", entry);
        }
      } catch {}
    }

    // Broadcast updated stats
    const stats = computeStats(readLog());
    broadcastSSE("stats", stats);
  } catch {}
});

// ── HTTP server ───────────────────────────────────────────────────────────────

const STATIC_DIR = __dirname;

function serveFile(res, filePath, contentType) {
  try {
    const content = fs.readFileSync(filePath);
    res.writeHead(200, { "Content-Type": contentType });
    res.end(content);
  } catch {
    res.writeHead(404);
    res.end("Not found");
  }
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // CORS for local dev
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");

  if (req.method === "OPTIONS") {
    res.writeHead(200);
    res.end();
    return;
  }

  // SSE stream
  if (pathname === "/api/stream") {
    res.writeHead(200, {
      "Content-Type":  "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection":    "keep-alive",
      "X-Accel-Buffering": "no",
    });
    res.write("retry: 1000\n\n");

    // Send initial data
    const entries = readLog();
    const stats = computeStats(entries);
    sendSSE(res, "init", { entries: entries.slice(0, 100), stats });

    sseClients.add(res);
    req.on("close", () => sseClients.delete(res));
    return;
  }

  // REST endpoints
  if (pathname === "/api/log") {
    const entries = readLog();
    const limit = parseInt(parsed.query.limit) || 100;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(entries.slice(0, limit)));
    return;
  }

  if (pathname === "/api/stats") {
    const stats = computeStats(readLog());
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(stats));
    return;
  }

  // Static files
  if (pathname === "/" || pathname === "/index.html") {
    serveFile(res, path.join(STATIC_DIR, "index.html"), "text/html");
    return;
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(PORT, () => {
  console.log(`\n⚡ CORD Dashboard`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Log: ${LOG_PATH}`);
  console.log(`   SSE: http://localhost:${PORT}/api/stream\n`);
});
