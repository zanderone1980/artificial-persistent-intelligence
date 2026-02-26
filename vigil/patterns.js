/**
 * VIGIL Threat Pattern Library
 * Organized regex patterns for detecting various threat categories
 */

const patterns = {
  // ── Prompt injection attempts ───────────────────────────────────────────
  injection: [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|context)/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|directives?|orders?|guidelines?|policies?)/gi,
    /forget\s+(all\s+)?(everything|your\s+(instructions?|rules?|prompts?))/gi,
    /system\s+prompt/gi,
    /reveal\s+(the\s+)?(system|hidden|original)\s+(prompt|instructions?|rules?)/gi,
    /new\s+(instructions?|prompt|rules?):\s*/gi,
    /override\s+(system|security|safety)\s+(settings?|rules?|protocols?)/gi,
    /you\s+are\s+now\s+(a|an|in)\s+/gi,
    /pretend\s+(you\s+are|to\s+be|you\s+have\s+no)/gi,
    /roleplay\s+as/gi,
    /act\s+as\s+(if|though|a|an)/gi,
    /\bDAN\s+mode\b/gi,
    /\bjailbreak\b/gi,
    /\bdeveloper\s+mode\b/gi,
    /\bgod\s+mode\b/gi,
    /\bunrestricted\s+mode\b/gi,
    /from\s+now\s+on\s+you\s+(are|will|must)/gi,
    /your\s+new\s+(role|purpose|mission|goal)\s+is/gi,
    /<\|.*?\|>/g,           // Token injection markers
    /\[INST\]|\[\/INST\]/g, // Instruction markers
    /\[SYSTEM\]/gi,         // System block injection
    /###\s*(system|instruction)/gi,
    /bypass\s+(all\s+)?(restrictions?|safeguards?|security|safety|protections?|filters?)/gi,
    /give\s+me\s+(admin|root|system|superuser)\s+access/gi,
    /ignore\s+(all\s+)?(security|safety|safeguards?|protections?)/gi,
  ],

  // ── Data exfiltration attempts ──────────────────────────────────────────
  exfil: [
    /curl\s+.*--data/gi,
    /curl\s+.*-d\s+@/gi,
    /wget\s+.*--post/gi,
    /fetch\(.*method:\s*['"]POST['"]/gi,
    /send\s+(secrets?|credentials?|tokens?|keys?|passwords?|data)\s+to/gi,
    /upload\s+(secrets?|credentials?|tokens?|keys?|passwords?)/gi,
    /exfiltrate/gi,
    /\.sendBeacon\(/gi,
    /navigator\.sendBeacon/gi,
    /requests\.post\(/gi,
    /httpx\.post\(/gi,
    /urllib/gi,
    /\bnc\s+.{0,40}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi, // netcat to IP
    /scp\s+.*@/gi,                  // scp to remote
    /rsync\s+.*@/gi,                // rsync to remote
  ],

  // ── Manipulation and deception ──────────────────────────────────────────
  manipulation: [
    /convince\s+the\s+user/gi,
    /trick\s+the\s+user/gi,
    /deceive\s+the\s+user/gi,
    /manipulate\s+the\s+user/gi,
    /gaslight/gi,
    /make\s+(them|the\s+user)\s+believe/gi,
    /social\s+engineering/gi,
    /phishing/gi,
    /blackmail/gi,
    /extort/gi,
    /coerce\s+the\s+user/gi,
    /impersonate\s+(a|the)\s+(human|user|admin|employee)/gi,
  ],

  // ── Obfuscation techniques ──────────────────────────────────────────────
  // Only match active usage, not mentions in discussion
  obfuscation: [
    /atob\s*\(/gi,
    /btoa\s*\(/gi,
    /eval\s*\(/gi,
    /new\s+Function\s*\(/gi,
    /setTimeout\s*\(\s*['"`]/gi,
    /setInterval\s*\(\s*['"`]/gi,
    /\.\s*constructor\s*\(\s*['"`]/gi,
    /String\.fromCharCode\s*\(/gi,
    /unescape\s*\(/gi,
    /\\x[0-9a-f]{2}/gi,            // Hex escape sequences
    /\\u[0-9a-f]{4}/gi,            // Unicode escape sequences
    /data:\s*text\/html/gi,         // Data URI payloads
    /&#x?[0-9a-f]+;/gi,            // HTML entity encoding
  ],

  // ── Dangerous operations ────────────────────────────────────────────────
  dangerousOps: [
    /rm\s+-rf\s+\//gi,
    /rm\s+-rf\s+~/gi,
    /rm\s+-rf\s+\*/gi,
    /drop\s+table/gi,
    /drop\s+database/gi,
    /delete\s+from.*where\s+1\s*=\s*1/gi,
    /truncate\s+table/gi,
    /exec\s*\(/gi,
    /spawn\s*\(/gi,
    /child_process/gi,
    /\/etc\/passwd/gi,
    /\/etc\/shadow/gi,
    /__import__\s*\(/gi,
    /os\.system\s*\(/gi,
    /subprocess\./gi,
    /format\s+c:/gi,
    /mkfs\./gi,
    /dd\s+if=.*of=\/dev\//gi,
    /chmod\s+-R\s+777/gi,
    /:\(\)\s*\{[^}]*:\|:.*\}/g,    // Fork bomb
  ],

  // ── Agent & tool-chain attacks (emerging 2025+) ─────────────────────────
  agentAttacks: [
    /\b(tell|instruct|convince)\s+the\s+(other|next|downstream)\s+(agent|model)/gi,
    /\bpass\s+(instructions?|commands?)\s+to\s+the\s+(next|other)\s+(agent|model)/gi,
    /\b(escape|break\s+out\s+of)\s+(the\s+)?(sandbox|container|jail)\b/gi,
    /\bself[_-]?(modify|replicate|propagate)\b/gi,
    /\b(register|inject)\s+(a\s+)?(fake|malicious|rogue)\s+(tool|server|plugin)\b/gi,
    /\b(intercept|hijack)\s+(tool|mcp|plugin)\s+(calls?|requests?|responses?)\b/gi,
    /\b(modify|write\s+to|patch)\s+(your\s+)?(own\s+)?(source|code|weights)\b/gi,
    /\bpersist\s+(beyond|after|across)\s+(the\s+)?(session|conversation)\b/gi,
  ],

  // ── Suspicious URLs ─────────────────────────────────────────────────────
  suspiciousURLs: [
    /https?:\/\/[^\/\s]*evil[^\/\s]*/gi,
    /https?:\/\/[^\/\s]*malicious[^\/\s]*/gi,
    /https?:\/\/[^\/\s]*hack[^\/\s]*/gi,
    /https?:\/\/[^\/\s]*phish[^\/\s]*/gi,
    /https?:\/\/[^\/\s]*attacker[^\/\s]*/gi,
    /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,  // Raw IP addresses
    /https?:\/\/[^\/\s]*\.onion\b/gi,                      // Tor hidden services
    /https?:\/\/[^\/\s]*ngrok/gi,                           // Tunneling services
  ],
};

// Severity weights for each category
const categoryWeights = {
  injection: 10,
  exfil: 10,
  manipulation: 10,
  agentAttacks: 10,
  obfuscation: 5,
  dangerousOps: 8,
  suspiciousURLs: 7,
};

// Critical categories that trigger immediate BLOCK
const criticalCategories = ['injection', 'exfil', 'manipulation', 'agentAttacks'];

module.exports = {
  patterns,
  categoryWeights,
  criticalCategories,
};
