// CORD v1 policy configuration
module.exports = {
  weights: {
    injection: 3,
    exfil: 3,
    privilege: 4,
    intentDrift: 2,
    irreversibility: 4,
    anomaly: 2,
  },
  thresholds: {
    allow: 2,
    contain: 4,
    challenge: 6,
    block: 8,
  },
  regex: {
    injection: /(<<|{{|}}\s*--|;\\s*--|\\bunion\\b|\\bdrop\\b|\\binsert\\b|\\bexec\\b|\\bshutdown\\b|\\brm\\s+-rf\\b|curl\\s+https?:)/i,
    exfil: /(upload|exfil|curl\\s+https?:|wget\\s+https?:|scp\\s|nc\\s)/i,
    secrets: /(api[_-]?key|token|password|secret|aws_secret|authorization)/i,
  },
  highImpactVerbs: [
    "delete",
    "drop",
    "shutdown",
    "format",
    "wipe",
    "disable",
    "lock",
    "kill",
    "terminate",
    "overwrite",
  ],
  allowlistKeywords: ["read-only", "preview", "dry-run", "simulate", "list"],
};
