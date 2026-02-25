/**
 * CORD v3 policy configuration
 * Weights, thresholds, patterns, and risk tiers.
 * Aligned with the Python cord_engine (14-check protocol engine).
 */

module.exports = {

  // ── Dimension weights ────────────────────────────────────────────────────
  weights: {
    injection:            4,
    exfil:                4,
    privilege:            4,
    intentDrift:          3,
    irreversibility:      4,
    anomaly:              2,
    // Protocol additions (v3)
    moralCheck:           5,   // Art II — highest weight, hard-block capable
    promptInjection:      5,   // Art VII ext — AI hijack attempt
    driftCheck:           4,   // Art VIII — bypass/override attempts
    piiLeakage:           4,   // Art VII ext — PII in outbound
    identityCheck:        3,   // Art XI — impersonation
    toolRisk:             1,   // Art IX ext — tool-tier baseline
    financialRisk:        4,   // Financial fraud detection
    networkTargetRisk:    3,   // Suspicious network target
  },

  // ── Decision thresholds ─────────────────────────────────────────────────
  thresholds: {
    allow:     3,
    contain:   5,
    challenge: 7,
    block:     7,
  },

  // ── Security patterns ────────────────────────────────────────────────────
  regex: {
    injection: /(<<|{{|}}\s*--|;\s*--|rm\s+-rf|\bunion\b|\bdrop\b|\binsert\b|\bexec\b|\bshutdown\b|curl\s+https?:|\beval\b|\bimport\s+os\b|\bsubprocess\b|__import__|os\.system|os\.popen)/i,
    exfil:     /(upload|exfil|curl\s+https?:|wget\s+https?:|scp\s|nc\s|requests\.post|urllib|httpx\.post|send.*to.*server|transmit|beacon)/i,
    secrets:   /(api[_\- ]?keys?|tokens?|passwords?|secrets?\b|aws_secret|authorization|credentials?|private[_\- ]?keys?|ssh[_\- ]?keys?|\.env\b|keychain|passphrase|system\s+prompts?)/i,

    // Article II — moral hard-block patterns
    moralBlock: /(steal|fraud|blackmail|extort|coerce|impersonate|forge|counterfeit|phish|exploit\s+vuln|hack\s+into|breach\s+security|harm\s+\w+|threaten|deceive\s+\w+|manipulate\s+\w+|pretend\s+to\s+be\s+(a\s+)?human|as\s+if\s+i\s+am\b|as\s+if\s+you\s+are\b|pose\s+as|masquerade\s+as|the\s+human\s+owner|acting\s+as\s+the\s+human|unless\s+(they|you|he|she|we|i)\s+(pay|comply|agree|cooperate|transfer)|compromising\s+(photos?|images?|videos?|materials?|info|information|data|documents?|evidence)|(leak|release|expose|publish|send)\s+.{0,30}(unless|or\s+else|if\s+not))/i,

    // Protocol VIII — protocol drift / bypass attempts
    drift: /(override\s+(constitution|protocols?)|ignore\s+rules|bypass\s+(policy|all\s+)?(restrictions?|safeguards?|security|safety|protections?|filters?)?|disable\s+safety|turn\s+off\s+checks|skip\s+validation|modify\s+core\s+values|change\s+the\s+rules|disable\s+cord|bypass\s+cord|override\s+sentinel|ignore\s+(all\s+)?(security|safety|safeguards?)|give\s+me\s+(admin|root|system)\s+access)/i,

    // Article XI — identity violations
    identity: /(pretend\s+to\s+be\s+(a\s+)?human|as\s+if\s+i\s+am\b|as\s+if\s+you\s+are\b|\bimpersonate\b|claim\s+to\s+be|pose\s+as|masquerade\s+as|the\s+human\s+owner|acting\s+as\s+the\s+human|respond.*as.*human|present.*as.*human)/i,

    // Prompt injection — jailbreak, role injection, instruction hijacking
    promptInjection: /(ignore\s*(?:\w+\s+){0,3}instructions?|disregard\s*(?:\w+\s+){0,3}(instructions?|rules?|guidelines?|constraints?)|forget\s*(everything|your\s*instructions?|what\s*you\s*were\s*told)|new\s*instructions?\s*:|override\s*:|system\s*override|you\s*are\s*now|from\s*now\s*on\s*you\s*(are|will|must)|act\s*as\s*(a|an|if\s*you\s*are)|your\s*new\s*(role|purpose|mission|goal|task)\s*is|pretend\s*(you\s*have\s*no|you\s*don.t\s*have|there\s*are\s*no)\s*(rules?|constraints?|limits?)|jailbreak|DAN\s*mode|developer\s*mode|god\s*mode|unrestricted\s*mode|<\|.*?\|>|<system>|<\/system>|\[INST\]|\[\/INST\]|\[SYSTEM\]|###\s*system|###\s*instruction|ignoreprevious\w*instruct|disregardall\w*|youarenow\w*)/i,

    // PII patterns
    pii: {
      ssn:        /\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b/,
      creditCard: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/,
      email:      /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/,
      phone:      /\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
    },
    piiFieldNames: /\b(social_security|ssn|credit_card|card_number|cvv|date_of_birth|dob|passport|drivers_license|medical_record|bank_account|routing_number|tax_id)\b/i,
  },

  // ── High-impact verbs ────────────────────────────────────────────────────
  highImpactVerbs: [
    "delete", "drop", "shutdown", "format", "wipe",
    "disable", "lock", "kill", "terminate", "overwrite",
    "purge", "destroy", "truncate", "revoke", "erase",
    "rm", "remove", "uninstall",
  ],

  // ── Allowlist keywords ────────────────────────────────────────────────────
  allowlistKeywords: [
    "read-only", "preview", "dry-run", "simulate", "list",
    "status", "check", "verify", "inspect", "view",
    "describe", "explain", "show", "query", "search",
  ],

  // ── Tool risk tiers ───────────────────────────────────────────────────────
  toolRiskTiers: {
    exec:    3.0,   // Shell execution — highest risk
    browser: 2.0,   // Browser automation — can exfil, fill forms
    network: 2.5,   // Outbound network
    message: 1.5,   // External communication
    write:   1.5,   // File write
    edit:    1.0,   // File edit
    read:    0.0,   // Read-only — no additional risk
    query:   0.0,
  },
};
