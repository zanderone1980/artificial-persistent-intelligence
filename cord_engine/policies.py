"""CORD policy configuration — weights, thresholds, patterns, and classifications."""

import re

# ---------------------------------------------------------------------------
# Dimension weights — how heavily each constitutional dimension is scored.
# Higher weight = more influence on the final composite score.
# ---------------------------------------------------------------------------
WEIGHTS = {
    # Article-mapped dimensions
    "long_term_alignment": 3,    # Art I  — Prime Directive
    "moral_check": 5,            # Art II — Moral Constraints (highest)
    "truth_check": 2,            # Art III — Truth & Integrity
    "consequence_analysis": 3,   # Art IV — Proactive Reasoning
    "sustainability_check": 2,   # Art V  — Human Optimization
    "financial_risk": 3,         # Art VI — Financial Stewardship
    "security_check": 4,         # Art VII — Security & Privacy
    "drift_check": 2,            # Art VIII — Learning & Adaptation
    "evaluation_framework": 3,   # Art IX — Command Evaluation
    "temperament_check": 1,      # Art X  — Temperament
    "identity_check": 1,         # Art XI — Identity
    # Sub-dimensions (security breakdown)
    "injection": 4,
    "exfil": 4,
    "privilege": 4,
    "irreversibility": 4,
    "intent_drift": 3,
    "anomaly": 2,
    # New dimensions (v2.1)
    "prompt_injection": 5,   # Highest — AI hijack attempt
    "pii_leakage": 4,        # PII exposure risk
    "rate_anomaly": 3,       # Frequency-based anomaly
    "tool_risk": 1,          # Tool-tier baseline signal (additive, not primary)
}

# ---------------------------------------------------------------------------
# Decision thresholds — composite score boundaries.
# ---------------------------------------------------------------------------
THRESHOLDS = {
    "allow": 3,       # score < 3 → ALLOW
    "contain": 5,     # 3 ≤ score < 5 → CONTAIN
    "challenge": 7,   # 5 ≤ score < 7 → CHALLENGE
    "block": 7,       # score ≥ 7 → BLOCK
}

# ---------------------------------------------------------------------------
# Regex patterns for security detection.
# ---------------------------------------------------------------------------
PATTERNS = {
    "injection": re.compile(
        r"(<<|{{|}}\s*--|;\s*--|"
        r"\bunion\b|\bdrop\b|\binsert\b|\bexec\b|\bshutdown\b|"
        r"\brm\s+-rf\b|curl\s+https?:|"
        r"\beval\b|\bimport\s+os\b|\bsubprocess\b|"
        r"__import__|os\.system|os\.popen)",
        re.IGNORECASE,
    ),
    "exfil": re.compile(
        r"(upload|exfil|curl\s+https?:|wget\s+https?:|scp\s|nc\s|"
        r"requests\.post|urllib|httpx\.post|"
        r"send.*to.*server|transmit|beacon)",
        re.IGNORECASE,
    ),
    "secrets": re.compile(
        r"(api[_\- ]?keys?|tokens?|passwords?|secrets?\b|aws_secret|"
        r"authorization|credentials?|private[_\- ]?keys?|"
        r"ssh[_\- ]?keys?|\.env\b|keychain|passphrase|"
        r"system\s+prompts?)",
        re.IGNORECASE,
    ),
}

# ---------------------------------------------------------------------------
# High-impact verbs — actions that raise irreversibility risk.
# ---------------------------------------------------------------------------
HIGH_IMPACT_VERBS = [
    "delete", "drop", "shutdown", "format", "wipe",
    "disable", "lock", "kill", "terminate", "overwrite",
    "purge", "destroy", "truncate", "revoke", "erase",
    "rm", "remove", "uninstall",
]

# Word-boundary regex — prevents substring collisions like "lock" in "block"
# or "rm" in "performance". Always use this instead of bare `in` checks.
HIGH_IMPACT_VERBS_PATTERN = re.compile(
    r'\b(' + '|'.join(HIGH_IMPACT_VERBS) + r')\b',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Allowlist keywords — signals that reduce risk (preview, dry-run, etc.).
# ---------------------------------------------------------------------------
ALLOWLIST_KEYWORDS = [
    "read-only", "preview", "dry-run", "simulate", "list",
    "status", "check", "verify", "inspect", "view",
    "describe", "explain", "show", "query", "search",
]

# ---------------------------------------------------------------------------
# Moral hard-block patterns — instant BLOCK, no scoring needed.
# These map to Article II prohibitions.
# ---------------------------------------------------------------------------
MORAL_BLOCK_PATTERNS = re.compile(
    r"(steal|fraud|blackmail|extort|coerce|"
    r"impersonate|forge|counterfeit|phish|"
    r"exploit\s+vuln|hack\s+into|breach\s+security|"
    r"harm\s+\w+|threaten|deceive\s+\w+|manipulate\s+\w+|"
    r"pretend\s+to\s+be\s+(a\s+)?human|"
    r"as\s+if\s+i\s+am\b|as\s+if\s+you\s+are\b|"
    r"pose\s+as|masquerade\s+as|"
    r"the\s+human\s+owner|acting\s+as\s+the\s+human|"
    # Behavioral extortion — coercion described without using the keyword
    r"unless\s+(they|you|he|she|we|i)\s+(pay|comply|agree|cooperate|transfer)|"
    r"compromising\s+(photos?|images?|videos?|materials?|info|information|data|documents?|evidence)|"
    r"(leak|release|expose|publish|send)\s+.{0,30}(unless|or\s+else|if\s+not))",
    re.IGNORECASE,
)

# Regex patterns specifically for Article XI identity checks (non-contiguous patterns)
IDENTITY_VIOLATION_PATTERNS = re.compile(
    r"(pretend\s+to\s+be\s+(a\s+)?human|"
    r"as\s+if\s+i\s+am\b|as\s+if\s+you\s+are\b|"
    r"\bimpersonate\b|claim\s+to\s+be|"
    r"pose\s+as|masquerade\s+as|"
    r"the\s+human\s+owner|acting\s+as\s+the\s+human|"
    r"respond.*as.*human|present.*as.*human)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Financial risk indicators.
# ---------------------------------------------------------------------------
FINANCIAL_RISK_PATTERNS = re.compile(
    r"(transfer\s+funds|wire\s+money|invest\s+all|"
    r"leverage|margin\s+call|high[_-]?risk|"
    r"gamble|bet\s+on|speculate|all[_-]?in|"
    r"borrow|loan|credit\s+card|overdraft)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Prompt injection patterns — malicious instructions hidden in external data.
# These attempt to hijack the AI's behavior via untrusted input sources.
# ---------------------------------------------------------------------------
PROMPT_INJECTION_PATTERNS = re.compile(
    r"("
    # Classic override attempts — \s* handles word-splitting attack ("i g n o r e")
    # (?:\w+\s+){0,3} allows up to 3 filler words between "ignore" and "instructions"
    r"ignore\s*(?:\w+\s+){0,3}instructions?|"
    r"disregard\s*(?:\w+\s+){0,3}(instructions?|rules?|guidelines?|constraints?)|"
    r"forget\s*(everything|your\s*instructions?|what\s*you\s*were\s*told)|"
    r"new\s*instructions?\s*:|override\s*:|system\s*override|"
    # Role jacking
    r"you\s*are\s*now|from\s*now\s*on\s*you\s*(are|will|must)|act\s*as\s*(a|an|if\s*you\s*are)|"
    r"your\s*new\s*(role|purpose|mission|goal|task)\s*is|"
    r"pretend\s*(you\s*have\s*no|you\s*don.t\s*have|there\s*are\s*no)\s*(rules?|constraints?|limits?)|"
    r"jailbreak|DAN\s*mode|developer\s*mode|god\s*mode|unrestricted\s*mode|"
    # Instruction injection via data — template delimiters
    r"<\|.*?\|>|<system>|</system>|<\|im_start\||<\|im_end\||"
    r"\[INST\]|\[/INST\]|\[SYSTEM\]|###\s*system|###\s*instruction|"
    # Collapsed word-split forms (e.g. "ignorepreviousinstructions")
    r"ignoreprevious\w*instruct|disregardall\w*|forgetinstruct\w*|"
    r"youarenow\w*|fromnowon\w*|"
    # Hidden instruction tricks
    r"the\s*(following|above)\s*(text|content|data)\s*(is|contains)\s*(your|new)\s*instructions?|"
    r"translate\s*(this|the\s*following)\s*(and|then)\s*(also|additionally)\s*(do|execute|run)|"
    r"after\s*(reading|processing|translating|summarizing).*?(do|execute|send|call)"
    r")",
    re.IGNORECASE | re.DOTALL,
)

# ---------------------------------------------------------------------------
# PII patterns — personally identifiable information that shouldn't be
# transmitted, stored, or processed without explicit consent.
# ---------------------------------------------------------------------------
PII_PATTERNS = {
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b"),
    "credit_card": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"           # Visa
        r"5[1-5][0-9]{14}|"                          # Mastercard
        r"3[47][0-9]{13}|"                           # Amex
        r"3(?:0[0-5]|[68][0-9])[0-9]{11}|"          # Diners
        r"6(?:011|5[0-9]{2})[0-9]{12})\b"           # Discover
    ),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "phone": re.compile(r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ip_address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
}

# PII field names that appear in data payloads (keys, column names, etc.)
PII_FIELD_NAMES = re.compile(
    r"\b(social_security|ssn|credit_card|card_number|cvv|"
    r"date_of_birth|dob|passport|drivers_license|"
    r"medical_record|health_record|diagnosis|prescription|"
    r"bank_account|routing_number|tax_id|ein|itin)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Tool risk tiers — different tools carry different baseline risk.
# ---------------------------------------------------------------------------
TOOL_RISK_TIERS = {
    "exec":    3.0,   # Shell execution — highest risk
    "write":   1.5,   # File write — moderate
    "edit":    1.0,   # File edit — low
    "browser": 2.0,   # Browser automation — elevated (can exfil, fill forms)
    "network": 2.5,   # Outbound network — elevated
    "read":    0.0,   # Read-only — no additional risk
    "query":   0.0,   # Query — no additional risk
    "message": 1.5,   # Messaging — moderate (external communication)
}

# ---------------------------------------------------------------------------
# Action type classification hints.
# ---------------------------------------------------------------------------
ACTION_TYPE_HINTS = {
    "command": re.compile(r"(^(git|npm|pip|docker|kubectl|sudo|apt|brew|make)\s)", re.IGNORECASE),
    "file_op": re.compile(r"(write|read|edit|create|delete|move|copy|rename)\s+(file|dir|folder|path)", re.IGNORECASE),
    "network": re.compile(r"(curl|wget|fetch|request|api\s+call|http|upload|download)", re.IGNORECASE),
    "financial": re.compile(r"(buy|sell|pay|transfer|invest|trade|purchase|invoice)", re.IGNORECASE),
    "communication": re.compile(r"(send|email|message|post|publish|tweet|reply|comment)", re.IGNORECASE),
    "system": re.compile(r"(install|uninstall|configure|chmod|chown|mount|systemctl|service)", re.IGNORECASE),
}
