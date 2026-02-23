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
    r"harm\s+\w+|threaten|deceive\s+\w+|manipulate\s+\w+)",
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
