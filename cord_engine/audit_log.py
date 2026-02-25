"""CORD audit log — append-only JSONL with cryptographic hash chaining.

v4.1 additions:
  - PII redaction (3 levels: none, pii, full)
  - Regex-based redaction of SSN, credit card, email, phone
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LOG_PATH = Path(
    os.environ.get("CORD_LOG_PATH", str(Path(__file__).parent / "cord.log.jsonl"))
)

# ── PII redaction (v4.1) ─────────────────────────────────────────────────────

REDACTION_LEVEL = os.environ.get("CORD_LOG_REDACTION", "pii")  # "none" | "pii" | "full"

PII_PATTERNS = {
    "ssn":         re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
        r"3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "email":       re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "phone":       re.compile(r"\b(\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
}


def redact_pii(text: str, level: str | None = None) -> str:
    """Redact PII from text before logging.

    Levels:
      - "none":  no redaction (passthrough)
      - "pii":   replace SSN, CC, email, phone with tokens
      - "full":  replace entire text with SHA-256 hash prefix
    """
    effective_level = level or REDACTION_LEVEL
    if not text or effective_level == "none":
        return text

    if effective_level == "full":
        h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        return f"{h}...[redacted]"

    # PII-level redaction
    redacted = text
    redacted = PII_PATTERNS["ssn"].sub("[SSN-REDACTED]", redacted)
    redacted = PII_PATTERNS["credit_card"].sub("[CC-REDACTED]", redacted)
    redacted = PII_PATTERNS["email"].sub("[EMAIL-REDACTED]", redacted)
    redacted = PII_PATTERNS["phone"].sub("[PHONE-REDACTED]", redacted)
    return redacted


def _hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _get_prev_hash(log_path: Path = DEFAULT_LOG_PATH) -> str:
    if not log_path.exists():
        return "GENESIS"
    data = log_path.read_text("utf-8").strip()
    if not data:
        return "GENESIS"
    last_line = [line for line in data.split("\n") if line.strip()][-1]
    try:
        parsed = json.loads(last_line)
        return parsed.get("entry_hash", "GENESIS")
    except (json.JSONDecodeError, IndexError):
        return "GENESIS"


def append_log(
    entry: dict[str, Any],
    log_path: Path = DEFAULT_LOG_PATH,
) -> str:
    """Append a hash-chained entry to the audit log. Returns the entry hash.

    PII redaction is applied before writing (controlled by CORD_LOG_REDACTION env var).
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    prev_hash = _get_prev_hash(log_path)

    # Apply PII redaction to sensitive fields
    sanitized = dict(entry)
    for field in ("proposal", "text", "path"):
        if field in sanitized and isinstance(sanitized[field], str):
            sanitized[field] = redact_pii(sanitized[field])

    base = {"timestamp": timestamp, "prev_hash": prev_hash, **sanitized}
    entry_hash = _hash(prev_hash + json.dumps(base, sort_keys=True))
    log_entry = {**base, "entry_hash": entry_hash}

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    return entry_hash


def verify_chain(log_path: Path = DEFAULT_LOG_PATH) -> tuple[bool, int]:
    """Verify the hash chain integrity. Returns (valid, entry_count)."""
    if not log_path.exists():
        return True, 0

    lines = [l for l in log_path.read_text("utf-8").strip().split("\n") if l.strip()]
    if not lines:
        return True, 0

    expected_prev = "GENESIS"
    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, i

        if entry.get("prev_hash") != expected_prev:
            return False, i

        stored_hash = entry.pop("entry_hash", None)
        recomputed = _hash(entry["prev_hash"] + json.dumps(entry, sort_keys=True))
        if stored_hash != recomputed:
            return False, i

        expected_prev = stored_hash

    return True, len(lines)


def read_log(log_path: Path = DEFAULT_LOG_PATH) -> list[dict]:
    """Read all log entries."""
    if not log_path.exists():
        return []
    lines = [l for l in log_path.read_text("utf-8").strip().split("\n") if l.strip()]
    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def check_rate_limit(
    window_seconds: int = 60,
    max_count: int = 20,
    log_path: Path = DEFAULT_LOG_PATH,
) -> tuple[bool, int, float]:
    """Check if proposal rate exceeds the allowed threshold.

    Returns:
        (exceeded: bool, count_in_window: int, rate_per_minute: float)

    A burst of proposals in a short window is a signal of:
    - Automated abuse / jailbreak loops
    - Gradual escalation attacks
    - Runaway agent behavior
    """
    from datetime import datetime, timezone, timedelta

    if not log_path.exists():
        return False, 0, 0.0

    entries = read_log(log_path)
    if not entries:
        return False, 0, 0.0

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=window_seconds)

    recent = []
    for entry in entries:
        ts_str = entry.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                recent.append(entry)
        except (ValueError, TypeError):
            continue

    count = len(recent)
    rate = (count / window_seconds) * 60  # normalize to per-minute

    exceeded = count >= max_count
    return exceeded, count, round(rate, 1)
