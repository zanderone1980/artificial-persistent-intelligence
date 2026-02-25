"""CORD engine — Counter-Operations & Risk Detection.

The 9-step evaluation pipeline:
  1. Normalize   — sanitize and parse the proposal
  2. Authenticate — verify intent lock exists
  3. Scope Check — target within allowed boundaries?
  4. Intent Match — proposal aligned with declared intent?
  5. Protocol Check — evaluate against all 11 protocols
  6. Risk Score  — weighted composite from all dimensions
  7. Decision    — map score to ALLOW / CHALLENGE / CONTAIN / BLOCK
  8. Audit       — write to append-only hash-chained log
  9. Verdict     — return structured result
"""

from __future__ import annotations

from pathlib import Path

from .models import Proposal, Verdict, Decision, CheckResult
from .protocols import run_all_checks
from .scoring import (
    compute_composite_score,
    detect_anomaly,
    decide,
    collect_reasons,
    collect_violations,
)
from .intent_lock import load_intent_lock, IntentLock
from .audit_log import append_log
from .policies import ALLOWLIST_KEYWORDS, HIGH_IMPACT_VERBS


def _normalize(proposal: Proposal) -> Proposal:
    """Step 1: Sanitize and normalize the proposal input."""
    proposal.text = proposal.text.strip()
    if not proposal.action_type or proposal.action_type == "unknown":
        proposal.action_type = _classify_action(proposal.text)
    return proposal


def _classify_action(text: str) -> str:
    """Infer action type from proposal text."""
    from .policies import ACTION_TYPE_HINTS
    for action_type, pattern in ACTION_TYPE_HINTS.items():
        if pattern.search(text):
            return action_type
    return "unknown"


def _authenticate(lock: IntentLock | None) -> CheckResult | None:
    """Step 2: Verify an intent lock exists and is valid."""
    if lock is None:
        return CheckResult(
            dimension="authentication",
            article="CORD — Intent Lock",
            score=2.0,
            reasons=["No intent lock set — session purpose undefined, operating in restricted mode"],
        )
    return None


def _scope_check(
    proposal: Proposal,
    lock: IntentLock | None,
    repo_root: str,
) -> CheckResult | None:
    """Step 3: Verify the proposal targets are within allowed scope."""
    if lock is None or lock.scope is None:
        return None

    scope = lock.scope
    reasons: list[str] = []
    score = 0.0

    if proposal.target_path:
        if not scope.is_path_allowed(proposal.target_path, repo_root):
            score += 2.0
            reasons.append(f"Path '{proposal.target_path}' is outside allowed scope")

    if proposal.network_target:
        if not scope.is_network_allowed(proposal.network_target):
            score += 2.0
            reasons.append(f"Network target '{proposal.network_target}' is not in allowlist")

    # Only check command scope for proposals that look like actual CLI commands
    if proposal.text and proposal.action_type in ("command", "system"):
        if not scope.is_command_allowed(proposal.text):
            score += 1.0
            reasons.append("Command not in allowed command patterns")

    if score > 0:
        return CheckResult(
            dimension="scope_check",
            article="CORD — Scope Enforcement",
            score=score,
            reasons=reasons,
            hard_block=score >= 4.0,
        )
    return None


def _intent_match(proposal: Proposal, lock: IntentLock | None) -> CheckResult | None:
    """Step 4: Does the proposal align with the declared session intent?"""
    if lock is None:
        return None

    intent = lock.intent_text.lower()
    text = proposal.text.lower()

    # Also check the session_intent field on the proposal itself
    session_intent = (proposal.session_intent or "").lower()

    # Direct word overlap check
    stop_words = {"the", "a", "an", "to", "and", "or", "in", "on", "at", "for", "of", "is", "it", "do"}
    intent_words = set(intent.split()) - stop_words
    text_words = set(text.split()) - stop_words

    # Semantic expansion — related terms that indicate alignment
    _synonyms = {
        "update": {"edit", "modify", "change", "tweak", "revise", "fix", "patch", "write"},
        "publish": {"push", "deploy", "release", "ship", "upload"},
        "site": {"html", "page", "website", "web", "contact", "index", "manifesto", "architecture"},
        "api": {"api", "artificial", "persistent", "intelligence"},
        "build": {"compile", "make", "create", "construct"},
        "delete": {"remove", "drop", "purge", "clean", "wipe", "rm"},
    }

    # Expand intent words with synonyms
    expanded_intent = set(intent_words)
    for word in intent_words:
        for key, synonyms in _synonyms.items():
            if word == key or word in synonyms:
                expanded_intent.update(synonyms)
                expanded_intent.add(key)

    meaningful_overlap = text_words & expanded_intent

    # Also check if the session_intent matches the lock intent
    if session_intent and session_intent == intent:
        return None  # Explicitly declared same intent — aligned

    if meaningful_overlap:
        return None  # Found semantic alignment

    # No alignment found — flag drift
    return CheckResult(
        dimension="intent_drift",
        article="CORD — Intent Alignment",
        score=1.5,
        reasons=[
            f"Proposal may drift from declared intent: '{lock.intent_text}'",
            "No meaningful overlap between proposal and session intent",
        ],
    )


def _suggest_alternatives(proposal: Proposal, check_results: list[CheckResult]) -> list[str]:
    """Generate safer alternatives based on what was flagged."""
    alternatives: list[str] = []
    text = proposal.text.lower()

    if any("irreversi" in r for cr in check_results for r in cr.reasons):
        alternatives.append("Run with --dry-run or --preview first to assess impact")

    if any("exfil" in r for cr in check_results for r in cr.reasons):
        alternatives.append("Review data before sending — minimize what leaves the system")

    if any("financial" in r.lower() for cr in check_results for r in cr.reasons):
        alternatives.append("Perform a structured ROI analysis before committing funds")

    if any("scope" in r.lower() for cr in check_results for r in cr.reasons):
        alternatives.append("Update intent lock to expand scope if this action is intentional")

    if any(v in text for v in ["rm -rf", "delete", "wipe", "purge"]):
        alternatives.append("Use a staging/trash approach instead of permanent deletion")

    if not alternatives:
        alternatives.append("No specific alternative needed — action appears within bounds")

    return alternatives


def evaluate(
    proposal: Proposal,
    repo_root: str | None = None,
    lock_path: Path | None = None,
    log_path: Path | None = None,
) -> Verdict:
    """Execute the full 9-step CORD pipeline on a proposal.

    Args:
        proposal: The action to evaluate.
        repo_root: Root directory for scope checking. Defaults to parent of cord_engine/.
        lock_path: Path to intent lock file. Uses default if None.
        log_path: Path to audit log file. Uses default if None.

    Returns:
        A Verdict with decision, score, reasons, alternatives, and log reference.
    """
    if proposal is None:
        proposal = Proposal(text="")
    if repo_root is None:
        repo_root = str(Path(__file__).parent.parent.resolve())

    # Import defaults
    from .intent_lock import DEFAULT_LOCK_PATH
    from .audit_log import DEFAULT_LOG_PATH

    if lock_path is None:
        lock_path = DEFAULT_LOCK_PATH
    if log_path is None:
        log_path = DEFAULT_LOG_PATH

    # ── Step 1: Normalize ──
    proposal = _normalize(proposal)

    # Anti-obfuscation: normalize text to canonical form before any checks
    # Handles: Unicode homoglyphs, leetspeak, word-splitting, base64, HTML entities
    from .normalizer import normalize_proposal_text
    proposal.text, proposal.raw_input = normalize_proposal_text(
        proposal.text, proposal.raw_input
    )

    # ── Step 2: Authenticate ──
    lock = load_intent_lock(lock_path)
    auth_result = _authenticate(lock)

    # ── Step 3: Scope Check ──
    scope_result = _scope_check(proposal, lock, repo_root)

    # ── Step 4: Intent Match ──
    intent_result = _intent_match(proposal, lock)

    # ── Step 4.5: Rate Limit Check ──
    # Thresholds are intentionally generous — legitimate active sessions run 10-20/min.
    # Flag at >30/min (unusual), hard block at >60/min (runaway loop / abuse).
    from .audit_log import check_rate_limit
    rate_exceeded, rate_count, rate_per_min = check_rate_limit(
        window_seconds=60, max_count=40, log_path=log_path
    )
    rate_result: CheckResult | None = None
    if rate_per_min > 30 or rate_exceeded:
        rate_score = min(2.0 + (rate_per_min / 30), 5.0) if rate_per_min > 30 else 2.0
        rate_result = CheckResult(
            dimension="rate_anomaly",
            article="Article VII — Security & Privacy Doctrine",
            score=rate_score,
            reasons=[
                f"Rate anomaly: {rate_count} proposals in last 60s "
                f"({rate_per_min}/min) — possible abuse loop or runaway agent"
            ],
            hard_block=rate_exceeded and rate_per_min > 60,
        )

    # ── Step 5: Protocol Check ──
    protocol_results = run_all_checks(proposal)

    # Combine all check results
    all_results: list[CheckResult] = list(protocol_results)
    if auth_result:
        all_results.append(auth_result)
    if scope_result:
        all_results.append(scope_result)
    if intent_result:
        all_results.append(intent_result)
    if rate_result:
        all_results.append(rate_result)

    # ── Step 6: Risk Score ──
    base_score = compute_composite_score(all_results)
    anomaly = detect_anomaly(all_results)
    total_score = base_score + anomaly

    # ── Step 7: Decision ──
    decision = decide(total_score, all_results)

    # Collect metadata
    reasons = collect_reasons(all_results)
    violations = collect_violations(all_results)
    alternatives = _suggest_alternatives(proposal, all_results)

    # Build risk profile
    risk_profile = {r.dimension: r.score for r in all_results if r.score > 0}
    if anomaly > 0:
        risk_profile["anomaly_amplification"] = anomaly

    # ── Step 8: Audit ──
    log_id = append_log(
        {
            "decision": decision.value,
            "score": round(total_score, 2),
            "risk_profile": risk_profile,
            "reasons": reasons,
            "violations": violations,
            "proposal": proposal.text,
            "action_type": proposal.action_type,
            "target_path": proposal.target_path,
            "network_target": proposal.network_target,
        },
        log_path=log_path,
    )

    # ── Step 9: Verdict ──
    return Verdict(
        decision=decision,
        score=round(total_score, 2),
        risk_profile=risk_profile,
        reasons=reasons,
        alternatives=alternatives,
        article_violations=violations,
        log_id=log_id,
    )
