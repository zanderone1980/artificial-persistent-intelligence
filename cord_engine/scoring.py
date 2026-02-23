"""CORD scoring engine — weighted composite scoring with anomaly amplification."""

from __future__ import annotations

from .models import Decision, CheckResult
from .policies import WEIGHTS, THRESHOLDS


def compute_composite_score(check_results: list[CheckResult]) -> float:
    """Compute a weighted composite score from all check results."""
    total = 0.0
    for result in check_results:
        weight = WEIGHTS.get(result.dimension, 1)
        total += result.score * weight
    return total


def detect_anomaly(check_results: list[CheckResult]) -> float:
    """Amplify score when multiple dimensions flag high risk simultaneously."""
    high_signals = sum(1 for r in check_results if r.score >= 2)
    if high_signals >= 4:
        return 3.0
    if high_signals >= 3:
        return 2.0
    if high_signals >= 2:
        return 1.0
    return 0.0


def has_hard_block(check_results: list[CheckResult]) -> bool:
    """Check if any result demands an immediate BLOCK."""
    return any(r.hard_block for r in check_results)


def decide(score: float, check_results: list[CheckResult]) -> Decision:
    """Map a composite score to a CORD decision."""
    if has_hard_block(check_results):
        return Decision.BLOCK

    if score >= THRESHOLDS["block"]:
        return Decision.BLOCK
    if score >= THRESHOLDS["challenge"]:
        return Decision.CHALLENGE
    if score >= THRESHOLDS["contain"]:
        return Decision.CONTAIN
    return Decision.ALLOW


def collect_reasons(check_results: list[CheckResult]) -> list[str]:
    """Gather all reasons from checks that flagged risk."""
    reasons = []
    for result in check_results:
        if result.score > 0 or result.hard_block:
            reasons.extend(result.reasons)
    return reasons


def collect_violations(check_results: list[CheckResult]) -> list[str]:
    """Gather article references from checks that flagged risk."""
    violations = []
    for result in check_results:
        if result.score > 0 or result.hard_block:
            if result.article not in violations:
                violations.append(result.article)
    return violations
