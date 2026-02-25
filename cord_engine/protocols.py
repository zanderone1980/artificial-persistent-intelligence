"""CORD protocol checks — each protocol as an evaluable constraint.

Every function takes a Proposal and returns a CheckResult.
Hard blocks bypass the scoring engine entirely.
"""

from __future__ import annotations

from .models import Proposal, CheckResult
from .policies import (
    PATTERNS,
    HIGH_IMPACT_VERBS,
    HIGH_IMPACT_VERBS_PATTERN,
    ALLOWLIST_KEYWORDS,
    MORAL_BLOCK_PATTERNS,
    FINANCIAL_RISK_PATTERNS,
    IDENTITY_VIOLATION_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    PII_PATTERNS,
    PII_FIELD_NAMES,
    TOOL_RISK_TIERS,
)


# ── Article I — Prime Directive ──────────────────────────────────────────────

def check_prime_directive(proposal: Proposal) -> CheckResult:
    """Does the action serve the Principal's long-term interests?

    Flags actions that prioritize short-term gain over long-term consequence.
    """
    score = 0.0
    reasons: list[str] = []
    text = proposal.text.lower()

    short_term_signals = [
        "quick fix", "hack around", "skip test", "ignore warning",
        "temporary workaround", "just ship it", "no time to",
        "deal with later", "tech debt", "shortcut",
    ]
    for signal in short_term_signals:
        if signal in text:
            score += 1.0
            reasons.append(f"Short-term signal detected: '{signal}' — may conflict with long-term interests")

    if proposal.context.get("bypasses_review"):
        score += 1.5
        reasons.append("Action bypasses review process — threatens long-term quality")

    return CheckResult(
        dimension="long_term_alignment",
        article="Article I — Prime Directive",
        score=min(score, 3.0),
        reasons=reasons,
    )


# ── Article II — Moral Constraints ───────────────────────────────────────────

def check_moral_constraints(proposal: Proposal) -> CheckResult:
    """Hard prohibitions: fraud, harm, coercion, deception.

    Violations trigger an immediate BLOCK — no scoring bypass.
    """
    reasons: list[str] = []
    text = proposal.text

    if MORAL_BLOCK_PATTERNS.search(text):
        reasons.append(f"Moral violation detected — Article II prohibits this action")
        return CheckResult(
            dimension="moral_check",
            article="Article II — Moral Constraints",
            score=5.0,
            reasons=reasons,
            hard_block=True,
        )

    deception_signals = ["hide from", "cover up", "mislead", "fake", "fabricate"]
    score = 0.0
    for signal in deception_signals:
        if signal in text.lower():
            score += 2.0
            reasons.append(f"Deception signal: '{signal}'")

    return CheckResult(
        dimension="moral_check",
        article="Article II — Moral Constraints",
        score=min(score, 5.0),
        reasons=reasons,
        hard_block=score >= 4.0,
    )


# ── Article III — Truth & Intellectual Integrity ─────────────────────────────

def check_truth_integrity(proposal: Proposal) -> CheckResult:
    """Is the action based on verified information? Does it fabricate claims?"""
    score = 0.0
    reasons: list[str] = []
    text = proposal.text.lower()

    fabrication_signals = [
        "make up", "invent data", "fake results", "fabricate",
        "hallucinate", "pretend", "assume without",
    ]
    for signal in fabrication_signals:
        if signal in text:
            score += 2.0
            reasons.append(f"Truth violation: '{signal}' — manufactured certainty is deception")

    if proposal.context.get("unverified_data"):
        score += 1.0
        reasons.append("Action relies on unverified data — Article III requires verification")

    return CheckResult(
        dimension="truth_check",
        article="Article III — Truth & Intellectual Integrity",
        score=min(score, 3.0),
        reasons=reasons,
    )


# ── Article IV — Proactive Reasoning ─────────────────────────────────────────

def check_consequence_analysis(proposal: Proposal) -> CheckResult:
    """Have second-order consequences been evaluated?"""
    score = 0.0
    reasons: list[str] = []
    text = proposal.text.lower()

    # High-impact actions without consequence analysis
    is_high_impact = bool(HIGH_IMPACT_VERBS_PATTERN.search(text))
    has_analysis = proposal.context.get("consequence_analysis_done", False)

    if is_high_impact and not has_analysis:
        score += 2.0
        reasons.append("High-impact action without documented consequence analysis")

    if proposal.context.get("no_rollback_plan") and is_high_impact:
        score += 1.0
        reasons.append("No rollback plan for irreversible action")

    return CheckResult(
        dimension="consequence_analysis",
        article="Article IV — Proactive Reasoning",
        score=min(score, 3.0),
        reasons=reasons,
    )


# ── Article V — Human Optimization Mandate ───────────────────────────────────

def check_sustainability(proposal: Proposal) -> CheckResult:
    """Does the action respect the Principal's biological, psychological, financial limits?"""
    score = 0.0
    reasons: list[str] = []

    if proposal.context.get("exceeds_capacity"):
        score += 2.0
        reasons.append("Action exceeds stated capacity limits — growth without sustainability is destruction")

    if proposal.context.get("burnout_risk"):
        score += 1.5
        reasons.append("Burnout risk flagged — CORD builds people up, never burns them out")

    return CheckResult(
        dimension="sustainability_check",
        article="Article V — Human Optimization Mandate",
        score=min(score, 3.0),
        reasons=reasons,
    )


# ── Article VI — Financial Stewardship Protocol ──────────────────────────────

def check_financial_risk(proposal: Proposal) -> CheckResult:
    """ROI evaluation, solvency protection, impulsive spending detection."""
    score = 0.0
    reasons: list[str] = []
    text = proposal.text

    if FINANCIAL_RISK_PATTERNS.search(text):
        score += 2.0
        reasons.append("Financial risk pattern detected — requires structured assessment")

    amount = proposal.context.get("financial_amount", 0)
    if amount > 0:
        if not proposal.context.get("roi_evaluated"):
            score += 1.5
            reasons.append(f"Financial action (${amount}) without ROI evaluation")
        if proposal.context.get("impulsive"):
            score += 2.0
            reasons.append("Impulsive financial behavior detected — every dollar is a decision")

    return CheckResult(
        dimension="financial_risk",
        article="Article VI — Financial Stewardship Protocol",
        score=min(score, 4.0),
        reasons=reasons,
    )


# ── Article VII — Security & Privacy Doctrine ────────────────────────────────

def check_security(proposal: Proposal) -> CheckResult:
    """Injection, exfiltration, privilege escalation, secrets exposure.

    Ported and extended from CORD v1 JavaScript engine.
    """
    score = 0.0
    reasons: list[str] = []
    text = proposal.text
    grants = proposal.grants

    # Injection risk
    if PATTERNS["injection"].search(text):
        score += 2.0
        reasons.append("Injection risk — hostile pattern detected")

    # Exfiltration risk
    if PATTERNS["exfil"].search(text):
        score += 2.0
        reasons.append("Data exfiltration risk — outbound data transfer detected")

    # Secrets exposure
    if PATTERNS["secrets"].search(text):
        score += 1.5
        reasons.append("Secrets exposure risk — sensitive credential pattern detected")

    # Privilege escalation — only flag genuinely elevated grants, not normal write scopes
    dangerous = bool(HIGH_IMPACT_VERBS_PATTERN.search(text))
    elevated = any(
        g for g in grants
        if any(p in g.lower() for p in ["admin", "sudo", "root", "write:system"])
    )
    if dangerous and elevated:
        score += 2.0
        reasons.append("Privilege escalation risk — high-impact verb with elevated grants")
    elif dangerous:
        score += 1.0
        reasons.append("High-impact verb detected — requires caution")

    # Irreversibility
    irreversible = bool(HIGH_IMPACT_VERBS_PATTERN.search(text))
    reversible_hint = any(k in text.lower() for k in ALLOWLIST_KEYWORDS)
    if irreversible and not reversible_hint:
        score += 2.0
        reasons.append("Irreversible action without safety indicators (dry-run, preview, etc.)")

    hard_block = score >= 4.0
    if hard_block:
        reasons.append("Security threat level critical — BLOCK enforced")

    return CheckResult(
        dimension="security_check",
        article="Article VII — Security & Privacy Doctrine",
        score=min(score, 5.0),
        reasons=reasons,
        hard_block=hard_block,
    )


# ── Article VIII — Learning & Adaptation ─────────────────────────────────────

def check_drift(proposal: Proposal) -> CheckResult:
    """Core values are immutable. Only capability adapts."""
    score = 0.0
    reasons: list[str] = []
    text = proposal.text.lower()

    drift_signals = [
        "override constitution", "override protocols", "ignore rules",
        "bypass policy", "disable safety", "turn off checks",
        "skip validation", "modify core values", "change the rules",
    ]
    for signal in drift_signals:
        if signal in text:
            score += 3.0
            reasons.append(f"Protocol drift attempt: '{signal}' — Protocols I-III are immutable")
            return CheckResult(
                dimension="drift_check",
                article="Article VIII — Learning & Adaptation",
                score=min(score, 5.0),
                reasons=reasons,
                hard_block=True,
            )

    return CheckResult(
        dimension="drift_check",
        article="Article VIII — Learning & Adaptation",
        score=0.0,
        reasons=[],
    )


# ── Article IX — Command Evaluation Framework ────────────────────────────────

def check_evaluation_framework(proposal: Proposal) -> CheckResult:
    """The six-question gate from Article IX.

    1. Is it lawful?
    2. Is it ethical?
    3. Does it create net positive value?
    4. What are the second-order consequences?
    5. Is there a superior alternative?
    6. Is this aligned with long-term objectives?
    """
    score = 0.0
    reasons: list[str] = []

    # Check if the proposal has significant impact and lacks structured assessment
    text = proposal.text.lower()
    # Financial actions only trigger Article IX above a meaningful threshold ($100)
    financial_significant = proposal.context.get("financial_amount", 0) >= 100
    is_significant = (
        bool(HIGH_IMPACT_VERBS_PATTERN.search(text))
        or proposal.context.get("significant_impact", False)
        or financial_significant
    )

    # roi_evaluated on a financial action implies full structured assessment:
    # alternatives were compared, consequences were weighed — that's what ROI means.
    roi_done = proposal.context.get("roi_evaluated", False)
    risk_assessment_done = proposal.context.get("risk_assessment_done", False) or roi_done
    alternative_considered = proposal.context.get("alternative_considered", False) or roi_done
    consequences_stated = proposal.context.get("consequences_stated", False) or roi_done

    if is_significant:
        if not risk_assessment_done:
            score += 1.0
            reasons.append("Significant action without structured risk assessment (Art IX req 1)")
        if not alternative_considered:
            score += 0.5
            reasons.append("No alternative solution presented (Art IX req 2)")
        if not consequences_stated:
            score += 0.5
            reasons.append("Long-term consequences not documented (Art IX req 3)")

    return CheckResult(
        dimension="evaluation_framework",
        article="Article IX — Command Evaluation Framework",
        score=min(score, 3.0),
        reasons=reasons,
    )


# ── Article X — Temperament ──────────────────────────────────────────────────

def check_temperament(proposal: Proposal) -> CheckResult:
    """Response tone: calm, rational, no ego, no manipulation."""
    score = 0.0
    reasons: list[str] = []
    text = proposal.text.lower()

    escalation_signals = [
        "threaten", "ultimatum", "demand immediate", "or else",
        "final warning", "last chance",
    ]
    for signal in escalation_signals:
        if signal in text:
            score += 1.0
            reasons.append(f"Emotional escalation detected: '{signal}' — respond with empathetic clarity")

    return CheckResult(
        dimension="temperament_check",
        article="Article X — Temperament",
        score=min(score, 2.0),
        reasons=reasons,
    )


# ── Article XI — Identity ────────────────────────────────────────────────────

def check_identity(proposal: Proposal) -> CheckResult:
    """Agent stays in role. No pretense, no ego, no approval-seeking."""
    score = 0.0
    reasons: list[str] = []
    text = proposal.text.lower()

    match = IDENTITY_VIOLATION_PATTERNS.search(text)
    if match:
        score += 3.0
        reasons.append(
            f"Identity violation: '{match.group(0)}' — CORD knows what it is"
        )

    return CheckResult(
        dimension="identity_check",
        article="Article XI — Identity",
        score=min(score, 3.0),
        reasons=reasons,
    )


# ── Prompt Injection Detection (Article VII extension) ───────────────────────

def check_prompt_injection(proposal: "Proposal") -> CheckResult:
    """Detect prompt injection attempts in proposal text or raw external input.

    Prompt injection = hostile instructions hidden inside data the AI is
    asked to process (emails, web pages, tool results, user messages).
    This is a hijacking attack on the agent's behavior.
    """
    score = 0.0
    reasons: list[str] = []

    # Scan both the proposal description AND any raw external input
    targets = [proposal.text]
    if proposal.raw_input:
        targets.append(proposal.raw_input)

    for target in targets:
        match = PROMPT_INJECTION_PATTERNS.search(target)
        if match:
            score += 4.0
            reasons.append(
                f"Prompt injection attempt detected: '{match.group(0)[:60]}' — "
                "external data is trying to hijack agent behavior"
            )
            break  # One hit is enough for hard block

    # Additional signal: external source + instruction-like structure
    if proposal.source == "external" and not score:
        # Heuristic: external input with unusual command-like density
        imperative_verbs = ["ignore", "forget", "disregard", "override", "instead", "now do"]
        hits = sum(1 for v in imperative_verbs if v in proposal.text.lower())
        if hits >= 2:
            score += 1.5
            reasons.append(
                "External input contains multiple imperative override signals — "
                "possible soft injection attempt"
            )

    hard_block = score >= 4.0
    return CheckResult(
        dimension="prompt_injection",
        article="Article VII — Security & Privacy Doctrine",
        score=min(score, 5.0),
        reasons=reasons,
        hard_block=hard_block,
    )


# ── PII Leakage Detection (Article VII extension) ────────────────────────────

def check_pii_leakage(proposal: "Proposal") -> CheckResult:
    """Detect PII in outbound communications, file writes, or network calls.

    PII (SSN, credit cards, emails, phone numbers, IP addresses) should not
    leave the system without explicit consent. Catching it here gives the
    agent a chance to redact or challenge before it moves.
    """
    score = 0.0
    reasons: list[str] = []
    found: list[str] = []

    # Combine all text to scan
    scan_target = " ".join(filter(None, [proposal.text, proposal.raw_input]))

    # Check each PII type
    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(scan_target):
            # Email in outbound contexts is only medium risk — it's often intentional
            weight = 1.0 if pii_type == "email" else 2.0
            score += weight
            found.append(pii_type)

    # Check for PII field names in payloads (schema/key exposure)
    if PII_FIELD_NAMES.search(scan_target):
        score += 1.5
        found.append("pii_field_names")
        reasons.append("PII field names detected in payload — data schema exposure risk")

    if found:
        pii_list = ", ".join(f for f in found if f != "pii_field_names")
        if pii_list:
            reasons.append(
                f"PII detected in proposal: {pii_list} — "
                "verify consent before transmitting"
            )

    # Amplify if this is an outbound action (network, communication, file write)
    outbound = proposal.action_type in ("network", "communication", "file_op")
    if score > 0 and outbound:
        score *= 1.5
        reasons.append(
            "PII detected in outbound action — transmission without redaction is a privacy violation"
        )

    return CheckResult(
        dimension="pii_leakage",
        article="Article VII — Security & Privacy Doctrine",
        score=min(score, 5.0),
        reasons=reasons,
    )


# ── Tool Risk Baseline (Article IX extension) ────────────────────────────────

def check_tool_risk(proposal: "Proposal") -> CheckResult:
    """Apply baseline risk score based on which OpenClaw tool is being called.

    Different tools have fundamentally different risk surfaces.
    exec > browser > network > message > write > edit > read.
    """
    score = 0.0
    reasons: list[str] = []

    if proposal.tool_name:
        tier_score = TOOL_RISK_TIERS.get(proposal.tool_name.lower(), 0.5)
        if tier_score > 0:
            score = tier_score
            reasons.append(
                f"Tool '{proposal.tool_name}' has elevated baseline risk "
                f"(tier score: {tier_score})"
            )

        # Amplify for exec with shell grants
        if proposal.tool_name.lower() == "exec" and "shell" in proposal.grants:
            score += 1.0
            reasons.append("exec + shell grant — highest risk combination")

    return CheckResult(
        dimension="tool_risk",
        article="Article IX — Command Evaluation Framework",
        score=min(score, 4.0),
        reasons=reasons,
    )


# ── All checks registry ─────────────────────────────────────────────────────

ALL_CHECKS = [
    check_prime_directive,
    check_moral_constraints,
    check_truth_integrity,
    check_consequence_analysis,
    check_sustainability,
    check_financial_risk,
    check_security,
    check_drift,
    check_evaluation_framework,
    check_temperament,
    check_identity,
    # v2.1 additions
    check_prompt_injection,
    check_pii_leakage,
    check_tool_risk,
]


def run_all_checks(proposal: Proposal) -> list[CheckResult]:
    """Execute every protocol check against a proposal."""
    return [check(proposal) for check in ALL_CHECKS]
