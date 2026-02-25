/**
 * CORD Explain — Plain English decision explanations.
 *
 * Takes any CORD result and returns a human-readable explanation
 * with the reason and an actionable fix suggestion.
 */

const DIMENSION_EXPLANATIONS = {
  moralCheck: {
    short: "Moral violation",
    message: "This proposal contains a pattern associated with fraud, extortion, blackmail, coercion, or behavioral threats.",
    fix: "Remove conditional threats, impersonation attempts, or requests to deceive or harm others.",
  },
  promptInjection: {
    short: "Prompt injection",
    message: "This proposal contains an instruction override pattern — it appears to be attempting to hijack the agent's behavior.",
    fix: "Remove override phrases like 'ignore previous instructions', 'you are now', or jailbreak mode requests.",
  },
  driftCheck: {
    short: "Protocol drift",
    message: "This proposal attempts to bypass or disable CORD safety protocols.",
    fix: "Remove references to overriding safety rules, disabling checks, or modifying core values.",
  },
  injection: {
    short: "Injection risk",
    message: "This proposal contains a code or command injection pattern.",
    fix: "Remove shell metacharacters, SQL injection patterns (UNION, DROP), or eval/exec calls.",
  },
  exfil: {
    short: "Exfiltration risk",
    message: "This proposal may be attempting to transmit data externally.",
    fix: "Remove curl/wget commands, upload references, or outbound data transfer patterns.",
  },
  privilege: {
    short: "Privilege escalation",
    message: "This proposal requests elevated permissions or contains high-impact destructive operations.",
    fix: "Remove dangerous verbs (delete, wipe, terminate, shutdown) or reduce required grants.",
  },
  identityCheck: {
    short: "Identity violation",
    message: "This proposal attempts to impersonate a human or claim a false identity.",
    fix: "Remove claims to be human, masquerade attempts, or impersonation language.",
  },
  piiLeakage: {
    short: "PII detected",
    message: "This proposal contains personally identifiable information (SSN, credit card, email, or phone number).",
    fix: "Redact PII before including it in proposals. Use placeholders or tokenized references instead.",
  },
  irreversibility: {
    short: "Irreversible action",
    message: "This is an irreversible action with no safety indicators.",
    fix: "Add --dry-run, preview, or simulate mode. Confirm this action is intentional.",
  },
  intentDrift: {
    short: "Intent drift",
    message: "This proposal doesn't align with the declared session intent.",
    fix: "Ensure your proposal relates to the declared session goal, or start a new session with an updated intent lock.",
  },
  anomaly: {
    short: "Anomaly amplification",
    message: "Multiple risk dimensions are flagging simultaneously — the combined signal exceeds safe thresholds.",
    fix: "Address the individual risk dimensions listed above.",
  },
  toolRisk: {
    short: "High-risk tool",
    message: "This tool carries an elevated baseline risk for this type of action.",
    fix: "Ensure the operation is within the declared session scope and has explicit intent lock coverage.",
  },
  "Intent not locked": {
    short: "No intent lock",
    message: "No session intent has been declared — CORD is operating in restricted mode.",
    fix: "Call setIntentLock() before evaluating proposals to establish session scope and unlock full ALLOW capability.",
  },
  "Out of scope": {
    short: "Out of scope",
    message: "This action targets a path, command, or network destination outside the declared session scope.",
    fix: "Check your session's allowPaths, allowCommands, and allowNetworkTargets, or update the intent lock scope.",
  },
};

const DECISION_CONTEXT = {
  ALLOW:     { label: "Allowed",   color: "green",  icon: "✅" },
  CONTAIN:   { label: "Contained", color: "yellow", icon: "🟡" },
  CHALLENGE: { label: "Challenge", color: "orange", icon: "🟠" },
  BLOCK:     { label: "Blocked",   color: "red",    icon: "🚫" },
};

/**
 * Generate a plain-English explanation for a CORD result.
 *
 * @param {object} result  — Result from evaluateProposal()
 * @param {string} [proposalPreview] — Optional short preview of the proposal text
 * @returns {object}  { decision, label, icon, summary, reasons, fixes, score, hardBlock }
 */
function explain(result, proposalPreview = "") {
  const ctx = DECISION_CONTEXT[result.decision] || DECISION_CONTEXT.BLOCK;

  // Build per-reason explanations
  const reasons = [];
  const fixes = [];
  const seen = new Set();

  for (const reason of (result.reasons || [])) {
    const exp = DIMENSION_EXPLANATIONS[reason];
    if (exp && !seen.has(reason)) {
      seen.add(reason);
      reasons.push(`${exp.short}: ${exp.message}`);
      fixes.push(exp.fix);
    } else if (!exp && !seen.has(reason)) {
      seen.add(reason);
      reasons.push(reason);
    }
  }

  // Top-level summary
  let summary;
  if (result.hardBlock) {
    summary = `Hard block — protocol violation. This action is prohibited regardless of context or score.`;
  } else if (result.decision === "ALLOW") {
    summary = `This proposal passed all CORD checks and is approved for execution.`;
  } else if (result.decision === "CONTAIN") {
    summary = `This proposal passes with elevated monitoring. Execution proceeds with enhanced logging.`;
  } else if (result.decision === "CHALLENGE") {
    summary = `This proposal requires human confirmation before execution can proceed.`;
  } else {
    summary = `This proposal has been blocked. Review the reasons below and revise before resubmitting.`;
  }

  return {
    decision: result.decision,
    label: ctx.label,
    icon: ctx.icon,
    color: ctx.color,
    score: result.score,
    hardBlock: result.hardBlock || false,
    summary,
    reasons,
    fixes: [...new Set(fixes)],
    proposalPreview: proposalPreview ? proposalPreview.slice(0, 120) : "",
    timestamp: new Date().toISOString(),
  };
}

/**
 * Format an explanation as a human-readable string for CLI/log output.
 */
function formatExplanation(explanation) {
  const lines = [
    `${explanation.icon} CORD ${explanation.decision} (score: ${explanation.score.toFixed(2)})`,
    `  ${explanation.summary}`,
  ];

  if (explanation.reasons.length > 0) {
    lines.push(`  Reasons:`);
    explanation.reasons.forEach((r) => lines.push(`    • ${r}`));
  }

  if (explanation.fixes.length > 0 && explanation.decision !== "ALLOW") {
    lines.push(`  How to fix:`);
    explanation.fixes.forEach((f) => lines.push(`    → ${f}`));
  }

  return lines.join("\n");
}

module.exports = { explain, formatExplanation, DIMENSION_EXPLANATIONS, DECISION_CONTEXT };
