/**
 * CORD v3 — Counter-Operations & Risk Detection (JavaScript)
 *
 * Aligned with the Python cord_engine protocol architecture.
 * 14-check pipeline covering all 11 CORD protocols.
 *
 * New in v3:
 *   - Hard blocks: moral violations, prompt injection, protocol drift
 *     bypass the scoring engine and trigger immediate BLOCK
 *   - Prompt injection detection (Article VII extension)
 *   - PII leakage detection (Article VII extension)
 *   - Constitutional drift detection (Article VIII)
 *   - Identity violation detection (Article XI)
 *   - Tool risk baseline (Article IX extension)
 *   - Stronger anomaly amplification (matches Python engine)
 *   - Hardened injection patterns (eval, subprocess, os.system)
 */

const path = require("path");
const { weights, thresholds, regex, highImpactVerbs, allowlistKeywords, toolRiskTiers } = require("./policies");
const { appendLog } = require("./logger");
const { loadIntentLock } = require("./intentLock");

// ── Optional VIGIL integration ──────────────────────────────────────────────
// VIGIL sits ABOVE CORD — always-on patrol that catches critical threats
// before the CORD pipeline runs. Optional: works without VIGIL installed.
let vigilModule = null;
try {
  vigilModule = require("../vigil/vigil");
} catch (e) {
  // VIGIL not available (npm-only install) — CORD works standalone
}

// ── Original 6 risk checks (v1/v2) ──────────────────────────────────────────

function injectionRisk(text = "") {
  if (!text) return 0;
  return regex.injection.test(text) ? 2 : 0;
}

function exfilRisk(text = "") {
  if (!text) return 0;
  const hits = [regex.exfil, regex.secrets].some((r) => r.test(text));
  return hits ? 2 : 0;
}

function privilegeRisk(proposal = "", grants = []) {
  const lower = proposal.toLowerCase();
  const dangerous = highImpactVerbs.some((v) => lower.includes(v));
  const elevated = grants.some((g) => /admin|sudo|root|write/.test(g));
  return dangerous || elevated ? 2 : 0;
}

function intentDriftRisk(proposal = "", sessionIntent = "") {
  if (!proposal || !sessionIntent) return 0;
  const aligned = proposal.toLowerCase().includes(sessionIntent.toLowerCase());
  return aligned ? 0 : 1;
}

function irreversibilityRisk(proposal = "") {
  const lower = proposal.toLowerCase();
  const irreversible = highImpactVerbs.some((v) => lower.includes(v));
  const reversibleHint = allowlistKeywords.some((k) => lower.includes(k));
  if (irreversible) return 3;
  if (reversibleHint) return 0;
  return 1;
}

function anomalyRisk(risks) {
  const highSignals = Object.values(risks).filter((v) => v >= 2).length;
  if (highSignals >= 4) return 3;
  if (highSignals >= 3) return 2;
  if (highSignals >= 2) return 1;
  return 0;
}

// ── v3 protocol checks ──────────────────────────────────────────────────────

/**
 * Article II — Moral Constraints
 * Hard-block patterns: fraud, extortion, blackmail, behavioral coercion.
 * Returns { score, hardBlock }
 */
function moralRisk(text = "") {
  if (!text) return { score: 0, hardBlock: false };
  if (regex.moralBlock.test(text)) {
    return { score: 5, hardBlock: true };
  }
  const deceptionSignals = ["hide from", "cover up", "mislead", "fabricate"];
  const hits = deceptionSignals.filter((s) => text.toLowerCase().includes(s)).length;
  const score = Math.min(hits * 2, 5);
  return { score, hardBlock: score >= 4 };
}

/**
 * Article VIII — Learning & Adaptation
 * Protocol drift: attempts to bypass, override, or disable CORD.
 * Hard-block on any match.
 */
function driftRisk(text = "") {
  if (!text) return { score: 0, hardBlock: false };
  if (regex.drift.test(text)) {
    return { score: 5, hardBlock: true };
  }
  return { score: 0, hardBlock: false };
}

/**
 * Article VII extension — Prompt Injection Detection
 * Detects jailbreak patterns, role hijacking, instruction override.
 * Hard-block on definitive injection signatures.
 */
function promptInjectionRisk(text = "") {
  if (!text) return { score: 0, hardBlock: false };
  if (regex.promptInjection.test(text)) {
    return { score: 5, hardBlock: true };
  }
  // Soft signal: multiple imperative override verbs from external-like content
  const imperatives = ["ignore", "forget", "disregard", "override", "instead"];
  const hits = imperatives.filter((v) => text.toLowerCase().includes(v)).length;
  if (hits >= 2) return { score: 1.5, hardBlock: false };
  return { score: 0, hardBlock: false };
}

/**
 * Article VII extension — PII Leakage Detection
 * Detects SSN, credit cards, email, phone numbers in proposals.
 * Amplified when the action type is outbound (network, file write, message).
 */
function piiRisk(text = "", actionType = "") {
  if (!text) return 0;
  let score = 0;
  if (regex.pii.ssn.test(text))        score += 2;
  if (regex.pii.creditCard.test(text)) score += 2;
  if (regex.pii.email.test(text))      score += 1;
  if (regex.pii.phone.test(text))      score += 1;
  if (regex.piiFieldNames.test(text))  score += 1.5;

  // Amplify for outbound actions
  const outbound = ["network", "communication", "file_op", "message"].includes(actionType);
  if (score > 0 && outbound) score *= 1.5;

  return Math.min(score, 5);
}

/**
 * Article XI — Identity
 * Detects impersonation attempts, claims to be human, role masquerading.
 */
function identityRisk(text = "") {
  if (!text) return 0;
  return regex.identity.test(text) ? 3 : 0;
}

/**
 * Article IX extension — Tool Risk Baseline
 * Different tools carry different inherent risk levels.
 * exec > network > browser > message > write > edit > read.
 */
function toolRisk(toolName = "") {
  if (!toolName) return 0;
  const score = toolRiskTiers[toolName.toLowerCase()];
  return score !== undefined ? score : 0.5;
}

/**
 * Financial fraud detection.
 * Detects money transfer, payment, and wallet-related fraud.
 * Amplified when actionType is 'financial'.
 */
function financialRisk(text = "", actionType = "") {
  if (!text) return 0;
  const lower = text.toLowerCase();
  const financialPatterns = [
    /transfer\s+\$?\d/i,
    /send\s+\$?\d/i,
    /wire\s+\$?\d/i,
    /payment\s+to/i,
    /to\s+(attacker|hacker|scammer|criminal)\s+(wallet|account|address)/i,
    /\battacker\b.*\b(wallet|account)\b/i,
    /\b(wallet|account)\b.*\battacker\b/i,
    /bitcoin\s+transfer/i,
    /crypto\s+transfer/i,
    /unauthorized\s+(transfer|payment|transaction)/i,
  ];
  let hits = financialPatterns.filter((p) => p.test(text)).length;
  let score = Math.min(hits * 2, 5);
  // Amplify for financial action type
  if (actionType === "financial" && score > 0) score = Math.min(score * 1.5, 5);
  if (actionType === "financial" && score === 0) score = 1; // Base risk for any financial action
  return score;
}

/**
 * Network target risk — suspicious domain detection.
 * Flags known-malicious domain keywords even without full URL.
 */
function networkTargetRisk(target = "") {
  if (!target) return 0;
  const lower = target.toLowerCase();
  const suspiciousWords = ["evil", "malicious", "hack", "attacker", "phish", "exploit", "steal"];
  const hits = suspiciousWords.filter((w) => lower.includes(w)).length;
  if (hits > 0) return Math.min(2 + hits, 5);
  // Raw IP address
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(target)) return 2;
  // Tor hidden service
  if (lower.endsWith(".onion")) return 3;
  // Tunneling
  if (lower.includes("ngrok")) return 2;
  return 0;
}

// ── Scoring ──────────────────────────────────────────────────────────────────

function scoreProposal({ text = "", proposal = "", grants = [], sessionIntent = "" }) {
  const base = {
    injection:      injectionRisk(text || proposal),
    exfil:          exfilRisk(text || proposal),
    privilege:      privilegeRisk(proposal, grants),
    intentDrift:    intentDriftRisk(proposal, sessionIntent),
    irreversibility: irreversibilityRisk(proposal),
  };
  base.anomaly = anomalyRisk(base);

  const weighted =
    base.injection      * weights.injection +
    base.exfil          * weights.exfil +
    base.privilege      * weights.privilege +
    base.intentDrift    * weights.intentDrift +
    base.irreversibility * weights.irreversibility +
    base.anomaly        * weights.anomaly;

  return { risks: base, score: weighted };
}

function decide(score) {
  if (score >= thresholds.block)     return "BLOCK";
  if (score >= thresholds.challenge) return "CHALLENGE";
  if (score >= thresholds.contain)   return "CONTAIN";
  return "ALLOW";
}

// ── Scope checks ──────────────────────────────────────────────────────────────

function ensureIntentLock() {
  const lock = loadIntentLock();
  if (!lock) return { lock: null, intentIssue: "Intent not locked" };
  return { lock, intentIssue: null };
}

function isPathAllowed(targetPath, scope, repoRoot) {
  if (!targetPath) return true;
  const abs = path.resolve(targetPath);
  if (!abs.startsWith(repoRoot)) return false;
  if (!scope?.allowPaths || scope.allowPaths.length === 0) return false;
  return scope.allowPaths.some((p) => abs.startsWith(path.resolve(p)));
}

function isNetworkAllowed(target = "", scope) {
  if (!target) return false;
  if (!scope?.allowNetworkTargets) return false;
  return scope.allowNetworkTargets.some((host) => target.includes(host));
}

function isCommandAllowed(proposal = "", scope) {
  if (!proposal) return true;
  if (!scope?.allowCommands || scope.allowCommands.length === 0) return false;
  return scope.allowCommands.some((pattern) => {
    if (pattern instanceof RegExp) return pattern.test(proposal);
    if (pattern?.__regex) return new RegExp(pattern.__regex, pattern.flags || "").test(proposal);
    if (typeof pattern === "string") return proposal.includes(pattern);
    return false;
  });
}

// ── Main evaluation pipeline ─────────────────────────────────────────────────

/**
 * Evaluate a proposal through the full CORD v3 pipeline.
 *
 * Input:
 *   text          — The proposal text (command, code, or content)
 *   proposal      — Alias for text (backward compat)
 *   path          — File path being targeted
 *   networkTarget — Network host being contacted
 *   grants        — Permission grants in effect
 *   sessionIntent — Declared session goal (for intent drift check)
 *   toolName      — OpenClaw tool being called (exec, write, browser, etc.)
 *   actionType    — Action classification (network, file_op, communication, etc.)
 *   rawInput      — Raw external input to scan for prompt injection
 *
 * Returns:
 *   { decision, score, risks, reasons, hardBlock, log_id }
 */
function evaluateProposal(input = {}) {
  if (input === null || input === undefined) input = {};
  const repoRoot = path.resolve(__dirname, "..");
  const text = input.proposal || input.text || "";
  const rawInput = input.rawInput || "";
  const scanText = [text, rawInput, input.networkTarget].filter(Boolean).join(" ");

  const { lock, intentIssue } = ensureIntentLock();

  // ── Phase 0: VIGIL pre-scan (if available) ──────────────────────────────
  // VIGIL is the outer patrol layer. If it detects a critical threat,
  // we skip the entire CORD pipeline — no score, no scope check, just BLOCK.
  // If it finds suspicious (CHALLENGE) content, we amplify CORD's score.
  let vigilResult = null;
  let proactiveResult = null;
  if (vigilModule && input.useVigil !== false) {
    const v = vigilModule.vigil;
    if (!v.running) v.start();

    // Phase 0a: Proactive input pre-screen (indirect injection in rawInput)
    if (rawInput && v.proactive) {
      try {
        proactiveResult = v.scanInput(rawInput, input.inputSource || "rawInput");
      } catch (e) {
        proactiveResult = null;
      }

      if (proactiveResult && proactiveResult.decision === "BLOCK") {
        const reasons = ["VIGIL INDIRECT INJECTION — " + (proactiveResult.summary || "poisoned input detected")];
        const log_id = appendLog({
          decision: "BLOCK",
          score: 99,
          risks: { indirectInjection: true, indirectSeverity: proactiveResult.severity },
          reasons,
          proposal: text,
          path: input.path || null,
          networkTarget: input.networkTarget || null,
          hardBlock: true,
        });
        return {
          decision: "BLOCK", score: 99,
          risks: { indirectInjection: true, indirectSeverity: proactiveResult.severity },
          reasons,
          hardBlock: true, log_id,
          vigilResult: null,
          proactiveResult,
        };
      }
    }

    // Phase 0b: Standard VIGIL threat scan
    try {
      vigilResult = v.scan(scanText);
    } catch (e) {
      // VIGIL error — proceed without it
      vigilResult = null;
    }

    if (vigilResult && vigilResult.decision === "BLOCK") {
      const reasons = ["VIGIL BLOCK — " + (vigilResult.summary || "critical threat detected")];
      if (vigilResult.escalatedBy === "memory") {
        reasons.push("Escalated by behavioral memory (cross-turn pattern)");
      }
      const log_id = appendLog({
        decision: "BLOCK",
        score: 99,
        risks: { vigilBlock: true, vigilSeverity: vigilResult.severity },
        reasons,
        proposal: text,
        path: input.path || null,
        networkTarget: input.networkTarget || null,
        hardBlock: true,
      });
      return {
        decision: "BLOCK", score: 99,
        risks: { vigilBlock: true, vigilSeverity: vigilResult.severity },
        reasons,
        hardBlock: true, log_id,
        vigilResult,
      };
    }
  }

  // ── Phase 1: Hard-block checks (bypass scoring entirely) ─────────────────
  // These are protocol violations that cannot be un-done by score weighting.

  const moral = moralRisk(scanText);
  if (moral.hardBlock) {
    const log_id = appendLog({
      decision: "BLOCK",
      score: 99,
      risks: { moralCheck: 5 },
      reasons: ["HARD BLOCK — moral violation (Article II)"],
      proposal: text,
      path: input.path || null,
      networkTarget: input.networkTarget || null,
      hardBlock: true,
    });
    return {
      decision: "BLOCK", score: 99,
      risks: { moralCheck: 5 },
      reasons: ["HARD BLOCK — moral violation (Article II)"],
      hardBlock: true, log_id,
    };
  }

  const drift = driftRisk(scanText);
  if (drift.hardBlock) {
    const log_id = appendLog({
      decision: "BLOCK",
      score: 99,
      risks: { driftCheck: 5 },
      reasons: ["HARD BLOCK — protocol drift attempt (Protocol VIII)"],
      proposal: text,
      path: input.path || null,
      networkTarget: input.networkTarget || null,
      hardBlock: true,
    });
    return {
      decision: "BLOCK", score: 99,
      risks: { driftCheck: 5 },
      reasons: ["HARD BLOCK — protocol drift attempt (Protocol VIII)"],
      hardBlock: true, log_id,
    };
  }

  const injection = promptInjectionRisk(scanText);
  if (injection.hardBlock) {
    const log_id = appendLog({
      decision: "BLOCK",
      score: 99,
      risks: { promptInjection: 5 },
      reasons: ["HARD BLOCK — prompt injection attempt (Article VII)"],
      proposal: text,
      path: input.path || null,
      networkTarget: input.networkTarget || null,
      hardBlock: true,
    });
    return {
      decision: "BLOCK", score: 99,
      risks: { promptInjection: 5 },
      reasons: ["HARD BLOCK — prompt injection attempt (Article VII)"],
      hardBlock: true, log_id,
    };
  }

  // ── Phase 2: Scored risk checks ───────────────────────────────────────────

  const { risks, score: baseScore } = scoreProposal({
    text,
    proposal: text,
    grants: input.grants || [],
    sessionIntent: input.sessionIntent || "",
  });

  // Additional v3 dimensions
  const v3Risks = {
    moralCheck:      moral.score,
    promptInjection: injection.score,
    piiLeakage:      piiRisk(scanText, input.actionType || ""),
    identityCheck:   identityRisk(scanText),
    toolRisk:        toolRisk(input.toolName || ""),
    financialRisk:   financialRisk(scanText, input.actionType || ""),
    networkTargetRisk: networkTargetRisk(input.networkTarget || ""),
  };

  const v3Score =
    v3Risks.moralCheck      * weights.moralCheck +
    v3Risks.promptInjection * weights.promptInjection +
    v3Risks.piiLeakage      * weights.piiLeakage +
    v3Risks.identityCheck   * weights.identityCheck +
    v3Risks.toolRisk        * weights.toolRisk +
    v3Risks.financialRisk   * (weights.financialRisk || 4) +
    v3Risks.networkTargetRisk * (weights.networkTargetRisk || 3);

  let totalScore = baseScore + v3Score;
  let decision = decide(totalScore);

  const allRisks = { ...risks, ...v3Risks };
  const reasons = Object.entries(allRisks)
    .filter(([, v]) => v > 0)
    .map(([k]) => k);

  // ── Phase 2b: VIGIL score amplification ─────────────────────────────────
  // If VIGIL found suspicious content (CHALLENGE), amplify CORD's score.
  // If VIGIL detected obfuscation, add a risk signal.
  // If proactive scanner found non-blocking threats, amplify score.
  if (vigilResult) {
    if (vigilResult.decision === "CHALLENGE") {
      const vigilAmplifier = vigilResult.severity * 0.5;
      totalScore += vigilAmplifier;
      reasons.push(`VIGIL suspicious (severity ${vigilResult.severity})`);
      allRisks.vigilSuspicious = vigilResult.severity;
    }
    if (vigilResult.wasObfuscated) {
      totalScore += 2;
      reasons.push("Obfuscated content detected by VIGIL");
      allRisks.vigilObfuscation = true;
    }
    // Re-decide with amplified score
    if (vigilResult.decision === "CHALLENGE" || vigilResult.wasObfuscated) {
      decision = decide(totalScore);
    }
  }

  // Phase 2c: Proactive score amplification
  // If indirect injection was detected but not blocked (CHALLENGE), amplify
  if (proactiveResult && !proactiveResult.clean && proactiveResult.decision === "CHALLENGE") {
    totalScore += proactiveResult.severity * 0.3;
    reasons.push(`Indirect injection detected in input (severity ${proactiveResult.severity})`);
    allRisks.indirectInjection = proactiveResult.severity;
    decision = decide(totalScore);
  }

  // ── Phase 3: Intent lock enforcement ─────────────────────────────────────

  if (intentIssue) {
    if (decision === "ALLOW" || decision === "CONTAIN") decision = "CHALLENGE";
    reasons.push(intentIssue);
  }

  // ── Phase 4: Scope enforcement ────────────────────────────────────────────

  if (lock?.scope) {
    const scope = lock.scope;
    const pathAllowed    = isPathAllowed(input.path || input.targetPath, scope, repoRoot);
    const networkAllowed = input.networkTarget ? isNetworkAllowed(input.networkTarget, scope) : true;
    const commandAllowed = isCommandAllowed(text, scope);

    if (!pathAllowed || !networkAllowed || !commandAllowed) {
      reasons.push("Out of scope");
      decision = "BLOCK"; // Scope violations are always hard blocks
    }
  }

  // ── Phase 5: Log and return ───────────────────────────────────────────────

  const log_id = appendLog({
    decision,
    score: totalScore,
    risks: allRisks,
    reasons,
    proposal: text,
    path: input.path || null,
    networkTarget: input.networkTarget || null,
  });

  const verdict = { decision, score: totalScore, risks: allRisks, reasons, hardBlock: false, log_id };
  if (vigilResult) verdict.vigilResult = vigilResult;
  if (proactiveResult && !proactiveResult.clean) verdict.proactiveResult = proactiveResult;
  return verdict;
}

// ── Plain English Explanations ────────────────────────────────────────────────

const EXPLANATIONS = {
  // Hard blocks
  "HARD BLOCK — moral violation (Article II)":
    "Blocked: this proposal contains a pattern associated with fraud, extortion, or coercion. Remove the threatening or deceptive language to proceed.",
  "HARD BLOCK — protocol drift attempt (Protocol VIII)":
    "Blocked: this proposal attempts to bypass, override, or disable safety checks. CORD cannot be turned off by the agent it governs.",
  "HARD BLOCK — prompt injection attempt (Article VII)":
    "Blocked: this proposal contains a prompt injection pattern — an attempt to hijack the agent's instructions. The input has been quarantined.",

  // Scored risks
  injection:
    "Hostile code pattern detected (SQL injection, shell command, or eval). Rewrite without executable payloads.",
  exfil:
    "Data exfiltration risk — the proposal references upload, transfer, or credential-harvesting patterns.",
  privilege:
    "Elevated privilege detected — a destructive verb or admin/root grant was found. Add safety flags (--dry-run) or narrow scope.",
  intentDrift:
    "This action doesn't align with the declared session intent. Restate or update the intent lock if the goal has changed.",
  irreversibility:
    "Irreversible action with no safety indicators (dry-run, preview, etc). Add a reversibility mechanism or explicit confirmation.",
  anomaly:
    "Multiple risk dimensions triggered simultaneously — compound threat detected.",
  moralCheck:
    "Deceptive or manipulative language detected. Rewrite with transparent intent.",
  promptInjection:
    "Soft prompt injection signals found — override-style imperative language from external input.",
  piiLeakage:
    "Personal data detected (SSN, credit card, phone, or email). Remove PII before sending to external services.",
  identityCheck:
    "Identity violation — the proposal attempts to impersonate a human or claim a false identity.",
  toolRisk:
    "This tool type carries inherent risk. Higher-risk tools (exec, network) receive additional scrutiny.",
  financialRisk:
    "Financial fraud risk — the proposal contains money transfer, payment, or wallet-related patterns.",
  networkTargetRisk:
    "Suspicious network target — the destination domain contains known-malicious indicators.",
  "Intent not locked":
    "No session intent has been declared. Set an intent lock so CORD can verify actions align with your goal.",
  "Out of scope":
    "This action falls outside the declared session scope (path, command, or network target not allowed).",
  // VIGIL integration explanations
  "VIGIL BLOCK — critical threat detected":
    "VIGIL (always-on patrol) detected a critical security threat. Blocked before CORD evaluation.",
  vigilSuspicious:
    "VIGIL patrol detected suspicious patterns — CORD score amplified.",
  vigilObfuscation:
    "Content contains obfuscation (base64, unicode tricks, zero-width chars). Decoded and flagged by VIGIL.",
};

/**
 * Generate a plain English explanation of a CORD verdict.
 *
 * @param {object} verdict  - Result from evaluateProposal()
 * @returns {string}        - Human-readable explanation
 */
function explain(verdict) {
  if (!verdict || !verdict.reasons || verdict.reasons.length === 0) {
    return verdict?.decision === "ALLOW"
      ? "Approved: no risk signals detected."
      : "No specific risk signals identified.";
  }

  const lines = verdict.reasons.map((reason) => {
    const explanation = EXPLANATIONS[reason];
    return explanation || reason;
  });

  const prefix =
    verdict.decision === "BLOCK"    ? "Blocked" :
    verdict.decision === "CHALLENGE" ? "Needs approval" :
    verdict.decision === "CONTAIN"  ? "Approved with monitoring" :
    "Approved";

  if (verdict.hardBlock) {
    return lines[0]; // Hard blocks have a single, clear explanation
  }

  return `${prefix} (score ${verdict.score.toFixed(1)}):\n${lines.map((l) => `  • ${l}`).join("\n")}`;
}

/**
 * Convenience: evaluate + explain in one call.
 * Returns the full verdict with an added `explanation` field.
 */
function evaluate(input = {}) {
  const verdict = evaluateProposal(input);
  verdict.explanation = explain(verdict);
  return verdict;
}

// ── Plan-Level Validation (v4.1) ─────────────────────────────────────────────

/**
 * Validate an aggregate task plan before execution.
 *
 * Individual tasks may pass CORD checks, but their combination can form
 * exfiltration chains, privilege escalation, or cumulative network exposure.
 * This function catches cross-task threats that per-task checks miss.
 *
 * @param {Array}  tasks          - Array of task objects from LEGION decomposition
 * @param {string} sessionIntent  - The declared session goal
 * @returns {object}              - CORD verdict with planLevel: true
 */
function validatePlan(tasks = [], sessionIntent = "") {
  if (!tasks || tasks.length === 0) {
    return {
      decision: "ALLOW",
      score: 0,
      reasons: [],
      risks: {},
      hardBlock: false,
      planLevel: true,
      taskCount: 0,
    };
  }

  // 1. Concatenate all task descriptions → run as single CORD proposal
  //    Use scoreProposal (not evaluateProposal) to avoid scope/intent-lock
  //    enforcement on the aggregate text — scope checks happen per-task later.
  const combinedText = tasks.map((t) => {
    const desc = typeof t === "string" ? t : (t.description || t.text || "");
    return desc;
  }).join("\n");

  // Run hard-block checks first (moral, drift, prompt injection)
  const moral = moralRisk(combinedText);
  if (moral.hardBlock) {
    return {
      decision: "BLOCK", score: 99, reasons: ["HARD BLOCK — moral violation (Article II)"],
      risks: { moralCheck: 5 }, hardBlock: true, planLevel: true, taskCount: tasks.length,
    };
  }
  const drift = driftRisk(combinedText);
  if (drift.hardBlock) {
    return {
      decision: "BLOCK", score: 99, reasons: ["HARD BLOCK — protocol drift attempt (Protocol VIII)"],
      risks: { driftCheck: 5 }, hardBlock: true, planLevel: true, taskCount: tasks.length,
    };
  }
  const injection = promptInjectionRisk(combinedText);
  if (injection.hardBlock) {
    return {
      decision: "BLOCK", score: 99, reasons: ["HARD BLOCK — prompt injection attempt (Article VII)"],
      risks: { promptInjection: 5 }, hardBlock: true, planLevel: true, taskCount: tasks.length,
    };
  }

  // Scored risk checks on combined text — plan-relevant dimensions only.
  // Intentionally skips intentDrift and irreversibility, which produce false
  // positives on high-level task descriptions that don't match intent verbatim.
  const allGrants = tasks.flatMap((t) => typeof t === "string" ? [] : (t.grants || []));
  const planRisks = {
    injection:       injectionRisk(combinedText),
    exfil:           exfilRisk(combinedText),
    privilege:       privilegeRisk(combinedText, allGrants),
    moralCheck:      moral.score,
    promptInjection: injection.score,
    piiLeakage:      piiRisk(combinedText, ""),
    identityCheck:   identityRisk(combinedText),
    financialRisk:   financialRisk(combinedText, ""),
    networkTargetRisk: 0, // checked per-task in step 2 below
  };

  let planScore =
    planRisks.injection       * weights.injection +
    planRisks.exfil           * weights.exfil +
    planRisks.privilege       * weights.privilege +
    planRisks.moralCheck      * weights.moralCheck +
    planRisks.promptInjection * weights.promptInjection +
    planRisks.piiLeakage      * weights.piiLeakage +
    planRisks.identityCheck   * weights.identityCheck +
    planRisks.financialRisk   * (weights.financialRisk || 4);

  const planReasons = Object.entries(planRisks).filter(([, v]) => v > 0).map(([k]) => k);

  // 2. Check cumulative network exposure
  const allNetworkTargets = tasks.flatMap((t) => {
    if (typeof t === "string") return [];
    return t.networkTargets || (t.networkTarget ? [t.networkTarget] : []);
  });
  const uniqueTargets = [...new Set(allNetworkTargets)];
  if (uniqueTargets.length >= 3) {
    planScore += 2;
    planReasons.push(`Plan contacts ${uniqueTargets.length} unique network targets`);
  }

  // 3. Check privilege escalation chain (uses allGrants from risk checks above)
  const hasElevated = allGrants.some((g) => /admin|sudo|root/.test(g));
  if (hasElevated) {
    planScore += 3;
    planReasons.push("Plan requests elevated privileges");
  }

  // 4. Check cross-task data flow (write → read → exfil pattern)
  const writePaths = tasks.filter((t) => {
    if (typeof t === "string") return false;
    return t.type === "code" || t.type === "write";
  }).flatMap((t) => t.filePaths || []);

  const hasReadTasks = tasks.some((t) => {
    const desc = typeof t === "string" ? t : (t.description || "");
    return /read|load|import|require|parse|open/i.test(desc);
  });

  const hasNetworkTasks = tasks.some((t) => {
    if (typeof t === "string") return false;
    return (t.networkTargets || []).length > 0 || t.networkTarget;
  });

  if (writePaths.length > 0 && hasReadTasks && hasNetworkTasks) {
    planScore += 2;
    planReasons.push("Plan has write→read→network exfiltration chain");
  }

  // 5. Check for excessive file scope
  const allPaths = tasks.flatMap((t) => {
    if (typeof t === "string") return [];
    return t.filePaths || [];
  });
  const uniquePaths = [...new Set(allPaths)];
  if (uniquePaths.length >= 10) {
    planScore += 1;
    planReasons.push(`Plan touches ${uniquePaths.length} unique files`);
  }

  // 6. Re-threshold using the adjusted score
  const planDecision = decide(planScore);

  return {
    decision: planDecision,
    score: planScore,
    reasons: planReasons,
    risks: planRisks,
    hardBlock: false,
    planLevel: true,
    taskCount: tasks.length,
  };
}

// ── Batch Evaluation (v4.1) ──────────────────────────────────────────────────

/**
 * Evaluate multiple proposals in bulk.
 *
 * @param {Array} proposals - Array of proposal objects or strings
 * @returns {Array}         - Array of CORD verdicts
 */
function evaluateBatch(proposals = []) {
  return proposals.map((p) => {
    const normalized = typeof p === "string" ? { text: p } : p;
    return evaluateProposal(normalized);
  });
}

module.exports = {
  evaluateProposal,
  evaluate,
  explain,
  scoreProposal,
  // v1/v2 checks
  injectionRisk,
  exfilRisk,
  privilegeRisk,
  intentDriftRisk,
  irreversibilityRisk,
  anomalyRisk,
  // v3 checks
  moralRisk,
  driftRisk,
  promptInjectionRisk,
  piiRisk,
  identityRisk,
  toolRisk,
  financialRisk,
  networkTargetRisk,
  // v4.1 additions
  validatePlan,
  evaluateBatch,
};
