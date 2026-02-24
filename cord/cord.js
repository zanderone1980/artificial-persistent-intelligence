const path = require("path");
const { weights, thresholds, regex, highImpactVerbs, allowlistKeywords } = require("./policies");
const { appendLog } = require("./logger");
const { loadIntentLock } = require("./intentLock");

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
  return highSignals >= 3 ? 2 : highSignals >= 2 ? 1 : 0;
}

function scoreProposal({ text = "", proposal = "", grants = [], sessionIntent = "" }) {
  const base = {
    injection: injectionRisk(text || proposal),
    exfil: exfilRisk(text || proposal),
    privilege: privilegeRisk(proposal, grants),
    intentDrift: intentDriftRisk(proposal, sessionIntent),
    irreversibility: irreversibilityRisk(proposal),
  };
  base.anomaly = anomalyRisk(base);

  const weighted =
    base.injection * weights.injection +
    base.exfil * weights.exfil +
    base.privilege * weights.privilege +
    base.intentDrift * weights.intentDrift +
    base.irreversibility * weights.irreversibility +
    base.anomaly * weights.anomaly;

  return { risks: base, score: weighted };
}

function decide(score) {
  if (score >= thresholds.block) return "BLOCK";
  if (score >= thresholds.challenge) return "CHALLENGE";
  if (score >= thresholds.contain) return "CONTAIN";
  return "ALLOW";
}

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

function evaluateProposal(input = {}) {
  const repoRoot = path.resolve(__dirname, "..");
  const { lock, intentIssue } = ensureIntentLock();

  const { risks, score } = scoreProposal(input);
  let decision = decide(score);
  const reasons = Object.entries(risks)
    .filter(([, v]) => v > 0)
    .map(([k]) => k);

  // Intent lock enforcement
  if (intentIssue) {
    decision = "CHALLENGE";
    reasons.push(intentIssue);
  }

  // Scope checks when lock present
  if (lock?.scope) {
    const scope = lock.scope;
    const pathAllowed = isPathAllowed(input.path, scope, repoRoot);
    const networkAllowed = input.networkTarget ? isNetworkAllowed(input.networkTarget, scope) : true;
    const commandAllowed = isCommandAllowed(input.proposal || input.text, scope);

    const scopeFail = !pathAllowed || !networkAllowed || !commandAllowed;
    if (scopeFail) {
      reasons.push("Out of scope");
      const highRisk = score >= thresholds.challenge || risks.privilege >= 2 || risks.irreversibility >= 3;
      decision = highRisk ? "BLOCK" : "CHALLENGE";
    }
  }

  const log_id = appendLog({
    decision,
    score,
    risks,
    reasons,
    proposal: input.proposal || input.text || "",
    path: input.path || null,
    networkTarget: input.networkTarget || null,
  });

  return { decision, score, risks, reasons, log_id };
}

module.exports = {
  evaluateProposal,
  scoreProposal,
  injectionRisk,
  exfilRisk,
  privilegeRisk,
  intentDriftRisk,
  irreversibilityRisk,
  anomalyRisk,
};
