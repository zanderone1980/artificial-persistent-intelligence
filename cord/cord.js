const { weights, thresholds, regex, highImpactVerbs, allowlistKeywords } = require("./policies");
const { appendLog } = require("./logger");

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

function evaluateProposal(input = {}) {
  const { risks, score } = scoreProposal(input);
  const decision = decide(score);
  const reasons = Object.entries(risks)
    .filter(([, v]) => v > 0)
    .map(([k]) => k);

  const log_id = appendLog({
    decision,
    score,
    risks,
    reasons,
    proposal: input.proposal || input.text || "",
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
