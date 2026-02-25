# CORD v1 — Counter-Operations & Risk Detection

CORD is the forensic validation and enforcement engine. It scores proposals against safety protocols, applies zero-trust validation, and records append-only audit entries.

## Run the demo

```bash
node demo.js
```

The demo exercises benign and hostile proposals (file edits, git push, rm -rf, secrets exfil, network exfil). Decisions will be one of: ALLOW, CONTAIN, CHALLENGE, BLOCK.

## Tuning
- Edit `policies.js` to adjust weights, thresholds, regex patterns, and high-impact verbs.
- `cord.js` uses these settings to compute a weighted score and decision.
- Logs are appended to `cord.log.jsonl` with a hash per entry.

## Decision flow
INTERCEPT → SCORE → COMPARE → ATTRIBUTE → DECIDE → LOG

## Outputs
`evaluateProposal(input)` returns `{ decision, score, risks, reasons, log_id }`.
