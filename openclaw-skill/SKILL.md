---
name: cord-sentinel
description: "SENTINEL/CORD governance engine integration. Use when: (1) a tool call is blocked and you need to understand why, (2) checking CORD audit logs, (3) setting or verifying intent locks, (4) understanding CORD decision scores and constitutional violations. CORD evaluates actions against an 11-article constitution covering security, ethics, finance, truth, and identity."
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡️",
        "requires": { "bins": ["python3"] },
      },
  }
---

# CORD — Counter-Operations & Risk Detection

CORD is the enforcement engine for the SENTINEL AI governance framework. It evaluates every proposed action against an 11-article constitution and returns a decision: **ALLOW**, **CONTAIN**, **CHALLENGE**, or **BLOCK**.

## When Tool Calls Are Blocked

If CORD blocks a tool call, the block reason will include:
- **Decision** and **score** (0-10 scale)
- **Article violations** — which constitutional articles flagged the action
- **Reasons** — specific explanations
- **Alternatives** — safer approaches

When blocked, explain to the user WHY the action was blocked and suggest the alternatives provided by CORD.

## Checking Status

Run the status script to see the current CORD state:

```bash
python3 {baseDir}/scripts/cord_status.py
```

This shows: intent lock status, recent audit log entries, and chain integrity.

## Setting Intent Locks

Before a work session, set an intent lock to define the allowed scope:

```bash
python3 -c "
from cord_engine import set_intent_lock
set_intent_lock(
    user_id='alex',
    passphrase='session-pass',
    intent_text='Deploy site updates',
    scope={
        'allow_paths': ['/path/to/repo'],
        'allow_commands': [r'^git\s+'],
        'allow_network_targets': ['github.com'],
    },
)
"
```

## Decision Thresholds

| Score | Decision | Behavior |
|-------|----------|----------|
| < 5.0 | ALLOW | Execute immediately |
| 5.0–6.99 | CONTAIN | Execute with monitoring |
| >= 7.0 | BLOCK | Prohibited |

Hard blocks from Articles II (moral), VII (security), VIII (drift) bypass scoring.

## The 11 Constitutional Articles

| # | Article | What It Checks |
|---|---------|---------------|
| I | Prime Directive | Long-term alignment, no short-term hacks |
| II | Moral Constraints | Hard ban: fraud, harm, coercion, deception |
| III | Truth & Integrity | No fabricated data or manufactured certainty |
| IV | Proactive Reasoning | Second-order consequences evaluated? |
| V | Human Optimization | Respects human limits (burnout, capacity) |
| VI | Financial Stewardship | ROI evaluation, no impulsive spending |
| VII | Security & Privacy | Injection, exfiltration, privilege escalation |
| VIII | Learning & Adaptation | Core values immutable, only capability adapts |
| IX | Command Evaluation | The 6-question gate for significant actions |
| X | Temperament | Calm, rational, no emotional escalation |
| XI | Identity | Agent stays in role, no pretense |

## References

- Read `references/cord-api.md` for the full Python API reference and proposal field definitions.
