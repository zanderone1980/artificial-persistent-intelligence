# SENTINEL / CORD Integration Notes

**For sharing context with partner Claude on claude.ai**

---

## What Was Built

### SENTINEL Constitution V2 (`SENTINEL_Constitution_V2.md`)
- All 11 original articles preserved with full philosophical text
- Each article now has a **Technical Specification** table mapping it to a CORD dimension
- New **Article XII** — full CORD engine technical specification
- Covers: pipeline steps, intent lock, audit log, anomaly amplification, decision thresholds

### CORD v2 Python Engine (`cord_engine/`)

**Architecture:**
```
cord_engine/
  __init__.py        — Public API (evaluate, Proposal, Verdict, etc.)
  models.py          — Data classes: Proposal, Verdict, Decision, CheckResult
  policies.py        — Weights, thresholds, regex patterns, verb lists
  constitution.py    — All 11 articles as callable check functions
  scoring.py         — Weighted composite scoring with anomaly amplification
  engine.py          — The 9-step CORD pipeline
  intent_lock.py     — Session intent binding with SHA-256 passphrase
  audit_log.py       — Append-only JSONL with hash chaining
  cli.py             — CLI wrapper (the `api` command mediator)
  __main__.py        — Module entry point
  demo.py            — 17 test scenarios
```

**The 9-Step Pipeline:**
```
NORMALIZE → AUTHENTICATE → SCOPE CHECK → INTENT MATCH → CONSTITUTIONAL CHECK → RISK SCORE → DECISION → AUDIT → VERDICT
```

**Decision Outcomes:**
| Score | Decision | Behavior |
|-------|----------|----------|
| < 3.0 | ALLOW | Execute immediately |
| 3.0–4.99 | CONTAIN | Execute with monitoring |
| 5.0–6.99 | CHALLENGE | Requires Principal confirmation |
| >= 7.0 | BLOCK | Prohibited, not executed |

Hard blocks from Articles II (moral), VII (security), VIII (drift) bypass scoring entirely.

**Article-to-Dimension Mapping:**
| Article | Dimension | Weight |
|---------|-----------|--------|
| I — Prime Directive | `long_term_alignment` | 3 |
| II — Moral Constraints | `moral_check` | 5 |
| III — Truth & Integrity | `truth_check` | 2 |
| IV — Proactive Reasoning | `consequence_analysis` | 3 |
| V — Human Optimization | `sustainability_check` | 2 |
| VI — Financial Stewardship | `financial_risk` | 3 |
| VII — Security & Privacy | `security_check` | 4 |
| VIII — Learning & Adaptation | `drift_check` | 2 |
| IX — Command Evaluation | `evaluation_framework` | 3 |
| X — Temperament | `temperament_check` | 1 |
| XI — Identity | `identity_check` | 1 |

### CLI Wrapper (`cord` command)
The command mediator from the architecture page is now functional:
```bash
cord git push origin main       # Routed through CORD
cord rm -rf ~/junk              # BLOCKED
cord --lock                     # Set intent lock
cord --status                   # View lock status
cord --log                      # View audit entries
cord --verify                   # Verify chain integrity
```

### Website Updates
- `wolf.html` — Added CORD v2 pipeline visualization, decision outcomes, constitutional coverage cards, CLI usage section

---

## Key Design Decisions

1. **CORD name kept as "Counter-Operations & Risk Detection"** — the original name from v1
2. **Python engine is standalone** — no external dependencies, standard library only
3. **JS engine (`cord/`) left intact** — serves as the v1 reference implementation
4. **Constitutional checks are modular** — each article is a separate function, easy to extend
5. **Hard blocks are immutable** — Articles II, VII, VIII can trigger instant BLOCK regardless of composite score
6. **Audit log uses hash chaining** — each entry's hash includes the previous entry's hash, making tampering detectable
7. **Intent lock is required** — without one, SENTINEL operates in restricted mode with elevated risk scores
8. **Anomaly amplification** — when multiple dimensions flag high risk simultaneously, the composite score is amplified (+1 to +3)

---

## Usage from Python

```python
from cord_engine import evaluate, Proposal, set_intent_lock

# Set intent lock
set_intent_lock(
    user_id="alex",
    passphrase="my-passphrase",
    intent_text="Deploy site updates",
    scope={
        "allow_paths": ["/path/to/repo"],
        "allow_commands": [r"^git\s+"],
        "allow_network_targets": ["github.com"],
    },
)

# Evaluate a proposal
verdict = evaluate(Proposal(
    text="git push origin main",
    grants=["network:git"],
    session_intent="Deploy site updates",
    network_target="github.com",
))

print(verdict.decision)        # Decision.ALLOW
print(verdict.score)           # 0.0
print(verdict.to_json())       # Full structured result
```

---

## What's Next

- Integration with the SENTINEL Partner Loop (Observe → Assess → Decide → Plan → Request → Act → Measure → Learn)
- Real-time monitoring mode for CORD
- Persistent user model storage (encrypted)
- Cloud acceleration gateway with zero-trust mediation
- Expanded pattern detection (more injection vectors, social engineering, etc.)
