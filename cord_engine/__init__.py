"""CORD — Counter-Operations & Risk Detection.

The enforcement engine for SENTINEL / Artificial Persistent Intelligence.
Evaluates proposed actions against the full SENTINEL Constitution.

Usage:
    from cord_engine import evaluate, Proposal

    verdict = evaluate(Proposal(
        text="git push origin main",
        grants=["network:git"],
        session_intent="Deploy site updates",
    ))
    print(verdict.decision)   # Decision.ALLOW
    print(verdict.to_json())  # Full structured result
"""

from .models import Proposal, Verdict, Decision, CheckResult, ActionType
from .engine import evaluate
from .intent_lock import set_intent_lock, load_intent_lock, verify_passphrase
from .audit_log import verify_chain, read_log

__version__ = "2.0.0"
__all__ = [
    "evaluate",
    "Proposal",
    "Verdict",
    "Decision",
    "CheckResult",
    "ActionType",
    "set_intent_lock",
    "load_intent_lock",
    "verify_passphrase",
    "verify_chain",
    "read_log",
]
