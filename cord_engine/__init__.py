"""CORD — Counter-Operations & Risk Detection.

AI governance engine for autonomous agents.
Evaluates proposed actions against configurable protocols,
enforcing safety at the framework level.

Usage (evaluate directly):
    from cord_engine import evaluate, Proposal

    verdict = evaluate(Proposal(
        text="git push origin main",
        grants=["network:git"],
        session_intent="Deploy site updates",
    ))
    print(verdict.decision)   # Decision.ALLOW

Usage (enforce automatically via interceptor):
    from cord_engine import cord_guard, guard_registry, CORDEnforcer

    @cord_guard("exec")
    def run_shell(cmd: str) -> str:
        return subprocess.check_output(cmd, shell=True).decode()

    run_shell("ls -la")     # Evaluated, allowed
    run_shell("rm -rf /")   # ToolBlocked raised automatically
"""

from .models import Proposal, Verdict, Decision, CheckResult, ActionType
from .engine import evaluate
from .intent_lock import set_intent_lock, load_intent_lock, verify_passphrase
from .audit_log import verify_chain, read_log
from .interceptor import (
    cord_guard,
    guard_registry,
    guard,
    CORDEnforcer,
    ToolBlocked,
    ToolChallenged,
    build_proposal,
)

# v4.1 framework adapters (optional — works without framework deps installed)
try:
    from .frameworks import (
        CORDCallbackHandler,
        wrap_langchain_llm,
        wrap_crewai_agent,
        wrap_llamaindex_llm,
    )
    _HAS_FRAMEWORKS = True
except ImportError:
    _HAS_FRAMEWORKS = False

__version__ = "4.1.0"
__all__ = [
    # Core pipeline
    "evaluate",
    "Proposal",
    "Verdict",
    "Decision",
    "CheckResult",
    "ActionType",
    # Intent lock
    "set_intent_lock",
    "load_intent_lock",
    "verify_passphrase",
    # Audit
    "verify_chain",
    "read_log",
    # Interceptor (v2.2)
    "cord_guard",
    "guard_registry",
    "guard",
    "CORDEnforcer",
    "ToolBlocked",
    "ToolChallenged",
    "build_proposal",
    # Framework adapters (v4.1)
    "CORDCallbackHandler",
    "wrap_langchain_llm",
    "wrap_crewai_agent",
    "wrap_llamaindex_llm",
]
