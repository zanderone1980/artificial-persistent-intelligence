"""CORD Tool Interceptor — framework-level enforcement for AI agent tool calls.

Instead of requiring agents to manually call ``evaluate()`` before every action,
the interceptor wraps tool functions so CORD evaluation happens *automatically*.

Three integration patterns:

1. **Decorator** — wrap individual functions::

       @cord_guard("exec")
       def run_shell(cmd: str) -> str:
           return subprocess.check_output(cmd, shell=True).decode()

2. **Registry** — wrap all tools in a dict/registry at once::

       tools = {"exec": run_shell, "write": write_file, "read": read_file}
       guarded = guard_registry(tools)
       guarded["exec"]("ls -la")  # Evaluated through CORD before execution

3. **Context manager** — temporary enforcement scope::

       with CORDEnforcer(tool_name="browser") as enforcer:
           result = enforcer.call(browse, url="https://example.com")

All three patterns:
- Build a ``Proposal`` from the tool call arguments
- Run the full 9-step CORD pipeline
- Route based on the ``Verdict.decision``
- Raise ``ToolBlocked`` on BLOCK, call the on_challenge hook on CHALLENGE
- Log everything to the hash-chained audit trail
"""

from __future__ import annotations

import functools
import inspect
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypeVar, Protocol

from .models import Proposal, Verdict, Decision
from .engine import evaluate
from .policies import TOOL_RISK_TIERS


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ToolBlocked(Exception):
    """Raised when CORD blocks a tool call."""

    def __init__(self, verdict: Verdict, tool_name: str, args_summary: str):
        self.verdict = verdict
        self.tool_name = tool_name
        self.args_summary = args_summary
        reasons = "; ".join(verdict.reasons[:3])
        super().__init__(
            f"CORD BLOCK — {tool_name}({args_summary}) "
            f"[score={verdict.score}, violations={verdict.article_violations}] "
            f"{reasons}"
        )


class ToolChallenged(Exception):
    """Raised when CORD challenges a tool call and no on_challenge handler approves it."""

    def __init__(self, verdict: Verdict, tool_name: str, args_summary: str):
        self.verdict = verdict
        self.tool_name = tool_name
        self.args_summary = args_summary
        super().__init__(
            f"CORD CHALLENGE — {tool_name}({args_summary}) "
            f"[score={verdict.score}] Requires principal confirmation."
        )


# ---------------------------------------------------------------------------
# Callback protocols
# ---------------------------------------------------------------------------

class ChallengeHandler(Protocol):
    """Called when CORD issues a CHALLENGE decision.

    Return True to allow execution, False to block.
    """

    def __call__(self, verdict: Verdict, tool_name: str, args: tuple, kwargs: dict) -> bool:
        ...


class VerdictCallback(Protocol):
    """Called after every evaluation, regardless of outcome. For telemetry/logging."""

    def __call__(self, verdict: Verdict, tool_name: str) -> None:
        ...


# ---------------------------------------------------------------------------
# Proposal builder — maps tool arguments into CORD Proposal fields
# ---------------------------------------------------------------------------

def build_proposal(
    tool_name: str,
    args: tuple,
    kwargs: dict,
    *,
    source: str = "agent",
    session_intent: str = "",
    context: dict[str, Any] | None = None,
) -> Proposal:
    """Build a CORD Proposal from a tool call's arguments.

    Extracts meaningful fields based on tool type:
    - ``exec``/``command``: text is the command string, grants=["shell"]
    - ``write``/``edit``: target_path from first path-like arg
    - ``network``/``browser``: network_target from URL args
    - ``message``: action_type="communication"
    - ``read``/``query``: action_type="query"

    For all tools, any kwarg named ``raw_input``, ``input``, ``body``,
    ``content``, or ``data`` is captured as raw_input for injection scanning.
    """
    # Flatten args and kwargs into a searchable text representation
    all_values = list(args) + list(kwargs.values())
    text_parts = [str(v) for v in all_values if v is not None]
    text = " ".join(text_parts) if text_parts else tool_name

    # Detect action type from tool name
    action_type = _tool_to_action_type(tool_name)

    # Extract specific fields based on tool type
    target_path = None
    network_target = None
    grants: list[str] = []
    raw_input = ""

    # -- Shell/exec tools --
    if tool_name in ("exec", "shell", "command", "bash", "subprocess"):
        grants = ["shell"]
        # First positional arg is usually the command
        if args:
            text = str(args[0])
        elif "cmd" in kwargs:
            text = str(kwargs["cmd"])
        elif "command" in kwargs:
            text = str(kwargs["command"])

    # -- File operation tools --
    elif tool_name in ("write", "edit", "create", "delete", "move", "copy"):
        for v in all_values:
            if isinstance(v, (str, Path)) and _looks_like_path(str(v)):
                target_path = str(v)
                break
        # For write/edit, capture the content being written
        for key in ("content", "data", "body", "text"):
            if key in kwargs and kwargs[key]:
                raw_input = str(kwargs[key])[:2000]  # Cap for performance
                break

    # -- Network tools --
    elif tool_name in ("network", "browser", "fetch", "request", "http"):
        import re
        for v in all_values:
            url_match = re.search(r"https?://([^\s/]+)", str(v))
            if url_match:
                network_target = url_match.group(1)
                break
        if "url" in kwargs:
            url_match = re.search(r"https?://([^\s/]+)", str(kwargs["url"]))
            if url_match:
                network_target = url_match.group(1)

    # -- Read tools (low risk) --
    elif tool_name in ("read", "query", "search", "list", "get"):
        for v in all_values:
            if isinstance(v, (str, Path)) and _looks_like_path(str(v)):
                target_path = str(v)
                break

    # -- Message tools --
    elif tool_name in ("message", "send", "email", "post", "publish"):
        for key in ("body", "content", "message", "text"):
            if key in kwargs and kwargs[key]:
                raw_input = str(kwargs[key])[:2000]
                break

    # Catch-all: capture untrusted input from common kwarg names
    if not raw_input:
        for key in ("raw_input", "input", "body", "content", "data", "payload"):
            if key in kwargs and kwargs[key]:
                raw_input = str(kwargs[key])[:2000]
                break

    return Proposal(
        text=text,
        action_type=action_type,
        target_path=target_path,
        network_target=network_target,
        grants=grants,
        session_intent=session_intent,
        context=context or {},
        tool_name=tool_name,
        source=source,
        raw_input=raw_input,
    )


def _tool_to_action_type(tool_name: str) -> str:
    """Map a tool name to a CORD action type."""
    mapping = {
        "exec": "command", "shell": "command", "command": "command",
        "bash": "command", "subprocess": "command",
        "write": "file_op", "edit": "file_op", "create": "file_op",
        "delete": "file_op", "move": "file_op", "copy": "file_op",
        "read": "query", "query": "query", "search": "query",
        "list": "query", "get": "query",
        "network": "network", "browser": "network", "fetch": "network",
        "request": "network", "http": "network",
        "message": "communication", "send": "communication",
        "email": "communication", "post": "communication",
        "publish": "communication",
    }
    return mapping.get(tool_name, "unknown")


def _looks_like_path(s: str) -> bool:
    """Heuristic: does this string look like a filesystem path?"""
    # Exclude URLs — they contain / but aren't paths
    if s.startswith(("http://", "https://", "ftp://", "s3://")):
        return False
    return (
        s.startswith("/") or
        s.startswith("~/") or
        s.startswith("./") or
        s.startswith("../")
    )


def _summarize_args(args: tuple, kwargs: dict, max_len: int = 80) -> str:
    """Create a short summary of tool call arguments for error messages."""
    parts = [repr(a) for a in args[:3]]
    parts += [f"{k}={repr(v)}" for k, v in list(kwargs.items())[:3]]
    summary = ", ".join(parts)
    if len(summary) > max_len:
        summary = summary[:max_len - 3] + "..."
    return summary


# ---------------------------------------------------------------------------
# Pattern 1: @cord_guard decorator
# ---------------------------------------------------------------------------

F = TypeVar("F", bound=Callable)


def cord_guard(
    tool_name: str,
    *,
    source: str = "agent",
    session_intent: str = "",
    on_challenge: ChallengeHandler | None = None,
    on_verdict: VerdictCallback | None = None,
    repo_root: str | None = None,
    lock_path: Path | None = None,
    log_path: Path | None = None,
) -> Callable[[F], F]:
    """Decorator that enforces CORD evaluation before a tool function executes.

    Usage::

        @cord_guard("exec")
        def run_shell(cmd: str) -> str:
            return subprocess.check_output(cmd, shell=True).decode()

        run_shell("ls -la")       # → evaluated, allowed
        run_shell("rm -rf /")     # → ToolBlocked raised

    Args:
        tool_name: Identifier for the tool (maps to TOOL_RISK_TIERS).
        source: Origin of the call ("agent", "external", "user", "tool_result").
        session_intent: Declared session purpose for intent matching.
        on_challenge: Callback for CHALLENGE decisions. If None or returns False,
            ToolChallenged is raised.
        on_verdict: Callback invoked after every evaluation (for telemetry).
        repo_root: Override repo root for scope checks.
        lock_path: Override intent lock file path.
        log_path: Override audit log file path.
    """
    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Build proposal from arguments
            proposal = build_proposal(
                tool_name, args, kwargs,
                source=source,
                session_intent=session_intent,
            )

            # Evaluate through CORD pipeline
            verdict = evaluate(
                proposal,
                repo_root=repo_root,
                lock_path=lock_path,
                log_path=log_path,
            )

            # Telemetry callback
            if on_verdict:
                on_verdict(verdict, tool_name)

            # Route based on decision
            args_summary = _summarize_args(args, kwargs)

            if verdict.decision == Decision.BLOCK:
                raise ToolBlocked(verdict, tool_name, args_summary)

            if verdict.decision == Decision.CHALLENGE:
                approved = False
                if on_challenge:
                    approved = on_challenge(verdict, tool_name, args, kwargs)
                if not approved:
                    raise ToolChallenged(verdict, tool_name, args_summary)

            # ALLOW or CONTAIN — execute the tool
            return fn(*args, **kwargs)

        # Attach metadata for introspection
        wrapper._cord_guarded = True  # type: ignore[attr-defined]
        wrapper._cord_tool_name = tool_name  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Pattern 2: guard_registry — wrap a dict of tool functions
# ---------------------------------------------------------------------------

def guard_registry(
    tools: dict[str, Callable],
    *,
    source: str = "agent",
    session_intent: str = "",
    on_challenge: ChallengeHandler | None = None,
    on_verdict: VerdictCallback | None = None,
    repo_root: str | None = None,
    lock_path: Path | None = None,
    log_path: Path | None = None,
    tool_name_map: dict[str, str] | None = None,
) -> dict[str, Callable]:
    """Wrap all tools in a registry dict with CORD enforcement.

    Usage::

        tools = {
            "exec": run_shell,
            "write": write_file,
            "read": read_file,
        }
        guarded = guard_registry(tools)
        guarded["exec"]("ls -la")   # Evaluated through CORD

    Args:
        tools: Mapping of tool_name → callable.
        tool_name_map: Optional mapping to override the CORD tool_name for
            registry keys (e.g. ``{"run_cmd": "exec"}``).
        **kwargs: Passed to cord_guard for each tool.

    Returns:
        New dict with the same keys, but all callables wrapped.
    """
    name_map = tool_name_map or {}
    guarded: dict[str, Callable] = {}

    for key, fn in tools.items():
        cord_name = name_map.get(key, key)
        guarded[key] = cord_guard(
            cord_name,
            source=source,
            session_intent=session_intent,
            on_challenge=on_challenge,
            on_verdict=on_verdict,
            repo_root=repo_root,
            lock_path=lock_path,
            log_path=log_path,
        )(fn)

    return guarded


# ---------------------------------------------------------------------------
# Pattern 3: CORDEnforcer context manager
# ---------------------------------------------------------------------------

@dataclass
class CORDEnforcer:
    """Context manager for scoped CORD enforcement.

    Usage::

        with CORDEnforcer(tool_name="browser") as enforcer:
            result = enforcer.call(browse, url="https://example.com")

    Or use it standalone::

        enforcer = CORDEnforcer(tool_name="exec")
        result = enforcer.call(run_shell, cmd="ls -la")
        print(enforcer.verdicts)  # All verdicts from this enforcer's lifetime

    Attributes:
        verdicts: List of all verdicts produced during this enforcer's scope.
        blocked_count: Number of BLOCK decisions.
        allowed_count: Number of ALLOW/CONTAIN decisions.
    """

    tool_name: str
    source: str = "agent"
    session_intent: str = ""
    on_challenge: ChallengeHandler | None = None
    repo_root: str | None = None
    lock_path: Path | None = None
    log_path: Path | None = None
    verdicts: list[Verdict] = field(default_factory=list)
    blocked_count: int = 0
    allowed_count: int = 0
    challenged_count: int = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Don't suppress exceptions
        return False

    def call(self, fn: Callable, *args, **kwargs) -> Any:
        """Execute a function through CORD evaluation.

        Args:
            fn: The function to call.
            *args, **kwargs: Arguments to pass to the function.

        Returns:
            The function's return value (if allowed).

        Raises:
            ToolBlocked: If CORD blocks the call.
            ToolChallenged: If CORD challenges and no handler approves.
        """
        proposal = build_proposal(
            self.tool_name, args, kwargs,
            source=self.source,
            session_intent=self.session_intent,
        )

        verdict = evaluate(
            proposal,
            repo_root=self.repo_root,
            lock_path=self.lock_path,
            log_path=self.log_path,
        )

        self.verdicts.append(verdict)
        args_summary = _summarize_args(args, kwargs)

        if verdict.decision == Decision.BLOCK:
            self.blocked_count += 1
            raise ToolBlocked(verdict, self.tool_name, args_summary)

        if verdict.decision == Decision.CHALLENGE:
            self.challenged_count += 1
            approved = False
            if self.on_challenge:
                approved = self.on_challenge(verdict, self.tool_name, args, kwargs)
            if not approved:
                raise ToolChallenged(verdict, self.tool_name, args_summary)

        self.allowed_count += 1
        return fn(*args, **kwargs)

    def evaluate_only(self, text: str, **proposal_kwargs) -> Verdict:
        """Evaluate a proposal without executing anything.

        Useful for pre-flight checks.
        """
        proposal = Proposal(
            text=text,
            tool_name=self.tool_name,
            source=self.source,
            session_intent=self.session_intent,
            **proposal_kwargs,
        )
        verdict = evaluate(
            proposal,
            repo_root=self.repo_root,
            lock_path=self.lock_path,
            log_path=self.log_path,
        )
        self.verdicts.append(verdict)
        return verdict

    @property
    def last_verdict(self) -> Verdict | None:
        """Most recent verdict, or None if no evaluations have run."""
        return self.verdicts[-1] if self.verdicts else None

    @property
    def total_evaluations(self) -> int:
        return len(self.verdicts)


# ---------------------------------------------------------------------------
# Convenience: guard a single callable (without decorator syntax)
# ---------------------------------------------------------------------------

def guard(
    fn: Callable,
    tool_name: str,
    *,
    source: str = "agent",
    session_intent: str = "",
    on_challenge: ChallengeHandler | None = None,
    on_verdict: VerdictCallback | None = None,
    **eval_kwargs,
) -> Callable:
    """Wrap a single callable with CORD enforcement.

    Like ``cord_guard`` but without the ``@decorator`` syntax::

        safe_exec = guard(run_shell, "exec")
        safe_exec("ls -la")

    Equivalent to::

        @cord_guard("exec")
        def safe_exec(cmd): ...
    """
    return cord_guard(
        tool_name,
        source=source,
        session_intent=session_intent,
        on_challenge=on_challenge,
        on_verdict=on_verdict,
        **eval_kwargs,
    )(fn)
