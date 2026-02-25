"""CORD data models — Proposal, Verdict, Decision, CheckResult."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Decision(Enum):
    """CORD decision outcomes."""
    ALLOW = "ALLOW"
    CHALLENGE = "CHALLENGE"
    CONTAIN = "CONTAIN"
    BLOCK = "BLOCK"


class ActionType(Enum):
    """Categories of proposed actions."""
    COMMAND = "command"
    FILE_OP = "file_op"
    NETWORK = "network"
    FINANCIAL = "financial"
    COMMUNICATION = "communication"
    SYSTEM = "system"
    QUERY = "query"
    UNKNOWN = "unknown"


@dataclass
class Proposal:
    """A proposed action to be evaluated by CORD."""
    text: str = ""
    action_type: str = "unknown"
    target_path: str | None = None
    network_target: str | None = None
    grants: list[str] = field(default_factory=list)
    session_intent: str = ""
    context: dict[str, Any] = field(default_factory=dict)
    # v2.1 fields
    tool_name: str = ""          # OpenClaw tool being called (exec, write, browser, etc.)
    source: str = "agent"        # Origin: "agent" | "external" | "user" | "tool_result"
    raw_input: str = ""          # Untrusted input being processed (for injection scanning)

    def __post_init__(self) -> None:
        # Coerce None fields to safe defaults — prevents crashes in downstream checks
        if self.text is None:
            self.text = ""
        if self.session_intent is None:
            self.session_intent = ""
        if self.raw_input is None:
            self.raw_input = ""
        if self.tool_name is None:
            self.tool_name = ""
        if self.source is None:
            self.source = "agent"
        if self.grants is None:
            self.grants = []
        if self.context is None:
            self.context = {}

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CheckResult:
    """Result from a single constitutional check."""
    dimension: str
    article: str
    score: float  # 0 = clean, higher = riskier
    reasons: list[str] = field(default_factory=list)
    hard_block: bool = False  # Bypasses scoring, instant BLOCK

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    """Final CORD evaluation result."""
    decision: Decision
    score: float
    risk_profile: dict[str, float] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)
    article_violations: list[str] = field(default_factory=list)
    log_id: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
