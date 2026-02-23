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
    text: str
    action_type: str = "unknown"
    target_path: str | None = None
    network_target: str | None = None
    grants: list[str] = field(default_factory=list)
    session_intent: str = ""
    context: dict[str, Any] = field(default_factory=dict)

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
