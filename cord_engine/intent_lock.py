"""CORD intent lock — binds sessions to a declared intent with passphrase verification."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import os as _os
DEFAULT_LOCK_PATH = Path(
    _os.environ.get("CORD_LOCK_PATH", str(Path(__file__).parent / "intent.lock.json"))
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class Scope:
    """Defines the allowed boundaries for a session."""
    allow_paths: list[str] = field(default_factory=list)
    allow_commands: list[str] = field(default_factory=list)  # regex strings
    allow_network_targets: list[str] = field(default_factory=list)

    def is_path_allowed(self, target_path: str, repo_root: str) -> bool:
        if not target_path:
            return True
        abs_path = str(Path(target_path).resolve())
        if not abs_path.startswith(str(Path(repo_root).resolve())):
            return False
        if not self.allow_paths:
            return False
        return any(abs_path.startswith(str(Path(p).resolve())) for p in self.allow_paths)

    def is_network_allowed(self, target: str) -> bool:
        if not target:
            return False
        if not self.allow_network_targets:
            return False
        return any(host in target for host in self.allow_network_targets)

    def is_command_allowed(self, proposal: str) -> bool:
        if not proposal:
            return True
        if not self.allow_commands:
            return False
        return any(re.search(pattern, proposal, re.IGNORECASE) for pattern in self.allow_commands)


@dataclass
class IntentLock:
    """An active intent lock binding a session to a declared purpose."""
    user_id: str
    intent_text: str
    scope: Scope
    passphrase_hash: str
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "intent_text": self.intent_text,
            "scope": asdict(self.scope),
            "passphrase_hash": self.passphrase_hash,
            "created_at": self.created_at,
        }


def set_intent_lock(
    user_id: str,
    passphrase: str,
    intent_text: str,
    scope: dict[str, Any] | Scope,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> IntentLock:
    """Create and persist an intent lock."""
    if not all([user_id, passphrase, intent_text]):
        raise ValueError("user_id, passphrase, and intent_text are required")

    if isinstance(scope, dict):
        scope = Scope(
            allow_paths=scope.get("allow_paths", scope.get("allowPaths", [])),
            allow_commands=scope.get("allow_commands", scope.get("allowCommands", [])),
            allow_network_targets=scope.get("allow_network_targets", scope.get("allowNetworkTargets", [])),
        )

    lock = IntentLock(
        user_id=user_id,
        intent_text=intent_text,
        scope=scope,
        passphrase_hash=_sha(passphrase),
        created_at=datetime.now(timezone.utc).isoformat(),
    )

    lock_path.write_text(json.dumps(lock.to_dict(), indent=2), encoding="utf-8")
    return lock


def load_intent_lock(lock_path: Path = DEFAULT_LOCK_PATH) -> IntentLock | None:
    """Load an existing intent lock, or None if not set."""
    if not lock_path.exists():
        return None
    try:
        data = json.loads(lock_path.read_text("utf-8"))
        scope_data = data.get("scope", {})
        scope = Scope(
            allow_paths=scope_data.get("allow_paths", []),
            allow_commands=scope_data.get("allow_commands", []),
            allow_network_targets=scope_data.get("allow_network_targets", []),
        )
        return IntentLock(
            user_id=data["user_id"],
            intent_text=data["intent_text"],
            scope=scope,
            passphrase_hash=data["passphrase_hash"],
            created_at=data.get("created_at", ""),
        )
    except (json.JSONDecodeError, KeyError):
        return None


def verify_passphrase(
    attempt: str,
    lock_path: Path = DEFAULT_LOCK_PATH,
) -> bool:
    """Verify a passphrase against the active intent lock."""
    lock = load_intent_lock(lock_path)
    if lock is None:
        return False
    return _sha(attempt) == lock.passphrase_hash
