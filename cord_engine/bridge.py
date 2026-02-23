#!/usr/bin/env python3
"""CORD JSON bridge — stdin/stdout interface for external callers (e.g., OpenClaw hooks).

Reads a JSON proposal from stdin, evaluates it through the CORD pipeline,
and writes the verdict as JSON to stdout.

Usage:
    echo '{"text":"rm -rf /","grants":["shell"]}' | python3 cord_engine/bridge.py
    echo '{"text":"git status"}' | python3 -m cord_engine.bridge
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running as script or module
sys.path.insert(0, str(Path(__file__).parent.parent))

from cord_engine.models import Proposal
from cord_engine.engine import evaluate


def main() -> None:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            _error("Empty input — expected JSON proposal on stdin", 1)
            return

        data = json.loads(raw)
        if not isinstance(data, dict):
            _error("Input must be a JSON object", 1)
            return

        text = data.get("text")
        if not text:
            _error("Missing required field: 'text'", 1)
            return

        proposal = Proposal(
            text=text,
            action_type=data.get("action_type", "unknown"),
            target_path=data.get("target_path"),
            network_target=data.get("network_target"),
            grants=data.get("grants", []),
            session_intent=data.get("session_intent", ""),
            context=data.get("context", {}),
        )

        # Allow overriding paths via env or input
        repo_root = data.get("repo_root")
        lock_path = data.get("lock_path")
        log_path = data.get("log_path")

        verdict = evaluate(
            proposal,
            repo_root=repo_root,
            lock_path=Path(lock_path) if lock_path else None,
            log_path=Path(log_path) if log_path else None,
        )

        sys.stdout.write(verdict.to_json() + "\n")
        sys.stdout.flush()

    except json.JSONDecodeError as e:
        _error(f"Invalid JSON: {e}", 1)
    except Exception as e:
        _error(f"Evaluation error: {e}", 1)


def _error(message: str, code: int) -> None:
    """Write a JSON error to stdout and exit."""
    error = {"error": True, "message": message}
    sys.stdout.write(json.dumps(error) + "\n")
    sys.stdout.flush()
    sys.exit(code)


if __name__ == "__main__":
    main()
