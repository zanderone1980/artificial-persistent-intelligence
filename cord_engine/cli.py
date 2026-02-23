#!/usr/bin/env python3
"""CORD CLI — the command mediator.

Instead of running commands directly, route them through CORD:

    api git push origin main
    api rm -rf ~/Downloads/junk
    api pip install requests

CORD evaluates the command against the SENTINEL Constitution,
then either ALLOWs, CONTAINs, CHALLENGEs, or BLOCKs execution.

Usage:
    api <command> [args...]
    api --status          Show current intent lock status
    api --lock            Set a new intent lock interactively
    api --log             Show recent audit log entries
    api --verify          Verify audit chain integrity
    api --help            Show this help
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .models import Proposal, Decision
from .engine import evaluate
from .intent_lock import set_intent_lock, load_intent_lock, Scope
from .audit_log import verify_chain, read_log


# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
ORANGE = "\033[33m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

DECISION_COLORS = {
    Decision.ALLOW: GREEN,
    Decision.CONTAIN: YELLOW,
    Decision.CHALLENGE: ORANGE,
    Decision.BLOCK: RED,
}


def _print_banner():
    print(f"{DIM}CORD — Counter-Operations & Risk Detection{RESET}")
    print(f"{DIM}{'─' * 50}{RESET}")


def _print_verdict(verdict):
    color = DECISION_COLORS.get(verdict.decision, "")
    print(f"\n  {BOLD}Decision:{RESET} {color}{verdict.decision.value}{RESET}")
    print(f"  {BOLD}Score:{RESET}    {verdict.score}")

    if verdict.article_violations:
        print(f"  {BOLD}Violations:{RESET} {', '.join(verdict.article_violations)}")

    if verdict.reasons:
        print(f"  {BOLD}Reasons:{RESET}")
        for r in verdict.reasons:
            print(f"    {DIM}-{RESET} {r}")

    if verdict.alternatives and verdict.decision != Decision.ALLOW:
        print(f"  {BOLD}Alternatives:{RESET}")
        for a in verdict.alternatives:
            print(f"    {DIM}>{RESET} {a}")


def _confirm_challenge() -> bool:
    """Ask the Principal for explicit confirmation."""
    try:
        response = input(f"\n  {ORANGE}CHALLENGE:{RESET} Proceed anyway? [y/N] ").strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def cmd_status():
    """Show current intent lock status."""
    _print_banner()
    lock = load_intent_lock()
    if lock is None:
        print(f"  {RED}No intent lock set.{RESET}")
        print(f"  Run {BOLD}api --lock{RESET} to set one.")
        return

    print(f"  {GREEN}Intent lock active{RESET}")
    print(f"  User:    {lock.user_id}")
    print(f"  Intent:  {lock.intent_text}")
    print(f"  Created: {lock.created_at}")
    if lock.scope:
        if lock.scope.allow_paths:
            print(f"  Paths:   {', '.join(lock.scope.allow_paths)}")
        if lock.scope.allow_network_targets:
            print(f"  Network: {', '.join(lock.scope.allow_network_targets)}")
        if lock.scope.allow_commands:
            print(f"  Commands: {len(lock.scope.allow_commands)} patterns")


def cmd_lock():
    """Set a new intent lock interactively."""
    _print_banner()
    print(f"  {BOLD}Set Intent Lock{RESET}\n")

    try:
        user_id = input("  User ID: ").strip()
        passphrase = input("  Passphrase: ").strip()
        intent = input("  Intent (what are you doing this session?): ").strip()

        print(f"\n  {DIM}Scope configuration:{RESET}")
        paths_raw = input("  Allowed paths (comma-separated, or Enter for cwd): ").strip()
        network_raw = input("  Allowed network targets (comma-separated, or Enter for none): ").strip()
        commands_raw = input("  Allowed command patterns (comma-separated regex, or Enter for any): ").strip()

        allow_paths = [p.strip() for p in paths_raw.split(",") if p.strip()] if paths_raw else [os.getcwd()]
        allow_network = [n.strip() for n in network_raw.split(",") if n.strip()] if network_raw else []
        allow_commands = [c.strip() for c in commands_raw.split(",") if c.strip()] if commands_raw else []

        lock = set_intent_lock(
            user_id=user_id,
            passphrase=passphrase,
            intent_text=intent,
            scope={
                "allow_paths": allow_paths,
                "allow_commands": allow_commands,
                "allow_network_targets": allow_network,
            },
        )

        print(f"\n  {GREEN}Intent lock set.{RESET}")
        print(f"  Intent: {lock.intent_text}")

    except (EOFError, KeyboardInterrupt):
        print(f"\n  {DIM}Cancelled.{RESET}")


def cmd_log():
    """Show recent audit log entries."""
    _print_banner()
    entries = read_log()
    if not entries:
        print(f"  {DIM}No audit log entries.{RESET}")
        return

    # Show last 10
    recent = entries[-10:]
    print(f"  {BOLD}Last {len(recent)} of {len(entries)} entries:{RESET}\n")

    for entry in recent:
        decision = entry.get("decision", "?")
        color = {
            "ALLOW": GREEN, "CONTAIN": YELLOW,
            "CHALLENGE": ORANGE, "BLOCK": RED,
        }.get(decision, "")

        proposal = entry.get("proposal", "")[:60]
        timestamp = entry.get("timestamp", "")[:19]
        score = entry.get("score", 0)

        print(f"  {DIM}{timestamp}{RESET}  {color}{decision:9s}{RESET}  {score:5.1f}  {proposal}")


def cmd_verify():
    """Verify audit chain integrity."""
    _print_banner()
    valid, count = verify_chain()
    if valid:
        print(f"  {GREEN}Chain VALID{RESET} — {count} entries, integrity confirmed")
    else:
        print(f"  {RED}Chain CORRUPTED{RESET} — tampering detected at entry {count}")


def cmd_evaluate_and_run(args: list[str]):
    """Evaluate a command through CORD and optionally execute it."""
    command_text = " ".join(args)

    if not command_text:
        print(f"  {RED}No command provided.{RESET}")
        print(f"  Usage: api <command> [args...]")
        return

    _print_banner()
    print(f"  {BOLD}Command:{RESET} {command_text}\n")

    # Build proposal
    proposal = Proposal(
        text=command_text,
        action_type="command",
        session_intent="",  # Will be read from intent lock
    )

    # Check for network targets in the command
    import re
    url_match = re.search(r"https?://([^\s/]+)", command_text)
    if url_match:
        proposal.network_target = url_match.group(1)

    # Check for file paths
    for arg in args[1:]:
        if arg.startswith("/") or arg.startswith("~") or arg.startswith("./"):
            proposal.target_path = os.path.expanduser(arg)
            break

    # Load intent for session_intent field
    lock = load_intent_lock()
    if lock:
        proposal.session_intent = lock.intent_text

    # Evaluate
    verdict = evaluate(proposal)
    _print_verdict(verdict)

    # Act on decision
    if verdict.decision == Decision.ALLOW:
        print(f"\n  {GREEN}Executing...{RESET}\n")
        result = subprocess.run(args, cwd=os.getcwd())
        sys.exit(result.returncode)

    elif verdict.decision == Decision.CONTAIN:
        print(f"\n  {YELLOW}Executing with monitoring...{RESET}\n")
        result = subprocess.run(args, cwd=os.getcwd())
        sys.exit(result.returncode)

    elif verdict.decision == Decision.CHALLENGE:
        if _confirm_challenge():
            print(f"\n  {ORANGE}Principal confirmed. Executing...{RESET}\n")
            result = subprocess.run(args, cwd=os.getcwd())
            sys.exit(result.returncode)
        else:
            print(f"\n  {DIM}Action cancelled by Principal.{RESET}")
            sys.exit(1)

    elif verdict.decision == Decision.BLOCK:
        print(f"\n  {RED}BLOCKED — this action violates the SENTINEL Constitution.{RESET}")
        print(f"  {DIM}The command was not executed.{RESET}")
        sys.exit(1)


def main():
    args = sys.argv[1:]

    if not args or "--help" in args:
        print(__doc__)
        return

    if args[0] == "--status":
        cmd_status()
    elif args[0] == "--lock":
        cmd_lock()
    elif args[0] == "--log":
        cmd_log()
    elif args[0] == "--verify":
        cmd_verify()
    else:
        cmd_evaluate_and_run(args)


if __name__ == "__main__":
    main()
