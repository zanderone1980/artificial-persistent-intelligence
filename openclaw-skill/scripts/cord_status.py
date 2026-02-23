#!/usr/bin/env python3
"""Quick CORD status check — intent lock, recent audit entries, chain integrity."""

from __future__ import annotations

import sys
from pathlib import Path

# Point to the actual cord_engine location
CORD_ROOT = Path.home() / "ClaudeWork" / "artificial-persistent-intelligence"
sys.path.insert(0, str(CORD_ROOT))

from cord_engine.intent_lock import load_intent_lock, DEFAULT_LOCK_PATH
from cord_engine.audit_log import verify_chain, read_log, DEFAULT_LOG_PATH


def main():
    print("=" * 60)
    print("  CORD Status Report")
    print("=" * 60)

    # Intent lock
    print("\n[Intent Lock]")
    lock = load_intent_lock()
    if lock:
        print(f"  User:   {lock.user_id}")
        print(f"  Intent: {lock.intent_text}")
        print(f"  Since:  {lock.created_at}")
        if lock.scope:
            print(f"  Paths:  {lock.scope.allow_paths}")
            print(f"  Network: {lock.scope.allow_network_targets}")
    else:
        print("  No intent lock set — operating in restricted mode")

    # Audit log
    print("\n[Audit Log]")
    entries = read_log()
    print(f"  Total entries: {len(entries)}")

    if entries:
        print("\n  Last 5 entries:")
        for entry in entries[-5:]:
            decision = entry.get("decision", "?")
            score = entry.get("score", "?")
            proposal = entry.get("proposal", "?")[:60]
            ts = entry.get("timestamp", "?")[:19]
            print(f"    [{ts}] {decision} ({score}) — {proposal}")

    # Chain integrity
    print("\n[Chain Integrity]")
    valid, count = verify_chain()
    status = "VALID" if valid else "CORRUPTED"
    print(f"  Status: {status}")
    print(f"  Entries verified: {count}")
    print()


if __name__ == "__main__":
    main()
