#!/usr/bin/env python3
"""uplink-launcher.py — start the honeypot with the uplink shipper attached.

This is now the canonical way to launch the honeypot (deathwatch and the
guards target this process, not honeypot.py directly).

What it does:
  1. Imports uplink_shipper, which registers a @honeypot.on_event hook
     (the hook's documented pattern: `import honeypot` + decorator).
     honeypot.py itself is NOT modified.
  2. Hands argv through to honeypot.main() so --log/--ports/--profile
     keep working exactly as before.

Usage: python3 uplink-launcher.py [--log logs/events.jsonl] [honeypot args...]
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

import uplink_shipper  # noqa: F401  (registers the on_event hook on import)
import honeypot

if __name__ == "__main__":
    # Present ourselves to honeypot's argparse as `honeypot.py <args>`.
    sys.argv = ["honeypot.py"] + sys.argv[1:]
    honeypot.main()
