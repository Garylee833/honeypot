#!/usr/bin/env python3
"""verify_chain.py — verify the hash chain of a honeypot event log.

Usage:
    python3 verify_chain.py [logfile]     # default: logs/events.jsonl

Exit codes:
    0  intact — every surviving chained line is unmodified and in order
    1  BROKEN — tampering detected (reports the first bad line number)
    2  usage error / log file missing

Pre-chain lines (written before chaining existed, or by a writer that
bypasses chainlog) are tolerated: they are reported as the chain-start
boundary, not as tampering. A log with ZERO chained lines exits 1 —
"nothing to verify" is itself suspicious.

Known blind spot (see chainlog.py): truncating lines off the TAIL of the
file still verifies. Pair with external line-count monitoring.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chainlog  # noqa: E402  (local module, same directory)

try:
    import fcntl
    _HAVE_FCNTL = True
except ImportError:
    _HAVE_FCNTL = False


def verify(path):
    """Returns (exit_code, report_lines)."""
    report = []
    expected_prev = chainlog.GENESIS
    chained = 0
    unchained = 0
    first_chained = None
    try:
        f = open(path, "r", encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return 2, [f"no such log file: {path}"]
    with f:
        if _HAVE_FCNTL:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # don't read a torn line
        try:
            for lineno, raw in enumerate(f, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    return 1, [f"BROKEN at line {lineno}: not valid JSON"]
                if not isinstance(e, dict) or not isinstance(e.get("hash"), str):
                    unchained += 1
                    continue
                if first_chained is None:
                    first_chained = lineno
                chained += 1
                if e.get("prev_hash") != expected_prev:
                    return 1, [
                        f"BROKEN at line {lineno}: prev_hash mismatch",
                        f"  expected {expected_prev[:16]}...",
                        f"  found    {str(e.get('prev_hash'))[:16]}...",
                        "  -> a line was inserted, deleted, or reordered here.",
                    ]
                if chainlog.compute_hash(e["prev_hash"], e) != e["hash"]:
                    return 1, [
                        f"BROKEN at line {lineno}: hash mismatch",
                        "  -> this line's content was modified after logging.",
                    ]
                expected_prev = e["hash"]
        finally:
            if _HAVE_FCNTL:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    if chained == 0:
        return 1, ["BROKEN: no chained lines found — "
                   "log is empty or was rewritten without the chain."]
    report.append(f"OK: {chained} chained lines verified, "
                  f"tip {expected_prev[:16]}...")
    if unchained:
        where = (f"chain starts at line {first_chained}"
                 if first_chained and first_chained > 1
                 else "unchained lines interleaved with chained ones")
        report.append(f"note: {unchained} unchained line(s) skipped ({where}); "
                      "they cannot be verified — investigate if unexpected.")
    else:
        report.append("note: no unchained lines; chain starts at line 1.")
    return 0, report


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join("logs", "events.jsonl")
    code, report = verify(path)
    print("\n".join(report))
    sys.exit(code)


if __name__ == "__main__":
    main()
