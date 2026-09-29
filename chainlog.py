#!/usr/bin/env python3
"""chainlog — tamper-evident hash-chained JSON-lines logging. Stdlib only.

Every event appended through append_event() gains two fields::

    prev_hash:  hash of the previous chained event ("GENESIS" for the first)
    hash:       SHA256(prev_hash + canonical_json(event_without_hash_fields))

``verify_chain.py`` replays the file and reports the first broken link.

Design notes (read before "improving" this):
- Cross-process safe: the read-tail + append happens under an exclusive
  flock, so the honeypot's service threads AND the aliveness generator
  (a separate process writing synthetic events to the same file) can't
  interleave and fork the chain. Threads inside one process each open
  their own fd, and flock serializes separate opens even in-process.
- If fcntl is unavailable (non-POSIX), it degrades to a threading lock
  and prints a one-time warning: cross-process chaining is then NOT safe.
- Only the last 64 KiB of the file is scanned for the previous hash. On a
  busy public honeypot, rotate logs (see HARDENING.md) so the tail scan
  always finds the chain tip.
- TRUNCATION BLIND SPOT (documented, not fixable in-band): deleting lines
  off the TAIL of the file still verifies — the chain only proves that
  every *surviving* chained line is unmodified and in order. Pair with
  external line-count / size monitoring for full tamper evidence.
"""

import hashlib
import json
import os
import threading

try:
    import fcntl
    _HAVE_FCNTL = True
except ImportError:  # pragma: no cover - non-POSIX fallback
    _HAVE_FCNTL = False

GENESIS = "GENESIS"
_TAIL_SCAN = 65536  # bytes of tail scanned for the chain tip
_thread_lock = threading.Lock()
_warned = False


def _canonical(entry):
    """Canonical JSON of the event, minus the chain fields themselves."""
    core = {k: v for k, v in entry.items() if k not in ("hash", "prev_hash")}
    return json.dumps(core, sort_keys=True, separators=(",", ":"))


def compute_hash(prev_hash, entry):
    """Recompute what entry['hash'] should be. Used by verify_chain.py."""
    return hashlib.sha256(
        (prev_hash + _canonical(entry)).encode("utf-8")).hexdigest()


def _tail_hash(f):
    """Return the 'hash' of the last chained line in open file f, or None."""
    try:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - _TAIL_SCAN))
        chunk = f.read()  # text mode: already str, no decode needed
    except (OSError, UnicodeDecodeError):
        # UnicodeDecodeError: the 64 KiB-back seek can land inside a
        # multibyte UTF-8 character. Treat as "no hash found", not fatal.
        return None
    last = None
    for line in chunk.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if isinstance(e, dict) and isinstance(e.get("hash"), str):
            last = e["hash"]
    return last


def append_event(log_path, entry):
    """Chain entry onto log_path and append it as one JSON line.

    Mutates entry in place (adds prev_hash + hash) and returns it.
    Every writer to a chained log MUST go through this function —
    writing raw lines forks/breaks the chain.
    """
    global _warned
    if _HAVE_FCNTL:
        # 'a+': readable, and every write lands at end-of-file.
        # errors="replace": the 64 KiB-back seek in _tail_hash can land
        # mid-multibyte-character; without this, attacker-influenced log
        # bytes raise UnicodeDecodeError and kill the service thread.
        with open(log_path, "a+", encoding="utf-8", errors="replace") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                prev = _tail_hash(f) or GENESIS
                entry["prev_hash"] = prev
                entry["hash"] = compute_hash(prev, entry)
                f.write(json.dumps(entry) + "\n")
                f.flush()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    else:
        if not _warned:
            print("[!] chainlog: fcntl unavailable — chain is NOT "
                  "cross-process safe on this platform")
            _warned = True
        with _thread_lock:
            prev = None
            try:
                with open(log_path, "r", encoding="utf-8",
                          errors="replace") as f:
                    prev = _tail_hash(f)
            except FileNotFoundError:
                pass
            entry["prev_hash"] = prev or GENESIS
            entry["hash"] = compute_hash(entry["prev_hash"], entry)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
    return entry
