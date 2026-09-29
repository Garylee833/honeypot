#!/usr/bin/env python3
"""deathwatch.py -- supervisor for honeypot.py (death forensics, not healing).

Launched by resurrect.sh instead of honeypot.py directly. On start it records
a JSON line in logs/deathwatch.log with the current boot ID; on child exit it
records HOW the child died (exit code or killing signal). It never restarts
the child itself -- the resurrect.sh cron owns restarting.

A lightweight sampler thread records /proc/meminfo every 60 s (rolling
window of the last 15 samples, ~15 min coverage) so a suspected OOM kill can
be checked against the box's memory state at death time. Sampling is
observe-only and can never crash the supervisor.

Log schema (one JSON object per line, logs/deathwatch.log):
  start: {"event":"start","ts_utc":...,"pid":...,"boot_id":...,
          "boot_changed":bool,            # only when a previous start exists
          "mem_at_start":{...}|null}      # MemTotal/MemAvailable/SwapTotal/
                                          # SwapFree (kB) + ts_utc, or null
  death: {"event":"death","ts_utc":...,"child_pid":...,
          "exit_code":N,                  # clean exit
          "mem_at_death":{...}|null}      # most recent sample, or null if
                                          # the child died before the first
       | {"event":"death","ts_utc":...,"child_pid":...,
          "killed_by_signal":N,"signal_name":"SIG...",
          "mem_at_death":{...}|null}      # killed by signal

Trap-door log (one JSON object per line, logs/trapdoor.jsonl):
  last_words: {"event":"last_words","ts_utc":...,"pid":...,"boot_id":...,
               "signal":N,"signal_name":"SIG..."}   # exact second the
                                                    # platform signaled us
  trapdoor:   {"event":"trapdoor","window_start_utc":...,  # last heartbeat
               "window_end_utc":...,"gap_seconds":N,       # this restart
               "prev_boot_id":...,"boot_id":...,
               "boot_changed":bool}
A 30 s heartbeat (logs/heartbeat.json, atomic tmp+replace) bounds each
opening even when no signal is delivered: the door opened somewhere between
the last heartbeat and the restart.

This file intentionally takes no arguments and reads no environment: the
child command is fixed so production behavior can't drift from what was
tested. honeypot.py is never modified by this supervisor: the child is
uplink-launcher.py, which attaches the uplink shipper via honeypot's own
@on_event hook and then runs honeypot.main().
"""
import collections
import json
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LOGDIR = os.path.join(HERE, "logs")
DWLOG = os.path.join(LOGDIR, "deathwatch.log")
TRAPDOOR_LOG = os.path.join(LOGDIR, "trapdoor.jsonl")
HEARTBEAT_PATH = os.path.join(LOGDIR, "heartbeat.json")
HEARTBEAT_INTERVAL_S = 30
CHILD_ARGV = ["/usr/bin/python3", "uplink-launcher.py", "--log", "logs/events.jsonl"]

MEMINFO_PATH = "/proc/meminfo"
SAMPLE_INTERVAL_S = 60
SAMPLE_WINDOW = 15  # rolling samples (~15 min of coverage)
_MEM_KEYS = ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")

_samples = collections.deque(maxlen=SAMPLE_WINDOW)
_samples_lock = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def read_boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id") as f:
            return f.read().strip() or None
    except OSError:
        return None


def boot_fallback():
    try:
        out = subprocess.run(
            ["uptime", "-s"], capture_output=True, text=True, timeout=10
        )
        stamp = out.stdout.strip()
        return ("uptime:" + stamp) if stamp else None
    except Exception:
        return None


def last_boot_id():
    """boot_id from the most recent start entry, or None if no history."""
    try:
        with open(DWLOG) as f:
            lines = f.readlines()
    except FileNotFoundError:
        return None
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        if entry.get("event") == "start" and "boot_id" in entry:
            return entry["boot_id"]
    return None


def log_event(entry):
    os.makedirs(LOGDIR, exist_ok=True)
    with open(DWLOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def read_mem_snapshot(path=MEMINFO_PATH):
    """Current memory snapshot: the four kB fields plus a UTC timestamp.
    Returns None if meminfo is unreadable or malformed."""
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return None
    vals = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        key = key.strip()
        if key in _MEM_KEYS:
            num = rest.strip().split()
            try:
                vals[key] = int(num[0])  # values are in kB
            except (ValueError, IndexError):
                return None
    if len(vals) != len(_MEM_KEYS):
        return None
    vals["ts_utc"] = now_iso()
    return vals


def _mem_warn(msg):
    print("[deathwatch] WARNING: " + msg, file=sys.stderr, flush=True)


def _sampler():
    """Daemon: rolling memory samples every SAMPLE_INTERVAL_S. Never raises;
    disables itself (once) if meminfo becomes unreadable."""
    try:
        while True:
            time.sleep(SAMPLE_INTERVAL_S)
            snap = read_mem_snapshot(MEMINFO_PATH)
            if snap is None:
                _mem_warn("meminfo unreadable; memory sampling disabled")
                return
            with _samples_lock:
                _samples.append(snap)
    except Exception as exc:  # absolute backstop: sampler must never kill us
        _mem_warn("sampler failed (%r); memory sampling disabled" % (exc,))
        return


def latest_sample():
    """Most recent memory sample, or None if none has been taken yet."""
    with _samples_lock:
        return _samples[-1] if _samples else None


def _append_trapdoor(entry):
    """Append one event to the trap-door log. Never raises."""
    try:
        os.makedirs(LOGDIR, exist_ok=True)
        with open(TRAPDOOR_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        _mem_warn("trapdoor log write failed (%r)" % (exc,))


def _heartbeat_loop(boot_id):
    """Daemon: proof-of-life heartbeat every HEARTBEAT_INTERVAL_S.

    Atomic tmp+replace write so a reader never sees a torn file. When the
    VM is replaced the heartbeat simply stops; on restart the gap between
    the last heartbeat and the new start bounds when the trap door opened
    -- no kill signal required."""
    while True:
        try:
            tmp = HEARTBEAT_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"ts_utc": now_iso(), "pid": os.getpid(),
                           "boot_id": boot_id}, f)
            os.replace(tmp, HEARTBEAT_PATH)
        except Exception as exc:
            _mem_warn("heartbeat write failed (%r); retrying" % (exc,))
        time.sleep(HEARTBEAT_INTERVAL_S)


def _install_last_words(boot_id):
    """If the platform delivers SIGTERM/SIGHUP on the way down, leave last
    words: the exact second the trap door opened. Then die for real."""
    def _handler(signum, frame):
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = str(signum)
        _append_trapdoor({
            "event": "last_words",
            "ts_utc": now_iso(),
            "pid": os.getpid(),
            "boot_id": boot_id,
            "signal": signum,
            "signal_name": name,
        })
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    for sig in (signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, _handler)
        except (OSError, ValueError, RuntimeError) as exc:
            _mem_warn("cannot trap signal %r (%r)" % (sig, exc))


def _record_trapdoor_window(boot_id):
    """On startup, bound when the trap door opened: [last heartbeat, now].

    Runs before this process writes its first heartbeat, so a stale
    heartbeat file can only come from a previous life."""
    try:
        with open(HEARTBEAT_PATH) as f:
            hb = json.load(f)
    except (OSError, ValueError):
        return
    last_ts = hb.get("ts_utc")
    prev_boot = hb.get("boot_id")
    if not last_ts:
        return
    try:
        last = datetime.fromisoformat(last_ts)
    except ValueError:
        return
    now = datetime.now(timezone.utc)
    gap = (now - last).total_seconds()
    if gap < 0:
        return  # clock skew; ignore
    if prev_boot != boot_id or gap > HEARTBEAT_INTERVAL_S * 3:
        _append_trapdoor({
            "event": "trapdoor",
            "window_start_utc": last_ts,
            "window_end_utc": now.isoformat(),
            "gap_seconds": round(gap, 1),
            "prev_boot_id": prev_boot,
            "boot_id": boot_id,
            "boot_changed": prev_boot != boot_id,
        })


def main():
    boot_id = read_boot_id() or boot_fallback()
    prev = last_boot_id()

    mem_start = read_mem_snapshot(MEMINFO_PATH)
    if mem_start is None:
        _mem_warn("meminfo unreadable at startup; memory sampling disabled")
    else:
        threading.Thread(target=_sampler, daemon=True,
                         name="deathwatch-mem-sampler").start()

    start_entry = {
        "event": "start",
        "ts_utc": now_iso(),
        "pid": os.getpid(),
        "boot_id": boot_id,
        "mem_at_start": mem_start,
    }
    if prev is not None:
        start_entry["boot_changed"] = prev != boot_id
    log_event(start_entry)

    _record_trapdoor_window(boot_id)   # bound the last trap-door opening
    _install_last_words(boot_id)       # exact timestamp if we're signaled
    threading.Thread(target=_heartbeat_loop, args=(boot_id,), daemon=True,
                     name="deathwatch-heartbeat").start()

    stdout_log = open(os.path.join(LOGDIR, "stdout.log"), "a")
    child = subprocess.Popen(
        CHILD_ARGV,
        cwd=HERE,
        stdout=stdout_log,
        stderr=subprocess.STDOUT,
    )
    rc = child.wait()
    stdout_log.close()

    death = {
        "event": "death",
        "ts_utc": now_iso(),
        "child_pid": child.pid,
        "mem_at_death": latest_sample(),
    }
    if rc < 0:
        death["killed_by_signal"] = -rc
        try:
            death["signal_name"] = signal.Signals(-rc).name
        except ValueError:
            pass
    else:
        death["exit_code"] = rc
    log_event(death)
    return 0


if __name__ == "__main__":
    sys.exit(main())
