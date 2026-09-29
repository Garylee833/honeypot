#!/usr/bin/env python3
"""test_connection_logging.py: every accepted connection is logged.

Run: python3 test_connection_logging.py   (exit 0 = all green)

Regression for the 2026-09-25 drill finding: quiet connect-and-disconnect
scans were invisible because only *conversation* was logged. A 6-port sweep
produced events for only 5 services and PORT_SCAN stayed silent.

The fix: _guarded_handler emits one "connect" event immediately after
accept() and before invoking the service handler.

This test proves:
  1. A quiet connect (open + immediate close, zero bytes sent) to every
     one of the 14 services produces exactly one "connect" event each.
  2. The event carries the right service name and source IP.
  3. Repeat connects to the same service log again (per-connection, not
     per-service dedup) — scanners knock more than once.
  4. No connection is dropped at these volumes.

All network activity is 127.0.0.1 only, high ports, in-process servers.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HONEY = os.path.dirname(os.path.abspath(__file__))
failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name
          + (" -- " + str(detail) if detail and not cond else ""))
    if not cond:
        failures.append(name)


SERVICES = [
    "ssh", "telnet", "http", "ftp", "mysql", "redis", "smtp",
    "vnc", "elastic", "docker", "postgres", "mssql", "mongo", "rdp",
]
BASE_PORT = 19001
ports = {svc: BASE_PORT + i for i, svc in enumerate(SERVICES)}


def quiet_connect(port, src_ip, timeout=10):
    """Open a TCP connection and close it immediately, sending nothing."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((src_ip, 0))
    s.connect(("127.0.0.1", port))
    s.close()


tmp = tempfile.mkdtemp(prefix="connlog-")
log_path = os.path.join(tmp, "events.jsonl")
server_code = "\n".join([
    "import sys",
    "sys.path.insert(0, %r)" % HONEY,
    "import honeypot, threading, time",
    "ports = %r" % [(ports[svc], svc) for svc in SERVICES],
    "log_path = %r" % log_path,
    "for port, svc in ports:",
    "    threading.Thread(target=honeypot.serve,",
    "                     args=(port, svc, log_path), daemon=True).start()",
    "time.sleep(120)",
])
srv = subprocess.Popen([sys.executable, "-c", server_code],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    time.sleep(3)  # let listeners come up

    # 1-2. one quiet connect per service, each from its own source IP
    src_ips = {}
    for i, svc in enumerate(SERVICES):
        src = "127.0.1.%d" % (i + 1)
        src_ips[svc] = src
        quiet_connect(ports[svc], src)
    time.sleep(2)  # let handlers flush

    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    connects = [e for e in events if e.get("data") == "connect"]
    check("14 quiet connects -> 14 connect events",
          len(connects) == 14, "got %d of 14" % len(connects))

    by_service = {}
    for e in connects:
        by_service.setdefault(e.get("service"), []).append(e)
    check("one connect event per service",
          all(len(by_service.get(svc, [])) == 1 for svc in SERVICES),
          {s: len(v) for s, v in by_service.items()})
    check("connect events carry the right source IP",
          all(by_service[svc][0].get("src_ip") == src_ips[svc]
              for svc in SERVICES if svc in by_service),
          [(e.get("service"), e.get("src_ip")) for e in connects])

    # 3. repeat knocks log again (no dedup)
    n_before = len(connects)
    quiet_connect(ports["ssh"], "127.0.1.100")
    quiet_connect(ports["ssh"], "127.0.1.101")
    time.sleep(2)
    events2 = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                events2.append(json.loads(line))
    connects2 = [e for e in events2 if e.get("data") == "connect"]
    check("repeat connects log again (per-connection, not deduped)",
          len(connects2) == n_before + 2,
          "before=%d after=%d" % (n_before, len(connects2)))

    # 4. nothing dropped at this volume
    drops = [e for e in events2 if "drop" in str(e.get("data", "")).lower()]
    check("no connections dropped", len(drops) == 0,
          "%d drop notes" % len(drops))
finally:
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except subprocess.TimeoutExpired:
        srv.kill()

print()
if failures:
    print("FAILURES: %d  %s" % (len(failures), failures))
    sys.exit(1)
print("ALL GREEN")
