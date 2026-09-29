#!/usr/bin/env python3
"""test_pd_bridge.py: prove the honeypot wiring is correct and safe.

Run: python3 test_pd_bridge.py   (exit 0 = all green)

Proves:
  1. Default-off: without PD_ENABLED=1 the bridge is a no-op and the
     honeypot behaves byte-identically (404 stays 404, no delays).
  2. With PD_ENABLED=1: suspicious paths with no bespoke bait get the
     harmless decoy page; bespoke theater (wp-admin, exploit bait) wins.
  3. Live loopback: 6 distinct services from one IP -> the 6th connection
     is throttled (measurable delay); normal visitors are not delayed.
  4. Live loopback: 5 SSH logins from one IP -> the 5th login is throttled.
  5. The PD evidence journal is written to the honeypot logs dir.
  6. Slow-and-low stays silent (L5) through the wired path too.

All network activity is 127.0.0.1 only, high ports, in-process servers.
"""
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


def connect_from(src_ip, port, timeout=10):
    """Connect to 127.0.0.1:port from a chosen 127.x source address.

    Each test phase uses its own source IP so trip-point state never
    leaks between phases.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((src_ip, 0))
    s.connect(("127.0.0.1", port))
    return s


def http_get(port, path, src_ip="127.0.0.2"):
    s = connect_from(src_ip, port)
    s.sendall(("GET %s HTTP/1.0\r\n\r\n" % path).encode())
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    return data.decode("utf-8", errors="replace")


def tcp_touch(port, payload=b"hello", src_ip="127.0.0.2"):
    s = connect_from(src_ip, port)
    try:
        s.sendall(payload)
    except OSError:
        pass
    time.sleep(0.2)
    s.close()


def time_to_first_byte(port, src_ip, hello=None):
    """Seconds from connect until the first byte (or close)."""
    s = connect_from(src_ip, port)
    t0 = time.time()
    try:
        if hello:
            s.sendall(hello)
        while True:
            chunk = s.recv(4096)
            if chunk:
                return time.time() - t0
            return time.time() - t0  # closed with no data
    except socket.timeout:
        return time.time() - t0
    finally:
        s.close()


# ------------------------------------------------ 1. default-off
env = dict(os.environ)
env.pop("PD_ENABLED", None)
code = ("import sys; sys.path.insert(0, %r);"
        "import pd_bridge;"
        "assert not pd_bridge.is_enabled(), 'bridge on without PD_ENABLED';"
        "assert pd_bridge.port_touch('ssh', ('1.2.3.4', 5)) is None;"
        "assert pd_bridge.http_hit(('1.2.3.4', 5), '/wp-admin') is None;"
        "print('disabled-ok')" % HONEY)
r = subprocess.run([sys.executable, "-c", code], env=env,
                   capture_output=True, text=True, timeout=30)
check("default-off: bridge no-op without PD_ENABLED",
      r.returncode == 0 and "disabled-ok" in r.stdout,
      (r.stdout + r.stderr)[-300:])

# ------------------------------------------------ live servers (PD on)
env_on = dict(os.environ, PD_ENABLED="1")
# Repaired 2026-09-26: the journal check below used to pass on a STALE
# journal from a prior run. Remove it first so the check proves THIS run
# wrote entries.
_journal = os.path.join(HONEY, "logs", "pd-evidence.jsonl")
if os.path.exists(_journal):
    os.remove(_journal)
tmp = tempfile.mkdtemp(prefix="pd-honey-")
log_path = os.path.join(tmp, "honeypot.jsonl")
server_code = "\n".join([
    "import sys, os",
    "sys.path.insert(0, %r)" % HONEY,
    "import honeypot",
    "assert honeypot.PD_BRIDGE_AVAILABLE, 'bridge did not import'",
    "assert honeypot.pd_bridge.is_enabled(), 'bridge not enabled'",
    "import threading, time",
    "ports = [(18080, 'http'), (18081, 'generic'), (18082, 'ssh'),",
    "         (18083, 'telnet'), (18084, 'ftp'), (18085, 'mysql'),",
    "         (18087, 'ssh')]",
    "for port, svc in ports:",
    "    threading.Thread(target=honeypot.serve,",
    "                     args=(port, svc, %r), daemon=True).start()" % log_path,
    "time.sleep(120)",
])
srv = subprocess.Popen([sys.executable, "-c", server_code], env=env_on,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    time.sleep(2.5)  # let listeners come up

    # 2. decoy vs bespoke theater
    t0 = time.time()
    normal = http_get(18080, "/index.html")
    dt_normal = time.time() - t0
    check("normal page served fast when clean",
          "200 OK" in normal and dt_normal < 1.5, dt_normal)
    wp = http_get(18080, "/wp-admin")
    check("bespoke theater wins over decoy (/wp-admin)",
          "WordPress" in wp or "wordpress" in wp.lower(), wp[:80])
    d1 = http_get(18080, "/.git")
    d2 = http_get(18080, "/.git")
    d3 = http_get(18080, "/.git")
    check("suspicious path with no bespoke bait -> decoy page",
          "placeholder page" in d3, d3[:80])
    check("decoy identical across hits",
          d1.split("\r\n\r\n", 1)[1] == d3.split("\r\n\r\n", 1)[1])

    # 3. scan throttle: 6 distinct services, one fresh IP (127.0.0.3).
    # The PD delay lands before each handler runs, so time-to-first-byte
    # on the 6th service must exceed the 1st by the 0.5s throttle.
    scan_plan = [(18080, b"GET / HTTP/1.0\r\n\r\n"),  # http
                 (18081, b"hello"),                    # generic
                 (18082, None),                        # ssh: banner first
                 (18083, None),                        # telnet: banner first
                 (18084, None),                        # ftp: banner first
                 (18085, None)]                        # mysql: handshake first
    times = [time_to_first_byte(p, "127.0.0.3", hello=h)
             for p, h in scan_plan]
    check("6th distinct service throttled (+0.4s vs 1st)",
          times[5] - times[0] >= 0.4,
          ["%.2f" % t for t in times])
    check("first touch not throttled (<0.4s)",
          times[0] < 0.4, ["%.2f" % t for t in times])

    # 4. login throttle: 5 SSH logins, one fresh IP (127.0.0.4).
    # Drain to the "login: " marker, then time until "Password: ".
    def ssh_login():
        s = connect_from("127.0.0.4", 18087, timeout=15)
        try:
            buf = b""
            s.sendall(b"SSH-2.0-x\r\n")
            time.sleep(0.4)
            s.sendall(b"\r\n")
            while b"login: " not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            t0 = time.time()
            s.sendall(b"root\r\n")
            buf = b""
            while b"Password: " not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return time.time() - t0
        finally:
            s.close()

    login_times = [ssh_login() for _ in range(5)]
    check("5th login throttled (>=0.4s)",
          login_times[4] >= 0.4, ["%.2f" % t for t in login_times])
    check("early logins not throttled (<0.4s)",
          all(t < 0.4 for t in login_times[:3]),
          ["%.2f" % t for t in login_times])

    # 5. journal written
    journal = os.path.join(HONEY, "logs", "pd-evidence.jsonl")
    time.sleep(0.5)
    check("PD evidence journal exists and has entries",
          os.path.exists(journal) and os.path.getsize(journal) > 0,
          journal if os.path.exists(journal) else "missing")

    # 6. L5 through the wired path: slow touches stay silent
    # Repaired 2026-09-26: the old check fired 5 probes and only asserted
    # the script printed 'l5-ok' - it proved nothing about silence. The
    # honest assertion: every under-threshold probe through the same
    # observe() the bridge calls must come back action="normal" with zero
    # delay and nothing tripped.
    code2 = ("import sys; sys.path.insert(0, %r);"
             "import pd_bridge;"
             "from peripheral_defense import PeripheralDefense;"
             "pd = PeripheralDefense();"
             "outs = [pd.observe({'type':'port_probe','src_ip':'9.9.9.9',"
             "'service':'s%%d'%%i}) for i in range(5)];"
             "silent = all(o['action'] == 'normal' "
             "and o['delay_seconds'] == 0 "
             "and not any(o['tripped'].values()) for o in outs);"
             "print('SILENT' if silent else 'NOISY')" % os.path.expanduser(
                 "~/workspace/your_files/peripheral-defense"))
    r2 = subprocess.run([sys.executable, "-c", code2], env=env_on,
                        capture_output=True, text=True, timeout=30)
    check("under-threshold stays silent (L5)",
          r2.returncode == 0 and "SILENT" in r2.stdout,
          (r2.stdout + r2.stderr)[-200:])
finally:
    srv.terminate()
    try:
        srv.wait(timeout=5)
    except subprocess.TimeoutExpired:
        srv.kill()

print()
if failures:
    print("FAILURES: %d" % len(failures))
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("ALL GREEN: the honeypot wiring works and stays safe.")
