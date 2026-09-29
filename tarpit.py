#!/usr/bin/env python3
"""
tarpit.py — multi-protocol tarpit (educational, defensive).

What it does: accepts TCP connections and dribbles out protocol chatter
*extremely* slowly — one short line every --delay seconds, forever (up to
--max-time). Scanners and brute-forcers that connect here get stuck: each
connection ties up one of their sockets for minutes while achieving
nothing.

Modes (--mode):
    ssh   (default port 2222) — endlessh-style: SSH banner, then junk lines.
    http  (default port 8080) — reads the request line, then dribbles a
            plausible-but-never-finishing HTTP response: status line, one
            header per interval, never the blank line that ends headers,
            never the body.
    smtp  (default port 2525) — speaks first (220 banner), reads EHLO/HELO,
            then dribbles "250-..." capability lines, never the final
            "250 " line that would let the client proceed.

This is a tarpit, not a honeypot: it never executes anything sent by the
visitor; inbound bytes are only logged (max 2000 chars), never
interpreted, never echoed.

Run:
    python3 tarpit.py                              # ssh mode on 0.0.0.0:2222
    python3 tarpit.py --mode http                   # http mode on :8080
    python3 tarpit.py --mode smtp --port 2525       # smtp mode on :2525
    python3 tarpit.py --delay 5 --max-time 600      # meaner/faster drip
    python3 tarpit.py --mode http --no-jitter       # metronome drip (demo)

Logs JSON lines to logs/tarpit.jsonl using the same event schema as
honeypot.py, so the SIEM can tail it later.

Default ports (2222/8080/2525) deliberately avoid the honeypot's real
trap ports (22/80/25) so both can run on the same box without a clash.

Adversarial notes (think like the red team):
- Fingerprinting via never-completing banners: every mode is designed to
  *never* finish, so a patient scanner will eventually notice. Mitigation
  is jitter + content variety, not invisibility.
- Fingerprinting via timing: a metronome-regular drip is the classic
  tarpit fingerprint. Every drip interval is multiplied by
  random.uniform(0.7, 1.4), which scrambles inter-arrival timing analysis.
  Different modes also vary their line content (http rotates header
  pools, smtp rotates capability lists, ssh keeps random junk lines).
- Short-timeout evasion: ACCEPTED as out of scope. Any client with a short
  socket timeout defeats the tarpit trivially. Tarpits target
  scanners/brute-forcers with generous timeouts; even a detected tarpit
  costs the attacker analysis time. The threat model is time-theft, not
  invisibility.
- Active probing: garbage sent to fingerprint the service is logged and
  ignored — never echoed, never answered with an error that could leak
  implementation details. In http/smtp modes only the first inbound line
  is logged; the rest is silently drained and discarded.
- Resource exhaustion against US: concurrent connections are bounded by
  --max-conn (default 200); beyond that, connections are closed
  immediately with a "tarpit_shed" log entry. The listen() backlog also
  caps the kernel queue. Each connection is capped by --max-time.
- Honest blind spots: distributed slowloris-style attackers (many slow
  connections from many IPs) still work against any single box; UDP is
  out of scope (TCP only); a scanner that never sends anything and just
  watches will eventually classify the drip as a tarpit — that is the
  cost of never finishing, and we accept it.
"""

import argparse
import datetime
import json
import os
import random
import socket
import string
import threading
import time
import uuid

ALPHABET = string.ascii_letters + string.digits

DEFAULT_PORTS = {"ssh": 2222, "http": 8080, "smtp": 2525}

# Plausible header pool for --mode http. The Content-Length is a deliberate
# lie: we never send the blank line that ends headers, so the body never
# starts. Pools rotate so no two connections look byte-identical.
HTTP_HEADERS = [
    "Server: nginx/1.18.0 (Ubuntu)",
    "Server: Apache/2.4.41 (Ubuntu)",
    "Server: Microsoft-IIS/10.0",
    "Content-Type: text/html; charset=UTF-8",
    "Content-Type: text/html; charset=utf-8",
    "Content-Length: 1048576",
    "Cache-Control: no-cache, no-store",
    "X-Powered-By: PHP/7.4.33",
    "X-Powered-By: Express",
    "X-Request-Id: {rid}",
    "X-Cache: MISS",
    "X-Frame-Options: SAMEORIGIN",
    "Connection: keep-alive",
    "Keep-Alive: timeout=5, max=100",
    "Vary: Accept-Encoding",
    "Accept-Ranges: bytes",
]

# Capability lines for --mode smtp. Every line uses the "250-" continuation
# form; the final "250 " line (note the SPACE, which ends the EHLO block
# and lets the client proceed) is NEVER sent, so the client waits forever.
SMTP_CAPS = [
    "250-mx01.example.net ESMTP Postfix",
    "250-PIPELINING",
    "250-SIZE 26214400",
    "250-ETRN",
    "250-STARTTLS",
    "250-ENHANCEDSTATUSCODES",
    "250-8BITMIME",
    "250-DSN",
]


def now():
    # UTC, timezone-aware — matches honeypot.py.
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def log_event(log_path, sid, addr, data):
    entry = {
        "time": now(),
        "service": "tarpit",
        "session": sid,
        "src_ip": addr[0],
        "src_port": addr[1],
        "data": data[:2000],
    }
    line = json.dumps(entry)
    print(line, flush=True)
    with open(log_path, "a") as f:
        f.write(line + "\n")


def wait_secs(args):
    if args.no_jitter:
        return args.delay
    # Jitter frustrates timing analysis: a metronome-regular drip is the
    # classic tarpit fingerprint, so we randomize each interval. With
    # --no-jitter the drip is exactly periodic (useful for demos).
    return args.delay * random.uniform(0.7, 1.4)


def random_line():
    # Looks like banner chatter; never a real version string after the first.
    n = random.randint(24, 64)
    return "#" + "".join(random.choice(ALPHABET) for _ in range(n)) + "\r\n"


def _read_line(conn, timeout, max_bytes=2048):
    """Read up to one newline (or timeout). Returns raw bytes, possibly
    empty. Used for the HTTP request line and SMTP EHLO/HELO. Anything the
    visitor sends is only ever logged — never executed, never echoed."""
    conn.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < max_bytes:
            chunk = conn.recv(1024)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    return buf


def _drip_lines(conn, lines, args, deadline, on_inbound=None):
    """Drip lines out of a TCP connection, one per jittered --delay.

    lines: iterable of str/bytes. Stops on disconnect, send failure,
    exhausted iterable, or the deadline. Inbound bytes are drained and
    optionally passed to on_inbound(chunk) — never echoed back.
    Returns the number of lines actually sent.
    """
    sent = 0
    it = iter(lines)
    while time.time() < deadline:
        conn.settimeout(wait_secs(args))
        try:
            chunk = conn.recv(1024)
            if not chunk:
                return sent  # orderly disconnect
            if on_inbound:
                on_inbound(chunk)
        except socket.timeout:
            pass  # silence is fine — drip anyway
        except (ConnectionResetError, BrokenPipeError):
            return sent
        try:
            line = next(it)
        except StopIteration:
            return sent
        if isinstance(line, str):
            line = line.encode("utf-8", errors="replace")
        try:
            conn.sendall(line)
            sent += 1
        except (ConnectionResetError, BrokenPipeError):
            return sent
    return sent


def _infinite_ssh_lines():
    while True:
        yield random_line()


def _infinite_http_lines():
    """Status line, then plausible headers forever — never the blank line
    that ends headers, never the body. Header pools rotate so connections
    don't look byte-identical (fingerprinting mitigation)."""
    yield "HTTP/1.1 200 OK\r\n"
    while True:
        for h in random.sample(HTTP_HEADERS, 4):
            if "{rid}" in h:
                h = h.replace("{rid}", uuid.uuid4().hex[:16])
            yield h + "\r\n"


def _infinite_smtp_lines():
    """Capability lines forever — every one uses the 250- continuation
    form; the final "250 " line is never sent, so the client hangs."""
    for c in SMTP_CAPS:
        yield c + "\r\n"
    n = 0
    while True:
        n += 1
        yield f"250-XGREYLIST-{n:03d}\r\n"


def handle(conn, addr, args, sid):
    """SSH mode — original behavior, unchanged apart from jitter on the
    drip interval."""
    start = time.time()
    deadline = start + args.max_time
    lines_sent = 0
    client_banner = ""

    def on_inbound(chunk):
        nonlocal client_banner
        # Scanners usually announce their version string first.
        text = chunk.decode("utf-8", errors="replace").strip()
        if text and not client_banner:
            client_banner = text[:120]
            log_event(args.log, sid, addr, f"client_banner: {client_banner}")

    log_event(args.log, sid, addr,
              "tarpit_open [ssh]: connection accepted, drip starting")
    try:
        # Real SSH servers speak first — so do we.
        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        lines_sent += 1
        lines_sent += _drip_lines(conn, _infinite_ssh_lines(), args,
                                  deadline, on_inbound=on_inbound)
    finally:
        duration = round(time.time() - start, 1)
        try:
            conn.close()
        except OSError:
            pass
        log_event(args.log, sid, addr,
                  f"tarpit_close [ssh]: held {duration}s, sent {lines_sent} lines"
                  + (f", banner={client_banner!r}" if client_banner else ""))


def handle_http(conn, addr, args, sid):
    """HTTP mode — read the request line, then dribble a never-finishing
    response: status line, one header per interval, no end-of-headers blank
    line, no body."""
    start = time.time()
    deadline = start + args.max_time
    lines_sent = 0
    request_line = ""
    log_event(args.log, sid, addr,
              "tarpit_open [http]: connection accepted, drip starting")
    try:
        raw = _read_line(conn, wait_secs(args))
        if raw:
            request_line = raw.decode("utf-8", errors="replace").split("\n")[0].strip()
            log_event(args.log, sid, addr,
                      f"http_request: {request_line[:120]}")
        else:
            log_event(args.log, sid, addr, "http_request: (none — silent)")
        # Subsequent inbound bytes (rest of the headers, junk probes) are
        # drained and discarded inside _drip_lines — never interpreted.
        lines_sent += _drip_lines(conn, _infinite_http_lines(), args, deadline)
    finally:
        duration = round(time.time() - start, 1)
        try:
            conn.close()
        except OSError:
            pass
        log_event(args.log, sid, addr,
                  f"tarpit_close [http]: held {duration}s, sent {lines_sent} lines"
                  + (f", request={request_line[:80]!r}" if request_line else ""))


def handle_smtp(conn, addr, args, sid):
    """SMTP mode — speak first like a real server (220), read EHLO/HELO,
    then dribble 250- capability lines forever, never the final 250 line."""
    start = time.time()
    deadline = start + args.max_time
    lines_sent = 0
    ehlo = ""
    log_event(args.log, sid, addr,
              "tarpit_open [smtp]: connection accepted, drip starting")
    try:
        # Real SMTP servers speak first — so do we.
        conn.sendall(b"220 mx01.example.net ESMTP Postfix\r\n")
        lines_sent += 1
        raw = _read_line(conn, wait_secs(args))
        if raw:
            ehlo = raw.decode("utf-8", errors="replace").split("\n")[0].strip()
            log_event(args.log, sid, addr, f"smtp_ehlo: {ehlo[:120]}")
        else:
            log_event(args.log, sid, addr, "smtp_ehlo: (none — silent)")
        # Further inbound (MAIL FROM attempts, junk probes) is drained and
        # discarded — never answered, never acted on.
        lines_sent += _drip_lines(conn, _infinite_smtp_lines(), args, deadline)
    finally:
        duration = round(time.time() - start, 1)
        try:
            conn.close()
        except OSError:
            pass
        log_event(args.log, sid, addr,
                  f"tarpit_close [smtp]: held {duration}s, sent {lines_sent} lines"
                  + (f", ehlo={ehlo[:60]!r}" if ehlo else ""))


HANDLERS = {"ssh": handle, "http": handle_http, "smtp": handle_smtp}


def main():
    ap = argparse.ArgumentParser(
        description="Educational multi-protocol tarpit: dribbles protocol "
                    "chatter impossibly slowly to waste scanners' time.")
    ap.add_argument("--mode", choices=["ssh", "http", "smtp"], default="ssh",
                    help="tarpit flavor (default: %(default)s)")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=None,
                    help="listening port; default depends on --mode "
                         "(ssh 2222 / http 8080 / smtp 2525)")
    ap.add_argument("--delay", type=float, default=10,
                    help="base seconds between drip lines; each interval is "
                         "jittered x uniform(0.7, 1.4) unless --no-jitter "
                         "(default: %(default)s)")
    ap.add_argument("--max-time", type=float, default=1800,
                    help="max seconds to hold one connection (default: %(default)s)")
    ap.add_argument("--max-conn", type=int, default=200,
                    help="max concurrent connections; extras are closed "
                         "immediately with a tarpit_shed log entry "
                         "(default: %(default)s)")
    ap.add_argument("--no-jitter", action="store_true",
                    help="drip on an exact metronome (demo/testing only; "
                         "regular timing is a tarpit fingerprint)")
    ap.add_argument("--log", default="logs/tarpit.jsonl")
    args = ap.parse_args()

    if args.port is None:
        args.port = DEFAULT_PORTS[args.mode]
    handler = HANDLERS[args.mode]

    os.makedirs(os.path.dirname(args.log) or ".", exist_ok=True)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(100)

    # Bound concurrent threads: shed load instead of melting the box.
    active = 0
    active_lock = threading.Lock()

    def run_handler(conn, addr, sid):
        nonlocal active
        try:
            handler(conn, addr, args, sid)
        finally:
            with active_lock:
                active -= 1

    print(f"[*] tarpit listening on {args.bind}:{args.port} mode={args.mode} "
          f"(drip every ~{args.delay}s{' jittered' if not args.no_jitter else ' (no jitter)'}, "
          f"max hold {args.max_time}s, max {args.max_conn} conns)", flush=True)
    print(f"[*] logging to {args.log}", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            sid = uuid.uuid4().hex[:8]
            with active_lock:
                if active >= args.max_conn:
                    # Shedding: close at once, log it, cost the scanner nothing
                    # more than a dial — better than us falling over.
                    try:
                        conn.close()
                    except OSError:
                        pass
                    log_event(args.log, sid, addr,
                              f"tarpit_shed: at capacity ({args.max_conn}), "
                              "connection refused")
                    continue
                active += 1
            threading.Thread(target=run_handler, args=(conn, addr, sid),
                             daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] tarpit shutting down", flush=True)


if __name__ == "__main__":
    main()
