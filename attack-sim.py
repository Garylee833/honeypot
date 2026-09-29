#!/usr/bin/env python3
"""attack-sim.py — synthetic attacker traffic generator for YOUR OWN honeypot.

DRILL TOOL. This generates fake attack traffic against a honeypot you own,
so you can study what the catch looks like and build detections against it.
Target is loopback-only by default; private ranges need --allow-private;
public targets are always refused.

Scenarios:
  scan   — connect to every trap port, grab banner, disconnect
  spray  — N login attempts with common passwords on ssh + telnet
  slow   — one quiet probe every --interval seconds, --count times
  web    — suspicious GET paths against the fake http service

Usage:
  python3 attack-sim.py scan
  python3 attack-sim.py spray --attempts 8
  python3 attack-sim.py slow --count 5 --interval 4
  python3 attack-sim.py web
"""

import argparse
import ipaddress
import socket
import sys
import time

# The trap ports our own honeypot listens on.
TRAP_PORTS = {
    22: "ssh", 23: "telnet", 80: "http", 21: "ftp", 3306: "mysql",
    1433: "mssql", 6379: "redis", 5900: "vnc", 25: "smtp",
    9200: "elasticsearch", 2375: "docker", 5432: "postgres",
    27017: "mongodb", 3389: "rdp",
}

SPRAY_PASSWORDS = [
    "admin", "password", "123456", "root", "hunter2",
    "qwerty", "letmein", "admin123",
]

WEB_PATHS = [
    "/admin", "/wp-login.php", "/.env", "/phpmyadmin/",
    "/actuator/env", "/cgi-bin/test.cgi",
]

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1\r\n"


def check_target(target, allow_private):
    """Refuse anything that is not ours to probe."""
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        print("attack-sim: target must be an IP address, got %r" % target)
        sys.exit(2)
    if ip.is_loopback:
        return
    if ip.is_private and allow_private:
        return
    print("attack-sim: refused — target %s is not loopback%s" %
          (target, " (use --allow-private for RFC1918 lab nets)" if ip.is_private else ""))
    sys.exit(2)


def probe(target, port, send=b"", read_bytes=256, timeout=3):
    """One TCP connection: optionally send, grab banner, close."""
    try:
        s = socket.create_connection((target, port), timeout=timeout)
    except OSError as e:
        return "closed: %s" % e
    try:
        s.settimeout(timeout)
        if send:
            try:
                s.sendall(send)
            except OSError:
                pass
        try:
            data = s.recv(read_bytes)
        except socket.timeout:
            data = b""
        return "open banner=%r" % data[:80]
    finally:
        s.close()


def do_scan(target):
    print("attack-sim: scanning %d trap ports on %s" % (len(TRAP_PORTS), target))
    for port in sorted(TRAP_PORTS):
        send = SSH_BANNER if TRAP_PORTS[port] == "ssh" else b""
        print("  %5d/%-13s %s" % (port, TRAP_PORTS[port], probe(target, port, send=send)))


def do_spray(target, attempts):
    print("attack-sim: password spray on ssh(22)+telnet(23), %d attempts" % attempts)
    pwds = (SPRAY_PASSWORDS * ((attempts // len(SPRAY_PASSWORDS)) + 1))[:attempts]
    for i, pwd in enumerate(pwds, 1):
        port = 22 if i % 2 else 23
        send = SSH_BANNER + ("password=%s\r\n" % pwd).encode()
        print("  try %2d -> port %d user=admin pass=%s : %s"
              % (i, port, pwd, probe(target, port, send=send)))
        time.sleep(0.3)


def do_slow(target, count, interval):
    print("attack-sim: slow probe, %d x every %ss" % (count, interval))
    for i in range(1, count + 1):
        print("  probe %d/%d : %s" % (i, count, probe(target, 22, send=SSH_BANNER)))
        if i < count:
            time.sleep(interval)


def do_web(target):
    print("attack-sim: web probing on port 80")
    for path in WEB_PATHS:
        req = ("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n" % (path, target)).encode()
        print("  %-18s %s" % (path, probe(target, 80, send=req)))
        time.sleep(0.3)


def main():
    ap = argparse.ArgumentParser(description="Synthetic attack traffic for your own honeypot (drill tool).")
    ap.add_argument("scenario", choices=["scan", "spray", "slow", "web"],
                    help="which attacker behavior to simulate")
    ap.add_argument("--target", default="127.0.0.1", help="honeypot IP (loopback default)")
    ap.add_argument("--allow-private", action="store_true",
                    help="permit RFC1918 lab targets")
    ap.add_argument("--attempts", type=int, default=8, help="spray attempts")
    ap.add_argument("--count", type=int, default=5, help="slow-probe rounds")
    ap.add_argument("--interval", type=float, default=4, help="slow-probe seconds between probes")
    args = ap.parse_args()

    check_target(args.target, args.allow_private)
    print("attack-sim: DRILL — synthetic traffic against %s (own honeypot)" % args.target)
    if args.scenario == "scan":
        do_scan(args.target)
    elif args.scenario == "spray":
        do_spray(args.target, args.attempts)
    elif args.scenario == "slow":
        do_slow(args.target, args.count, args.interval)
    elif args.scenario == "web":
        do_web(args.target)
    print("attack-sim: done — check the honeypot catch to study the shape")


if __name__ == "__main__":
    main()
