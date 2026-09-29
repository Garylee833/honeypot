#!/usr/bin/env python3
"""aliveness.py — background-noise generator ("fake aliveness") for the
educational honeypot. Stdlib only.

WHY THIS EXISTS
---------------
A honeypot that logs nothing for hours looks dead to anyone studying it —
including your own SIEM demos and dashboard screenshots. aliveness.py emits
synthetic background-noise events (fake user logins, cron completions,
routine HTTP hits, an FTP login attempt, a nightly backup notice) so the
"server" looks alive when no attacker is present.

SCHEDULE / TUNING
-----------------
Run it as a separate process next to honeypot.py, pointed at the SAME log
file (it uses chainlog.append_event, so the hash chain stays intact across
processes thanks to flock):

    python3 aliveness.py --log logs/events.jsonl &

Tunable knobs:
    --interval 60      mean seconds between synthetic events (default 45)
    --jitter 0.5       each gap is interval * uniform(1-jitter, 1+jitter);
                       0.5 keeps the cadence human-irregular, 0 is metronomic
    --once / --count N emit one / N events and exit (good for testing)
    --seed 42          reproducible noise for demos and tests

EVENT TYPES (weighted)
----------------------
service   weight   what it looks like (data field)
"ssh"     20       sshd accepted-publickey / accepted-password for a fake
                   service or admin account, from a private 192.168.1.x host
"ssh"     12       session closed / disconnected for one of those accounts
"cron"    24       cron[PID]: (user) CMD (/path/to/job) -> completed in
                   0.42s, exit 0  — logrotate-check, apt-daily, certbot
"http"    20       internal health check: GET /status or /healthz 200, a few
                   hundred bytes, a few ms, plain-English user agent
"ftp"     10       routine backup-account FTP login attempt (usually fails
                   once, then succeeds — the classic flaky cron job)
"system"  4        nightly backup notice: "nightly backup completed: 14.2 GB
                   to /mnt/backup-<date>, 0 errors" (only emitted 01:00-05:00
                   UTC; otherwise re-rolled as a cron event)

HONEST DESIGN NOTES
-------------------
- EVERY event carries "synthetic": True. The mini-SIEM skips synthetic
  events, and defense in depth applies anyway: the data strings are kept
  clean of exploit-signature substrings (no ${jndi:, ../.., ;cat /etc/,
  $(, backticks, union select, ' or '1'='1, etc.). If you add a template,
  grep it against FORBIDDEN_SUBSTRINGS in --self-test before shipping.
- src_ip is always private-range (192.168.1.x) and src_port a random high
  port — clearly internal traffic, clearly not the attacker's.
- fake_users_now() gives the fake shell's `who` command a stable roster:
  deterministic per 30-minute time slot (RNG seeded by slot), 0-2 users,
  so the roster doesn't flicker within a demo but does rotate over time.
- fake_last_entries(n) renders the same fake users in classic `last`
  output format for the fake shell's `last` command.

BLIND SPOTS (read this)
-----------------------
- Approximate theater only: the event stream, the who-roster, and the
  last-log are only LOOSELY consistent with each other. An SSH login
  event at 02:14 does not guarantee that user appears in the who-roster
  at 02:15, and logouts don't reliably clear users. A careful attacker
  correlating events.jsonl against `who` output could spot the seams —
  but this is a training prop, not a lie told to a skilled adversary.
- The backup notice is time-gated to 01:00-05:00 UTC; run the generator
  with a short interval at other hours and you'll mostly see cron noise.
- Like all chained writers, aliveness.py appends under flock; on a
  non-POSIX box without fcntl the chain is cross-process unsafe (see
  chainlog.py).
"""

import argparse
import datetime
import json
import os
import random
import subprocess
import sys
import tempfile
import time

# Import the sibling module chainlog.py with the same pattern verify_chain.py uses.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chainlog  # noqa: E402  (local module, same directory)

# ---------------------------------------------------------------------------
# Clean-data policy: synthetic data strings must never contain any of these,
# case-insensitively. Defense in depth on top of "SIEM skips synthetic".
# ---------------------------------------------------------------------------
FORBIDDEN_SUBSTRINGS = [
    "${jndi:",
    "..;/",
    "%2e%2e",
    "../..",
    ";cat /etc/",
    "|/bin/id",
    "$(",
    "`id`",
    "union select",
    "' or '1'='1",
]

FAKE_USERS = ["ops", "deploy", "backup", "monitoring", "ansible", "admin"]
INTERNAL_HOSTS = ["192.168.1.%d" % i for i in range(10, 61)]  # .10-.60
CRON_JOBS = [
    ("/usr/local/bin/logrotate-check", "root"),
    ("/usr/bin/apt-daily", "root"),
    ("/usr/bin/certbot renew --quiet", "root"),
    ("/opt/monitor/disk-check.sh", "monitoring"),
    ("/opt/monitor/health-report.sh", "monitoring"),
    ("/home/deploy/.local/bin/prune-tmp.sh", "deploy"),
]
HTTP_PATHS = ["/status", "/healthz", "/metrics", "/index.html", "/robots.txt"]
HTTP_AGENTS = ["health-check/1.2", "uptime-monitor", "curl/8.5.0",
               "internal-dashboard", "prometheus-scrape"]


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _internal_src():
    """Private-range source address with a random high source port."""
    return random.choice(INTERNAL_HOSTS), random.randint(40000, 60000)


def _session_id():
    return "%08x" % random.getrandbits(32)


def _make_event(service, data, src_ip=None, src_port=None, session=None):
    src_ip = src_ip if src_ip is not None else _internal_src()[0]
    if src_port is None:
        src_port = random.randint(40000, 60000)
    return {
        "time": now_utc(),
        "service": service,
        "session": session or _session_id(),
        "src_ip": src_ip,
        "src_port": src_port,
        "data": data[:2000],
        "synthetic": True,          # EVERY synthetic event carries this.
    }


# ---------------------------------------------------------------------------
# Event templates: (service, weight, builder)
# ---------------------------------------------------------------------------
def _ev_ssh_login():
    user = random.choice(FAKE_USERS)
    ip, port = _internal_src()
    method = random.choice(["accepted-password", "accepted-publickey"])
    return _make_event(
        "ssh",
        "sshd[%d]: %s for %s from %s port %d ssh2" % (
            random.randint(900, 4200), method, user, ip, port),
        src_ip=ip, src_port=port)


def _ev_ssh_logout():
    user = random.choice(FAKE_USERS)
    ip, port = _internal_src()
    reason = random.choice([
        "session closed for user %s" % user,
        "Disconnected from user %s %s port %d" % (user, ip, port),
        "pam_unix(sshd:session): session closed for user %s" % user,
    ])
    return _make_event("ssh", "sshd[%d]: %s" % (random.randint(900, 4200), reason),
                       src_ip=ip, src_port=port)


def _ev_cron():
    job, user = random.choice(CRON_JOBS)
    pid = random.randint(800, 9000)
    dur = round(random.uniform(0.05, 3.4), 2)
    return _make_event(
        "cron",
        "cron[%d]: (%s) CMD (%s) -> completed in %.2fs, exit 0" % (pid, user, job, dur))


def _ev_http():
    ip, port = _internal_src()
    path = random.choice(HTTP_PATHS)
    code = random.choices([200, 200, 200, 200, 301, 404], k=1)[0]
    size = random.randint(180, 2400)
    dur = round(random.uniform(0.002, 0.09), 3)
    return _make_event(
        "http",
        'GET %s -> %d, %dB, %.3fs, agent "%s"' % (
            path, code, size, dur, random.choice(HTTP_AGENTS)),
        src_ip=ip, src_port=port)


def _ev_ftp():
    ip, port = _internal_src()
    user = random.choice(["backup", "deploy", "ftp-sync"])
    outcome = random.choices(
        ["login ok for %s (passive mode)" % user,
         "login failed for %s: bad password (attempt 1/3)" % user,
         "login ok for %s after retry" % user],
        weights=[6, 2, 2], k=1)[0]
    return _make_event("ftp", "vsftpd: " + outcome, src_ip=ip, src_port=port)


def _ev_backup():
    # Nightly backup notice. Only meaningful 01:00-05:00 UTC; outside that
    # window the scheduler re-rolls it into a cron event.
    hour = datetime.datetime.now(datetime.timezone.utc).hour
    if not (1 <= hour < 5):
        return _ev_cron()
    size = round(random.uniform(8.0, 22.5), 1)
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    dur = random.randint(240, 1400)
    return _make_event(
        "system",
        "nightly backup completed: %.1f GB to /mnt/backup-%s, 0 errors, %ds" % (
            size, today, dur))


EVENT_TYPES = [
    (_ev_ssh_login, 20),
    (_ev_ssh_logout, 12),
    (_ev_cron, 24),
    (_ev_http, 20),
    (_ev_ftp, 10),
    (_ev_backup, 4),
]


def generate_event():
    """Build one weighted random synthetic event dict (not yet logged)."""
    builders, weights = zip(*EVENT_TYPES)
    return random.choices(builders, weights=weights, k=1)[0]()


def emit_event(log_path):
    """Generate one event and chain it onto the log. Returns the entry."""
    entry = generate_event()
    return chainlog.append_event(log_path, entry)


# ---------------------------------------------------------------------------
# Fake roster for the fake shell's `who` command.
# Deterministic per 30-minute slot: stable within a slot, rotates over time.
# ---------------------------------------------------------------------------
_ROSTER_SALT = "aliveness-roster-v1"


def fake_users_for_slot(slot, now=None):
    """Roster for a given 30-minute time slot. Internal; slot = epoch//1800."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    rng = random.Random("%s:%d" % (_ROSTER_SALT, slot))
    users = []
    for i in range(rng.randint(0, 2)):
        user = rng.choice(FAKE_USERS)
        if any(u["user"] == user for u in users):
            continue
        login = now - datetime.timedelta(minutes=rng.randint(5, 170))
        idle_choice = rng.random()
        idle = ("0.00s" if idle_choice < 0.6
                else "%.2fs" % rng.uniform(1, 30)
                if idle_choice < 0.9
                else "%d:%02d" % (rng.randint(1, 40), rng.randint(0, 59)))
        users.append({
            "user": user,
            "tty": "pts/%d" % i,
            "login": login.strftime("%Y-%m-%d %H:%M"),
            "idle": idle,
            "from": rng.choice(INTERNAL_HOSTS),
        })
    return users


def fake_users_now():
    """Roster for the CURRENT 30-minute slot. For the fake shell's `who`."""
    now = datetime.datetime.now(datetime.timezone.utc)
    slot = int(now.timestamp() // 1800)
    return fake_users_for_slot(slot, now)


# ---------------------------------------------------------------------------
# fake_last_entries(n): classic `last` output format lines.
# ---------------------------------------------------------------------------
_WDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _last_stamp(dt):
    # classic `last` style: "Thu Sep 17 21:52"
    return "%s %s %2d %02d:%02d" % (
        _WDAYS[dt.weekday()], _MONTHS[dt.month - 1], dt.day,
        dt.hour, dt.minute)


def fake_last_entries(n=8):
    """n lines in classic `last` output format, using the fake user names."""
    now = datetime.datetime.now(datetime.timezone.utc)
    rng = random.Random("%s:last:%d" % (_ROSTER_SALT, int(now.timestamp() // 86400)))
    lines = []
    cursor = now
    for _ in range(n):
        user = rng.choice(FAKE_USERS)
        tty = "pts/%d" % rng.randint(0, 3)
        host = rng.choice(INTERNAL_HOSTS)
        login = cursor - datetime.timedelta(minutes=rng.randint(20, 400))
        if rng.random() < 0.35:
            # still logged in
            line = "%-8s %-8s %-16s %s   still logged in" % (
                user, tty, host, _last_stamp(login))
        else:
            logout = login + datetime.timedelta(minutes=rng.randint(10, 300))
            if logout > now:
                logout = now
            delta = logout - login
            hrs, rem = divmod(int(delta.total_seconds()), 3600)
            mins = rem // 60
            line = "%-8s %-8s %-16s %s - %s  (%02d:%02d)" % (
                user, tty, host, _last_stamp(login),
                _last_stamp(logout).split(" ", 2)[2], hrs, mins)
        lines.append(line)
        cursor = login
    return lines


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def _data_is_clean(data):
    lowered = data.lower()
    return [s for s in FORBIDDEN_SUBSTRINGS if s.lower() in lowered]


def self_test():
    """Run the full self-test. Returns (ok, report_lines)."""
    report = []
    ok = True

    # (a) 200 events ALL carry synthetic:true
    random.seed()  # unseeded — real variety
    events = [generate_event() for _ in range(200)]
    bad = [i for i, e in enumerate(events) if e.get("synthetic") is not True]
    if bad:
        ok = False
        report.append("FAIL (a): %d/200 events missing synthetic:true: %s"
                      % (len(bad), bad[:5]))
    else:
        report.append("PASS (a): 200/200 generated events carry synthetic:true")

    # also require every generated event to carry the full schema
    schema_keys = {"time", "service", "session", "src_ip", "src_port", "data",
                   "synthetic"}
    bad_schema = [i for i, e in enumerate(events)
                  if not schema_keys.issubset(e.keys())]
    if bad_schema:
        ok = False
        report.append("FAIL (a2): %d/200 events missing schema keys: %s"
                      % (len(bad_schema), bad_schema[:5]))
    else:
        report.append("PASS (a2): 200/200 events carry the full event schema")

    # (b) no exploit substrings in any data string
    dirty = [(i, hits) for i, e in enumerate(events)
             if (hits := _data_is_clean(e["data"]))]
    if dirty:
        ok = False
        report.append("FAIL (b): %d/200 events contain forbidden substrings:"
                      % len(dirty))
        for i, hits in dirty[:5]:
            report.append("    event %d: %s" % (i, hits))
    else:
        report.append("PASS (b): 0/200 events contain any forbidden substring")

    # private-range src_ip + high src_port sanity on the same 200
    weird = [i for i, e in enumerate(events)
             if not (e["src_ip"].startswith("192.168.1.")
                     and isinstance(e["src_port"], int)
                     and 40000 <= e["src_port"] <= 60000)]
    if weird:
        ok = False
        report.append("FAIL (b2): %d/200 events with non-internal src: %s"
                      % (len(weird), weird[:5]))
    else:
        report.append("PASS (b2): 200/200 events use 192.168.1.x + high src_port")

    # (c) roster stable within one slot, changes across slots
    now = datetime.datetime.now(datetime.timezone.utc)
    slot = int(now.timestamp() // 1800)
    r1 = fake_users_for_slot(slot, now)
    r2 = fake_users_for_slot(slot, now)
    if r1 != r2:
        ok = False
        report.append("FAIL (c): roster NOT stable within one slot")
    else:
        report.append("PASS (c): roster stable within one slot (%d user(s))"
                      % len(r1))
    variants = {json.dumps(fake_users_for_slot(s, now), sort_keys=True)
                for s in range(slot - 40, slot)}
    if len(variants) < 2:
        ok = False
        report.append("FAIL (c2): roster identical across 40 slots")
    else:
        report.append("PASS (c2): roster varies across slots (%d distinct in last 40)"
                      % len(variants))

    # fake_last_entries smoke test: count + names + classic-last shape
    last = fake_last_entries(8)
    bad_last = [l for l in last if l.split()[0] not in FAKE_USERS]
    shape_ok = all(len(l.split()) >= 7 for l in last)
    if bad_last or len(last) != 8 or not shape_ok:
        ok = False
        report.append("FAIL (c3): fake_last_entries format problem")
    else:
        report.append("PASS (c3): fake_last_entries(8) -> 8 lines, "
                      "fake user names, classic last format")

    # (d) 20 events chain-verify clean through chainlog on a temp file
    tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
    tmp_path = tmp.name
    tmp.close()
    try:
        try:
            for _ in range(20):
                chainlog.append_event(tmp_path, generate_event())
        except Exception as exc:  # e.g. a broken chainlog must not kill the runner
            ok = False
            report.append("FAIL (d): chainlog.append_event raised %s: %s"
                          % (type(exc).__name__, exc))
        else:
            verifier = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "verify_chain.py")
            proc = subprocess.run([sys.executable, verifier, tmp_path],
                                  capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                ok = False
                report.append("FAIL (d): verify_chain.py exited %d"
                              % proc.returncode)
                report.append("    " + proc.stdout.strip().replace("\n", " | "))
            else:
                report.append("PASS (d): 20 events chain-verify clean "
                              "(verify_chain.py exit 0)")
                report.append("    " + proc.stdout.strip().splitlines()[0])
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    return ok, report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Fake-aliveness background-noise generator for the "
                    "educational honeypot. Emits synthetic events to the "
                    "shared chained event log.")
    ap.add_argument("--log", default=os.path.join("logs", "events.jsonl"),
                    help="event log path (default logs/events.jsonl, "
                         "relative to CWD)")
    ap.add_argument("--interval", type=float, default=45,
                    help="mean seconds between events (default 45)")
    ap.add_argument("--jitter", type=float, default=0.5,
                    help="gap = interval * uniform(1-jitter, 1+jitter) "
                         "(default 0.5)")
    ap.add_argument("--once", action="store_true",
                    help="emit one event and exit")
    ap.add_argument("--count", type=int, default=None, metavar="N",
                    help="emit N events and exit")
    ap.add_argument("--seed", type=int, default=None,
                    help="seed RNG for reproducible noise")
    ap.add_argument("--self-test", action="store_true",
                    help="run the built-in self-test and exit")
    args = ap.parse_args(argv)

    if args.self_test:
        ok, report = self_test()
        print("\n".join(report))
        print("SELF-TEST:", "PASS" if ok else "FAIL")
        return 0 if ok else 1

    if args.seed is not None:
        random.seed(args.seed)

    log_dir = os.path.dirname(os.path.abspath(args.log))
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    def _sleep_gap():
        jitter = max(0.0, min(1.0, args.jitter))
        gap = args.interval * random.uniform(1 - jitter, 1 + jitter)
        return max(0.0, gap)

    if args.once:
        entry = emit_event(args.log)
        print(json.dumps(entry), flush=True)
        return 0

    remaining = args.count
    try:
        while True:
            entry = emit_event(args.log)
            print(json.dumps(entry), flush=True)
            if remaining is not None:
                remaining -= 1
                if remaining <= 0:
                    break
            time.sleep(_sleep_gap())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
