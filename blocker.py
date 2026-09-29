#!/usr/bin/env python3
"""auto-blocker — graduated-response countermeasure daemon for the mini-SIEM.

Reads alerts from siem.py's alerts.jsonl and answers attacker IPs with an
escalation ladder instead of hair-trigger blocks:

  strike 1 -> WATCH     log only, no firewall touch. Strike recorded in state.
  strike 2 -> ESCALATE  prominent log + persisted flag. Still no firewall.
  strike 3 -> BLOCK     base duration, firewall DROP (--enforce only).
  strike 4 -> BLOCK     2x base duration.
  strike 5+ -> BLOCK    4x base duration (capped at 24h).

Ladder philosophy: a single alert is a knock, not a breach. One alert can be
a misfire, a spoofed source, or a one-off probe — blocking on it costs the
defender (firewall churn, self-DoS via forged alerts) more than it costs the
attacker. WATCH and ESCALATE exist to give the analyst and the SIEM time:
they build a log trail the dashboard and incident review can read, and they
cost nothing in firewall state. But persistence is malice: three strikes —
with the SIEM's ~10-minute per-(rule,ip) alert cooldown that is 20+ minutes
of sustained attack — means the door gets slammed, and the longer the
attacker keeps coming back, the longer the door stays shut. The ladder
deliberately trades a slow first response for a punishing response to
persistence.

DRY-RUN BY DEFAULT: it only logs what it would do. Pass --enforce (as root)
to actually run iptables. In --enforce mode WATCH and ESCALATE still only
log — only BLOCK ever touches the firewall. Escalation is about attention,
not packets.

Safeguards:
  * Never blocks loopback, the host's own addresses, or ALLOWLIST entries.
  * Blocks expire automatically and are lifted on schedule; WATCH/ESCALATE
    strike records decay after STRIKE_TTL of attacker silence.
  * Every decision is appended to blocker.log.
  * IPs are validated with the ipaddress module before any firewall call,
    and iptables is invoked with an argument list (no shell).
  * The swarm tripwire (see below) only ever LOGS — aggregate conditions
    never auto-block, because auto-blocking on aggregates is a self-DoS
    footgun when source IPs can be spoofed.

Swarm tripwire (the ladder's honest blind spot):
  The ladder is per-IP-per-rule, so N IPs with 1-2 strikes each never reach
  BLOCK. That is a real blind spot: botnets, spoofed sources, and slow
  distributed scans live in it by design. As a tripwire only: if >=
  SWARM_IPS distinct IPs reach WATCH+ for the SAME rule within SWARM_WINDOW,
  the blocker logs "SWARM suspected distributed <rule> from N ips (log only,
  no auto-block)". Log only. Never auto-block. The analyst decides; the
  machine does not hand an attacker a DoS button aimed at our own firewall.

Related blind spots, stated plainly:
  * Strike-count gaming: an attacker who holds at exactly 2 strikes per
    IP per rule is the ladder's designed equilibrium — they stay in
    ESCALATE forever. That is accepted on purpose: WATCH/ESCALATE's value
    is the analyst's log trail, not the block. The dashboard sees them;
    the firewall does not have to.
  * Alert spoofing: blocker.py trusts whatever is in alerts.jsonl. That
    file MUST be writable only by the SIEM user (chmod 600, owned by the
    SIEM's uid) — forged alerts could farm blocks against innocent IPs,
    which is especially dangerous in --enforce mode.
  * Timescale: the SIEM's ~10-minute per-(rule,ip) alert cooldown means
    strikes arrive at most every ~10 minutes per rule, so reaching BLOCK
    takes 20+ minutes of sustained malice. That is the point, not a bug.

Usage:
  python3 blocker.py                        # dry run — watch only
  sudo python3 blocker.py --enforce         # live blocking
  sudo python3 blocker.py --unblock-all     # lift every active block now
  python3 blocker.py --alerts-file /tmp/f.jsonl --log-file /tmp/b.log --state-file /tmp/s.json

Typical stack on one machine:
  sudo python3 honeypot.py &   # the bait
  python3 siem.py &            # the eyes
  sudo python3 blocker.py --enforce &   # the teeth (with a graduated jaw)
"""
import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

ALERTS_FILE = "alerts.jsonl"
LOG_FILE = "blocker.log"
STATE_FILE = "blocker-state.json"

# rule -> base block duration in minutes. strike 3 = base, strike 4 = 2x,
# strike 5+ = 4x (capped at 24h). Strikes 1 and 2 never touch the firewall.
# Rules flagged "immediate" skip the ladder: a single CRITICAL alert is
# enough to BLOCK, because by the time you see an exploit probe or a
# shell, the visitor has already shown their hand.
LADDER_POLICY = {
    "SHELL_ACCESS":  {"base_minutes": 120, "immediate": True},   # touched the fake shell
    "HONEYCREDS":    {"base_minutes": 120, "immediate": True},   # used planted honey credentials
    "EXPLOIT_PROBE": {"base_minutes": 120, "immediate": True},   # e.g. log4shell string inbound
    "AI_AGENT":      {"base_minutes": 120},                      # behavioral AI detection (HIGH, not CRITICAL)
    "BRUTE_FORCE":   {"base_minutes": 60},                       # 5+ logins already
    "PORT_SCAN":     {"base_minutes": 30},
    "WEB_PROBING":   {"base_minutes": 30},
}

STRIKE_TTL = 24 * 60 * 60   # seconds of attacker silence before WATCH/ESCALATE strikes decay
SWARM_IPS = 5               # distinct IPs that trip the swarm log for one rule
SWARM_WINDOW = 10 * 60      # seconds window for the swarm tripwire
MAX_BLOCK_MINUTES = 24 * 60  # hard cap on any single block duration

# IPs that are never blocked. Loopback and the host's own addresses are
# always protected automatically; add yours here (your home/office IP).
ALLOWLIST = set()


def log(msg):
    line = "%s %s" % (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), msg)
    print(line, flush=True)
    with open(LOG_FILE, "a") as fh:
        fh.write(line + "\n")


def own_ips():
    """Host's own addresses — never block these.
    Limitation: gethostbyname_ex() can miss secondary or VPN-interface
    addresses. Loopback is always protected (see is_protected), but an
    own-IP on an unlisted interface would NOT be recognized as ours —
    so double-check before running --enforce on a multi-homed host."""
    ips = set()
    try:
        _, _, addrs = socket.gethostbyname_ex(socket.gethostname())
        ips.update(addrs)
    except OSError:
        pass
    return ips


def is_protected(ip, protected):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a valid IP -> block nothing
    return addr.is_loopback or str(addr) in protected


def fw_block(ip):
    subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                   check=True, capture_output=True)


def fw_unblock(ip):
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                   check=False, capture_output=True)


def state_key(ip, rule):
    return "%s|%s" % (ip, rule)


def split_key(key):
    return key.rsplit("|", 1)


def normalize_entry(key, entry):
    """Accept OLD-format entries {"until","rule"} (backward compat):
    treat as level BLOCK with 3 strikes. Also upgrades bare-ip keys from
    the old single-rule-per-IP format to composite "ip|rule" keys."""
    e = dict(entry or {})
    if "strikes" not in e:
        e["strikes"] = 3
    if "level" not in e:
        e["level"] = "BLOCK"
    if "|" not in key:
        key = state_key(key, e.get("rule", ""))
    return key, e


def load_state():
    raw = {}
    try:
        with open(STATE_FILE) as fh:
            raw = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    state = {}
    now = time.time()
    for key, entry in raw.items():
        key, e = normalize_entry(key, entry)
        if e.get("dryrun"):
            continue  # a dry-run BLOCK was never enforced — do not honor it
        if e.get("until", 0) <= now:
            continue
        state[key] = e
    return state


def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE_FILE)


def follow_alerts(path):
    """Yield alert dicts: everything already in the file, then new lines.

    TRUST NOTE: blocker.py acts on whatever is in this file. alerts.jsonl
    must be writable only by the SIEM user (chmod 600) — a forged alert is
    a forged strike, and in --enforce mode that is a forged block.
    """
    pos = 0
    while True:
        try:
            with open(path) as fh:
                fh.seek(pos)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        pass
                pos = fh.tell()
        except FileNotFoundError:
            pass
        time.sleep(1)


def level_for(strikes):
    if strikes <= 1:
        return "WATCH"
    if strikes == 2:
        return "ESCALATE"
    return "BLOCK"


def block_minutes(strikes, base):
    if strikes <= 3:
        return base
    if strikes == 4:
        return min(2 * base, MAX_BLOCK_MINUTES)
    return min(4 * base, MAX_BLOCK_MINUTES)


def main():
    global ALERTS_FILE, LOG_FILE, STATE_FILE
    ap = argparse.ArgumentParser(description="SIEM auto-blocker: graduated response (dry-run by default)")
    ap.add_argument("--enforce", action="store_true",
                    help="actually run iptables (needs root)")
    ap.add_argument("--unblock-all", action="store_true",
                    help="lift every active block and exit")
    ap.add_argument("--alerts-file", default=ALERTS_FILE,
                    help="alerts.jsonl to tail (default: %(default)s)")
    ap.add_argument("--log-file", default=LOG_FILE,
                    help="decision log (default: %(default)s)")
    ap.add_argument("--state-file", default=STATE_FILE,
                    help="ladder state JSON (default: %(default)s)")
    args = ap.parse_args()

    ALERTS_FILE, LOG_FILE, STATE_FILE = args.alerts_file, args.log_file, args.state_file

    protected = set(ALLOWLIST) | own_ips() | {"127.0.0.1", "::1"}
    state = load_state()
    mode_tag = "ENFORCE" if args.enforce else "dry-run"

    if args.unblock_all:
        if not args.enforce:
            # Refuse in dry-run: clearing the state file WITHOUT removing
            # the live iptables rules would orphan DROP rules the blocker
            # no longer tracks — and never expires them.
            print("[-] --unblock-all needs --enforce: clearing the state "
                  "file without lifting the live iptables rules would "
                  "orphan DROP rules the blocker forgets.", file=sys.stderr)
            sys.exit(2)
        for key in list(state):
            ip, rule = split_key(key)
            if args.enforce and state[key].get("level") == "BLOCK":
                fw_unblock(ip)
            log("UNBLOCK %s (manual)" % ip)
        state = {}
        save_state(state)
        return

    if args.enforce and os.geteuid() != 0:
        print("[-] --enforce needs root (iptables). Run with sudo.", file=sys.stderr)
        sys.exit(2)

    def sweep():
        now_ = time.time()
        for key in [k for k, e in state.items() if e["until"] <= now_]:
            ip, rule = split_key(key)
            e = state[key]
            if e.get("level") == "BLOCK":
                if args.enforce:
                    fw_unblock(ip)
                log("UNBLOCK %s (expired, rule %s)" % (ip, rule))
            else:
                log("DECAY %s (rule %s, %d strikes lapsed after silence)" %
                    (ip, rule, e.get("strikes", 0)))
            del state[key]
        save_state(state)

    def is_blocked(ip):
        now_ = time.time()
        return any(k.rsplit("|", 1)[0] == ip and e.get("level") == "BLOCK"
                   and e["until"] > now_ for k, e in state.items())

    swarm = {}       # rule -> [(ip, ts)] of strike activity, for the tripwire
    last_swarm = {}  # rule -> ts of last SWARM log (rate-limit the tripwire)

    log("started (mode=%s, watching %s)" % (mode_tag, ALERTS_FILE))
    try:
        for alert in follow_alerts(ALERTS_FILE):
            sweep()
            if not isinstance(alert, dict):
                continue  # garbage line that happened to parse as JSON
            now = time.time()
            ip = str(alert.get("src_ip", ""))
            rule = alert.get("rule", "")
            if rule not in LADDER_POLICY:
                continue
            if is_protected(ip, protected):
                log("SKIP %s (protected address, rule %s)" % (ip, rule))
                continue
            if is_blocked(ip):
                log("SKIP %s (already blocked, rule %s)" % (ip, rule))
                continue

            # --- the ladder: one more strike on this IP's record for this rule
            key = state_key(ip, rule)
            prev = state.get(key, {})
            strikes = prev.get("strikes", 0) + 1
            if LADDER_POLICY[rule].get("immediate"):
                # CRITICAL rules don't climb the ladder: one alert = BLOCK.
                strikes = max(strikes, 3)
            level = level_for(strikes)
            base = LADDER_POLICY[rule]["base_minutes"]
            if level == "BLOCK":
                minutes = block_minutes(strikes, base)
                until = now + minutes * 60
            else:
                minutes = 0
                until = now + STRIKE_TTL  # strikes die of old age, not of mercy
            state[key] = {"until": until, "rule": rule,
                          "strikes": strikes, "level": level}

            # --- swarm tripwire: distributed sources stay under the ladder,
            # --- so >= SWARM_IPS distinct IPs at WATCH+ for one rule in
            # --- SWARM_WINDOW earns a log line. LOG ONLY. Never auto-block:
            # --- blocking on aggregates hands spoofed sources a self-DoS
            # --- button pointed at our own firewall.
            seen = swarm.setdefault(rule, [])
            seen.append((ip, now))
            seen = [(i, t) for (i, t) in seen if t >= now - SWARM_WINDOW]
            swarm[rule] = seen
            distinct = {i for (i, t) in seen}
            if (len(distinct) >= SWARM_IPS
                    and now - last_swarm.get(rule, 0) > SWARM_WINDOW):
                last_swarm[rule] = now
                log("SWARM suspected distributed %s from %d ips "
                    "(log only, no auto-block)" % (rule, len(distinct)))

            # --- act (or deliberately not act) per level
            dry = "" if args.enforce else " [dry-run]"
            if level == "WATCH":
                save_state(state)
                log("WATCH %s (rule %s, strike %d)%s" % (ip, rule, strikes, dry))
            elif level == "ESCALATE":
                save_state(state)
                log("ESCALATE %s (rule %s, strike %d: heightened watch)%s" %
                    (ip, rule, strikes, dry))
            else:  # BLOCK — the only level that ever touches the firewall
                if args.enforce:
                    try:
                        fw_block(ip)
                    except subprocess.CalledProcessError as e:
                        log("BLOCK-FAILED %s: %s" % (ip, e))
                        continue
                    save_state(state)
                    log("BLOCK %s for %dm (rule %s, strike %d)" %
                        (ip, minutes, rule, strikes))
                else:
                    state[key]["dryrun"] = True  # never honored on reload
                    save_state(state)
                    log("WOULD-BLOCK %s for %dm (rule %s, strike %d) [dry-run]" %
                        (ip, minutes, rule, strikes))
    except KeyboardInterrupt:
        log("stopped.")


# ---------------------------------------------------------------------------
# NOT IMPLEMENTED — tarpit-redirect sketch (kept as a comment on purpose).
#
# Instead of "-j DROP", a blocked IP could be redirected into a tarpit that
# dribbles responses forever, e.g.:
#   iptables -t nat -A PREROUTING -s <ip> -p tcp -j REDIRECT --to-ports <tarpit-port>
# or, where available, the dedicated TARPIT target (xt_TARPIT), which answers
# SYNs and then goes silent, holding the attacker's connection open.
#
# Why this is NOT enforced here:
#   * Topology decisions: the tarpit needs its own listener per protocol/port,
#     and REDIRECT only works pre-routing — the machine's own services, NAT,
#     and any bridged/VM networking all change what "redirect" even means.
#   * Abuse reflection: a misconfigured redirect can bounce attacker traffic
#     somewhere it shouldn't go, or wedge the firewall with held-open state.
#   * DROP is legible: it fails closed and is trivially auditable. The
#     standalone tarpit/ module covers slow-drip tarpitting as its own
#     deliberately-deployed thing, not as a side effect of the blocker.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
