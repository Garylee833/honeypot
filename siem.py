#!/usr/bin/env python3
"""mini-SIEM — a tiny detection engine for the honeypot.

Tails logs/events.jsonl and fires detection rules written like baby Sigma:
each rule is a name, a MITRE ATT&CK ID, a threshold, and a time window.
Tune the RULES list below — that's detection engineering.

Usage:
    python3 siem.py                 # live mode: watch for new events
    python3 siem.py --replay        # analyze the existing log from the top
    python3 siem.py --log PATH      # watch a different log file
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

try:
    import playbooks  # Layer 1: SIEM may escalate an IP's playbook on alert
    PLAYBOOKS_AVAILABLE = True
except ImportError:
    playbooks = None
    PLAYBOOKS_AVAILABLE = False

SERVICE_PORTS = {
    "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "http": 80,
    "mssql": 1433, "docker": 2375, "mysql": 3306, "rdp": 3389,
    "postgres": 5432, "vnc": 5900, "redis": 6379, "elastic": 9200,
    "mongo": 27017, "ollama": 11434, "openai": 8000,
}

SUSPICIOUS_PATHS = ["admin", "wp-", "wordpress", "phpmyadmin", "/pma",
                    ".env", "config", "backup", ".git", "shell.php",
                    "cmd", "eval", "phpinfo"]

# --- Detection rules: (name, attack_id, severity, window_seconds, threshold) ---
RULES = [
    # Many login attempts from one IP in a short window = password guessing.
    ("BRUTE_FORCE", "T1110",     "HIGH",     60, 5),
    # One IP touching many different service ports = reconnaissance scan.
    ("PORT_SCAN",   "T1046",     "MEDIUM",   30, 6),
    # One IP requesting lots of admin/login/config paths = web probing.
    ("WEB_PROBING", "T1595.002", "MEDIUM",   60, 3),
]
# Any interactive shell session at all = someone got in. Always critical.
SHELL_RULE = ("SHELL_ACCESS", "T1078", "CRITICAL")
# Behavioral AI-agent detection from the honeypot's shell tracker.
# Closest ATT&CK mapping: Active Scanning — no dedicated technique ID exists
# yet for AI-agent tradecraft.
AI_RULE = ("AI_AGENT", "T1595", "HIGH")
# Canary credential touched (read or used via the fake `aws` CLI).
# Closest ATT&CK mapping: Valid Accounts -- the attacker is reaching for
# credentials that would grant access if they were real.
HONEYCREDS_RULE = ("HONEYCREDS", "T1078", "CRITICAL")
# Credential-dump decoy touched (a planted fake credential cache was read).
# Closest ATT&CK mapping: OS Credential Dumping — the attacker is collecting
# credential material. Honest boundary: this fires on *decoy* contact only;
# it does NOT detect real LSASS/memory dumping (no endpoint telemetry).
CRED_DUMP_TRIPWIRE_RULE = ("CRED_DUMP_TRIPWIRE", "T1003", "CRITICAL")
# Inference-abuse attempt on the fake LLM endpoints (Ollama / OpenAI-compat).
# One POST carrying a prompt is enough: nobody legitimately prompts a
# honeypot. Closest ATT&CK mapping: Resource Hijacking — the attacker's
# goal is someone else's inference compute — the documented exposed-LLM
# playbook (scan 11434/8000, resell the access).
LLMJACK_RULE = ("LLMJACK_ATTEMPT", "T1496", "CRITICAL")
# Known exploit payload aimed at any service (Log4Shell, path traversal,
# command/SQL injection...). The honeypot never executes it — the event is
# the tripwire. Closest ATT&CK mapping: Exploit Public-Facing Application.
EXPLOIT_RULE = ("EXPLOIT_PROBE", "T1190", "CRITICAL")

ALERT_COOLDOWN = timedelta(minutes=10)


def _maybe_escalate(ip, rule):
    """Layer 1: an alert is strong behavioral evidence — force the IP's
    engagement playbook. Never raises. SHELL_ACCESS/HONEYCREDS are
    deliberately NOT escalated: one shell or one canary touch is evidence,
    not yet an attacker type (the classifier decides from fuller behavior).
    AI_AGENT is the strongest signal and wins outright."""
    if not PLAYBOOKS_AVAILABLE:
        return
    mapping = {"AI_AGENT": "ai_agent", "BRUTE_FORCE": "stuffer",
               "PORT_SCAN": "scanner", "EXPLOIT_PROBE": "scanner",
               "WEB_PROBING": "scanner", "LLMJACK_ATTEMPT": "scanner"}
    pb = mapping.get(rule)
    if pb:
        try:
            playbooks.escalate(ip, pb)
        except Exception:
            pass


def _load_honeytoken_values():
    """Canonical canary secret values from honeycreds.py (same directory).

    Guarded import: the SIEM must keep working if honeycreds.py is absent.
    Only values carrying an obvious fake marker (HONEY/FAKE/EXAMPLE) are
    returned, so mundane decoy-file strings (ports, regions, hostnames)
    can never match a visitor's command.
    """
    try:
        import honeycreds
        markers = ("HONEY", "FAKE", "EXAMPLE")
        vals = set()
        for content in honeycreds.HONEYCREDS_FILES.values():
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                v = line.split("=", 1)[1].strip().strip("\"'")
                if len(v) >= 12 and any(m in v.upper() for m in markers):
                    vals.add(v)
        return vals
    except Exception:
        return set()


_HONEYTOKEN_VALUES = _load_honeytoken_values()


def _cmd_carries_honeytoken(cmd):
    """True if a shell command contains a known canary secret value."""
    return any(v in cmd for v in _HONEYTOKEN_VALUES)


def parse_time(ts):
    try:
        dt = datetime.fromisoformat(ts)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


class Engine:
    def __init__(self, quiet=False, alert_log="alerts.jsonl"):
        # ip -> list of (timestamp, kind, detail); kind in auth/port/web
        self.events = defaultdict(list)
        self.cooldowns = {}  # (rule, ip) -> datetime of last alert
        # Bounded: a spoofed-source flood must not grow this forever.
        # The dashboard slices engine.alerts, so this stays a plain list.
        self.alerts = []
        self.quiet = quiet
        self.alert_log = alert_log
        # session ids that have read a canary file: a later aws-style
        # invocation in the same session is credential USE, not just a read.
        # Bounded best-effort: per-session tracking is a nicety, not a promise.
        self.honey_sessions = set()

    def _clean(self, s):
        """Strip terminal control characters from attacker-influenced text."""
        return "".join(c for c in s if c in "\n\t" or ord(c) >= 32)

    def _fire(self, when, severity, rule, attack_id, ip, detail):
        a = {"time": when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "severity": severity, "rule": rule, "attack_id": attack_id,
             "src_ip": ip, "detail": detail}
        self.alerts.append(a)
        if len(self.alerts) > 5000:
            del self.alerts[:len(self.alerts) - 5000]
        if self.alert_log:
            try:
                with open(self.alert_log, "a") as fh:
                    fh.write(json.dumps(a) + "\n")
            except OSError:
                pass  # alerting must never crash the SIEM
        if not self.quiet:
            # Console copy is attacker-influenced (detail carries raw shell
            # commands); strip ANSI/control codes before printing.
            line = self._clean(f"[{a['time']}] {severity:8} {rule:12} "
                               f"({attack_id:9}) src={ip} {detail}")
            print(line, flush=True)

    def _cooled(self, rule, ip, now):
        # Periodic sweep: expired cooldowns are dropped so a spoofed-source
        # flood can't grow this dict without bound.
        if len(self.cooldowns) > 10000:
            expired = [k for k, t in self.cooldowns.items()
                       if now - t >= ALERT_COOLDOWN]
            for k in expired:
                del self.cooldowns[k]
        key = (rule, ip)
        if key in self.cooldowns and now - self.cooldowns[key] < ALERT_COOLDOWN:
            return True
        self.cooldowns[key] = now
        return False

    def _prune(self, ip, now, window):
        cutoff = now - timedelta(seconds=window)
        self.events[ip] = [e for e in self.events[ip] if e[0] >= cutoff]
        if not self.events[ip]:
            # Pruned to nothing: delete the key, or every distinct src_ip
            # ever seen (spoofed or not) lives here forever.
            del self.events[ip]

    def handle(self, ev):
        # Synthetic aliveness noise: NEVER alert on our own theater.
        # This check is first on purpose — nothing below may see synthetic
        # events, or the fortress would detect itself.
        if not isinstance(ev, dict):
            return  # malformed line that somehow parsed: never alert, never die
        if ev.get("synthetic") is True:
            return
        now = parse_time(ev.get("time"))
        ip = ev.get("src_ip", "?")
        service = ev.get("service", "?")
        data = ev.get("data", "")
        if not isinstance(data, str):
            # A forged log line with non-string data ("data": 123) must not
            # kill the SIEM via AttributeError on .startswith below.
            data = str(data)
        if len(self.events) > 10000:
            # One-shot spoofed-source floods leave keys that are never
            # revisited, so per-IP pruning never sees them. Sweep keys whose
            # events are all older than the longest rule window.
            cutoff = now - timedelta(seconds=60)  # max RULES window
            dead = [k for k, evs in self.events.items()
                    if all(t < cutoff for t, _, _ in evs)]
            for k in dead:
                del self.events[k]

        # AI agent detected by the honeypot's behavioral tracker: instant alert.
        if data.startswith("AI_AGENT_DETECTED"):
            if not self._cooled(AI_RULE[0], ip, now):
                self._fire(now, AI_RULE[2], AI_RULE[0], AI_RULE[1], ip, data)
                _maybe_escalate(ip, AI_RULE[0])  # Layer 1: steer to tripwires
            return

        # Canary credential touched: instant critical alert, no threshold.
        # honeycreds_read=  <- a reader (cat/less/...) opened a canary file
        # honeycreds_used=  <- the fake `aws` CLI was invoked
        # Read and use cool down independently: a use right after a read is
        # a distinct, more serious step in the kill chain, not a duplicate.
        if data.startswith("honeycreds_read="):
            if len(self.honey_sessions) >= 1000:
                # Bounded best-effort: drop old session marks rather than
                # let a spoofed-session flood grow this set forever.
                self.honey_sessions.clear()
            self.honey_sessions.add(ev.get("session"))
            if not self._cooled("HONEYCREDS:read", ip, now):
                detail = ("canary credential file read: "
                          + data[len("honeycreds_read="):][:80])
                self._fire(now, HONEYCREDS_RULE[2], HONEYCREDS_RULE[0],
                           HONEYCREDS_RULE[1], ip, detail)
            return

        if data.startswith("honeycreds_used="):
            if not self._cooled("HONEYCREDS:use", ip, now):
                detail = ("canary credential used via aws: "
                          + data[len("honeycreds_used="):][:80])
                self._fire(now, HONEYCREDS_RULE[2], HONEYCREDS_RULE[0],
                           HONEYCREDS_RULE[1], ip, detail)
            return

        # Credential-dump decoy read: instant critical alert, no threshold.
        # The event itself is the tripwire — the file is planted fake
        # credential material (T1003 decoy layer, honest PARTIAL).
        if data.startswith("cred_dump_decoy_read="):
            if not self._cooled("CRED_DUMP_TRIPWIRE:read", ip, now):
                detail = ("credential-dump decoy read: "
                          + data[len("cred_dump_decoy_read="):][:80])
                self._fire(now, CRED_DUMP_TRIPWIRE_RULE[2],
                           CRED_DUMP_TRIPWIRE_RULE[0],
                           CRED_DUMP_TRIPWIRE_RULE[1], ip, detail)
            return

        # Exploit probe: a known exploit signature in visitor input.
        # Instant critical alert, no threshold — the payload never executes,
        # the event itself is the tripwire.
        if data.startswith("exploit_probe="):
            if not self._cooled(EXPLOIT_RULE[0], ip, now):
                detail = data[len("exploit_probe="):][:80]
                self._fire(now, EXPLOIT_RULE[2], EXPLOIT_RULE[0],
                           EXPLOIT_RULE[1], ip, detail)
                _maybe_escalate(ip, EXPLOIT_RULE[0])  # Layer 1: tarpit them
            return

        # Shell access: instant critical alert, no threshold.
        if data.startswith("shell_cmd="):
            cmd = data[len("shell_cmd="):]
            # Credential USE, method 1: the command carries a known canary
            # secret value (pasted key, exported env var, -p password...).
            if _cmd_carries_honeytoken(cmd):
                if not self._cooled("HONEYCREDS:use", ip, now):
                    self._fire(now, HONEYCREDS_RULE[2], HONEYCREDS_RULE[0],
                               HONEYCREDS_RULE[1], ip,
                               "canary credential value used in command: "
                               + cmd[:80])
            # Credential USE, method 2: an aws-style invocation the
            # honeypot's own hook misses (odd path/casing), after a canary
            # read in the same session. Plain `aws` already trips
            # honeycreds_used= above, so it is excluded here.
            words = cmd.split()
            if (ev.get("session") in self.honey_sessions and words
                    and words[0] != "aws"
                    and any(os.path.basename(w).lower() == "aws"
                            for w in words)):
                if not self._cooled("HONEYCREDS:use", ip, now):
                    self._fire(now, HONEYCREDS_RULE[2], HONEYCREDS_RULE[0],
                               HONEYCREDS_RULE[1], ip,
                               "aws invoked after canary read in same "
                               "session: " + cmd[:80])
            if not self._cooled(SHELL_RULE[0], ip, now):
                self._fire(now, SHELL_RULE[2], SHELL_RULE[0], SHELL_RULE[1], ip,
                           f"interactive shell on {service} (tried: {cmd[:60] or '<empty>'})")
            return

        # Shell acquisition: the fake ssh/telnet handlers accept ANY
        # credentials and drop the visitor straight into the fake shell, so
        # a completed password exchange on those services IS a shell grant
        # -- even if the visitor never types a command (then no shell_cmd=
        # event ever exists for the SIEM to see). Instant critical alert.
        # Falls through on purpose: the password event must still count as
        # an "auth" event for BRUTE_FORCE below.
        if service in ("ssh", "telnet") and data.startswith("password="):
            if not self._cooled(SHELL_RULE[0], ip, now):
                self._fire(now, SHELL_RULE[2], SHELL_RULE[0], SHELL_RULE[1], ip,
                           f"interactive shell granted on {service} "
                           f"(any credentials accepted)")

        # Inference-abuse attempt on the fake LLM endpoints: instant
        # critical, like SHELL_ACCESS. One prompt POST is the whole story —
        # it must not also dilute into threshold counting below.
        if data.startswith("llm_abuse_attempt="):
            if not self._cooled(LLMJACK_RULE[0], ip, now):
                self._fire(now, LLMJACK_RULE[2], LLMJACK_RULE[0],
                           LLMJACK_RULE[1], ip,
                           f"inference-abuse attempt on {service} "
                           f"({data[:80]})")
                _maybe_escalate(ip, LLMJACK_RULE[0])
            return

        kind = None
        if "username=" in data or "password=" in data:
            kind = "auth"
        elif service in ("http", "ollama", "openai") and data.startswith("request="):
            # "request=GET /admin HTTP/1.1" -> path is token [1]
            parts = data.split("request=", 1)[1].split(" ")
            path = parts[1].lower() if len(parts) > 1 else parts[0].lower()
            if any(s in path for s in SUSPICIOUS_PATHS):
                kind = "web"
        if kind is None and service in SERVICE_PORTS:
            # every connection to a service counts as touching that port
            kind = "port"

        if kind is None:
            return
        self.events[ip].append((now, kind, service))

        for name, attack_id, severity, window, threshold in RULES:
            want = {"BRUTE_FORCE": "auth", "PORT_SCAN": "port",
                    "WEB_PROBING": "web"}[name]
            self._prune(ip, now, window)
            if want == "port":
                distinct = {SERVICE_PORTS[s] for _, k, s in self.events[ip]
                            if k == "port" and s in SERVICE_PORTS}
                count = len(distinct)
                detail = f"{count} distinct ports in {window}s"
            else:
                count = sum(1 for _, k, _ in self.events[ip] if k == want)
                detail = f"{count} events in {window}s"
            if count >= threshold and not self._cooled(name, ip, now):
                self._fire(now, severity, name, attack_id, ip,
                           detail + f" (threshold {threshold})")
                _maybe_escalate(ip, name)  # Layer 1: route to a playbook


def follow(path, replay):
    """Yield parsed events. Replay: one pass over the whole file.
    Live: tail new lines forever, surviving log rotation."""
    f = open(path, encoding="utf-8", errors="replace")
    if not replay:
        f.seek(0, os.SEEK_END)  # live mode starts at the tail, not the head
    while True:
        line = f.readline()
        if line:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
        else:
            if replay:
                return  # one pass done
            try:
                # Log rotated (rename-and-recreate) or truncated? Reopen.
                # The project's own rotate-fortress-logs.sh uses mv, so
                # inode comparison is what keeps the SIEM from going blind
                # on the first rotation.
                rotated = os.stat(path).st_ino != os.fstat(f.fileno()).st_ino
                truncated = os.path.getsize(path) < f.tell()
                if rotated or truncated:
                    f.close()
                    f = open(path, encoding="utf-8", errors="replace")
                    continue
            except OSError:
                pass
            time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser(description="mini-SIEM for the honeypot")
    ap.add_argument("--log", default="logs/events.jsonl")
    ap.add_argument("--replay", action="store_true",
                    help="analyze the existing log instead of tailing")
    ap.add_argument("--alert-log", default="alerts.jsonl",
                    help="append every fired alert here (blocker.py tails this)")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        print(f"[!] log not found: {args.log}", file=sys.stderr)
        print("    Start the honeypot first:  sudo python3 honeypot.py", file=sys.stderr)
        sys.exit(1)

    eng = Engine(alert_log=args.alert_log)
    mode = "REPLAY" if args.replay else "LIVE"
    print(f"[*] mini-SIEM ({mode}) watching {args.log}")
    print(f"[*] alerts -> {args.alert_log} (tailed by blocker.py)")
    print(f"[*] {len(RULES)} threshold rules + {SHELL_RULE[0]} (any shell = {SHELL_RULE[2]}) + {AI_RULE[0]} (behavioral = {AI_RULE[2]}) + {HONEYCREDS_RULE[0]} (canary creds = {HONEYCREDS_RULE[2]}) + {CRED_DUMP_TRIPWIRE_RULE[0]} (dump decoys = {CRED_DUMP_TRIPWIRE_RULE[2]}) + {EXPLOIT_RULE[0]} (exploit payload = {EXPLOIT_RULE[2]}) + {LLMJACK_RULE[0]} (LLM inference abuse = {LLMJACK_RULE[2]})")
    print(f"[*] thresholds: " + ", ".join(f"{n}>={t}/{w}s" for n, _, _, w, t in RULES))
    print("-" * 70, flush=True)
    try:
        for ev in follow(args.log, args.replay):
            try:
                eng.handle(ev)
            except Exception as e:
                # One malformed event must never kill detection for the rest.
                print(f"[!] dropped event: {e}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\n[*] mini-SIEM stopped.")


if __name__ == "__main__":
    main()
