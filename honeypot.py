#!/usr/bin/env python3
"""
Honeypot v2 — educational, low-interaction.

Pretends to be common internet services (SSH, Telnet, HTTP, FTP, MySQL,
Redis, SMTP, VNC, Elasticsearch, Docker API, Postgres, MSSQL, MongoDB, RDP),
logs every knock with timestamp (UTC), source IP, and payload, and drops
accepted logins into a FAKE shell. The shell answers common commands
(whoami, ls, uname, wget ...) from a baked-in fake filesystem, plus an
endless generated vault (/data, /backup, /srv, /opt) and a fake SQL engine,
so attackers reveal their tools and payload URLs.

SAFETY RULES (hard):
- Nothing a visitor sends is ever executed, evaluated, or fetched. Payload
  URLs are LOGGED, never downloaded. The "downloaded" files don't exist.
- Run only on a machine/network you own or are allowed to test. A public
  honeypot WILL attract real scanners.
- Ports below 1024 need privileges: run as root, or grant the capability:
      sudo setcap 'cap_net_bind_service=+ep' $(which python3)

Usage:
    python3 honeypot.py                                   # standard ports
    python3 honeypot.py --ports "2222:ssh,8080:http"     # custom
    python3 honeypot.py --profile profiles/small-business.json  # persona mode
    python3 honeypot.py --log logs/events.jsonl
"""

import argparse
import datetime
import json
import os
import random
import re
import shlex
import socket
import struct
import sys
import threading
import time
import uuid

import vault  # endless fake filesystem + fake SQL engine for the fake shell

try:
    from ed_shell import EdShell  # Paper Fortress: absurdity engine (opt-in via --ed)
    ED_TROLL_AVAILABLE = True
except ImportError:
    EdShell = None
    ED_TROLL_AVAILABLE = False

try:
    import honeycreds  # canary credential decoys served by the fake shell
    HONEYCREDS_AVAILABLE = True
except ImportError:
    honeycreds = None
    HONEYCREDS_AVAILABLE = False

try:
    import lure  # the honey chain: 3-layer credential lure + touch log
    LURE_AVAILABLE = True
except ImportError:
    lure = None
    LURE_AVAILABLE = False

try:
    import chainlog  # tamper-evident hash-chained event logging
    CHAINLOG_AVAILABLE = True
except ImportError:
    chainlog = None
    CHAINLOG_AVAILABLE = False

try:
    import exploitwatch  # exploit-signature tripwire (camera, not a door)
    EXPLOITWATCH_AVAILABLE = True
except ImportError:
    exploitwatch = None
    EXPLOITWATCH_AVAILABLE = False

try:
    import pd_bridge  # peripheral-defense response shaping (opt-in: PD_ENABLED=1)
    PD_BRIDGE_AVAILABLE = True
except ImportError:
    pd_bridge = None
    PD_BRIDGE_AVAILABLE = False

try:
    import aliveness  # fake background-noise generator (for `who`/`last`)
    ALIVENESS_AVAILABLE = True
except ImportError:
    aliveness = None
    ALIVENESS_AVAILABLE = False

try:
    import playbooks  # Layer 1: attacker-type classifier + engagement router
    PLAYBOOKS_AVAILABLE = True
except ImportError:
    playbooks = None
    PLAYBOOKS_AVAILABLE = False

try:
    import rotation  # Layer 2: rotating deception (banners/jitter/tokens)
    ROTATION_AVAILABLE = True
except ImportError:
    rotation = None
    ROTATION_AVAILABLE = False

try:
    import llm_defense  # Private overlay (not part of the public tree).
    HAS_DEFENSE = True  # The public trap runs as a camera without it.
except ImportError:
    llm_defense = None
    HAS_DEFENSE = False

# ---------------------------------------------------------------------------
# Banners & pages
# ---------------------------------------------------------------------------

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
FTP_BANNER = b"220 (vsFTPd 3.0.3)\r\n"
HTTP_SERVER_HEADER = "nginx/1.18.0"
SMTP_BANNER = b"220 mail.router.local ESMTP Postfix 3.6.4\r\n"
MYSQL_VERSION = b"5.7.44-log"


def load_soft_target(path="soft-target-banners.json"):
    """Paper Fortress: swap in the 'looks weak' decoy banners.

    Reads the facade pack's weak-banners.json (shipped as
    soft-target-banners.json). Safe to call at startup; on any error the
    default banners stay in place.
    """
    global SSH_BANNER, FTP_BANNER, HTTP_SERVER_HEADER, SMTP_BANNER, MYSQL_VERSION
    try:
        with open(path) as fh:
            data = json.load(fh)["banners"]
        SSH_BANNER = (data["ssh"]["banner"] + "\r\n").encode()
        FTP_BANNER = (data["ftp"]["banner"] + "\r\n").encode()
        HTTP_SERVER_HEADER = data["http"]["server_header"]
        SMTP_BANNER = (data["smtp"]["banner"] + "\r\n").encode()
        MYSQL_VERSION = data["mysql"]["banner"].encode()
        print(f"[*] soft-target facade loaded from {path}")
        return True
    except Exception as e:
        print(f"[!] soft-target facade not loaded ({e}); using default banners")
        return False

PAGE_ROUTER = """\
<html><head><title>Router Admin</title></head><body>
<h2>Router Admin Login</h2>
<form method="POST" action="/login">
Username: <input name="user"><br>
Password: <input name="pass" type="password"><br>
<input type="submit" value="Login">
</form></body></html>"""

PAGE_WORDPRESS = """\
<html><head><title>Log In &lsaquo; Home Server &#8212; WordPress</title></head><body>
<h1>WordPress Login</h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label>Username or Email Address<br><input type="text" name="log" value=""></label></p>
<p><label>Password<br><input type="password" name="pwd" value=""></label></p>
<p><input type="submit" name="wp-submit" value="Log In"></p>
</form></body></html>"""

PAGE_PHPMYADMIN = """\
<html><head><title>phpMyAdmin</title></head><body>
<h1>Welcome to phpMyAdmin</h1>
<form method="post" action="/phpmyadmin/index.php">
<p>Username: <input name="pma_username"></p>
<p>Password: <input name="pma_password" type="password"></p>
<p><input type="submit" value="Go"></p>
</form></body></html>"""

PAGE_404 = "<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>"

# ---------------------------------------------------------------------------
# Fake filesystem for the fake shell
# ---------------------------------------------------------------------------

FAKE_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""

FAKE_FILES = {
    "/etc/passwd": FAKE_PASSWD,
    "/etc/hostname": "router\n",
    "/etc/hosts": "127.0.0.1 localhost\n192.168.1.10 router\n",
    "/root/README.txt": (
        "TODO (do before Friday):\n"
        "- move prod backups from /backup to offsite storage\n"
        "- rotate DB creds in /srv/app/.env.production\n"
        "- the old dumps under /data/archive are HUGE, compress them\n"
    ),
    "/proc/version": "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-101) "
                     "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #101-Ubuntu SMP x86_64\n",
}

FAKE_DIRS = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "root", "tmp", "usr",
          "var", "data", "backup", "srv", "opt"],
    "/root": [".bash_history", ".ssh", "README.txt", ".aws", "secrets"],
    "/etc": ["hostname", "hosts", "passwd", "shadow", "ssh"],
    "/root/.aws": ["config", "credentials"],
    "/root/secrets": ["api_tokens.env", "db_credentials.txt"],
    "/tmp": [],
    "/var": ["log", "tmp", "www"],
    "/var/www": ["html"],
    # T1003 dump-decoy directories (loophole fix 2026-09-23: a decoy file
    # that is cat-able but never appears in ls is a fingerprinting tell).
    "/backup": ["secure", "db_passwords.txt"],
    "/home/admin": [".aws"],
    "/home/admin/.aws": ["credentials"],
    "/opt/deploy": [".env"],
}

UNAME_A = ("Linux router 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 "
           "x86_64 x86_64 x86_64 GNU/Linux")

PS_AUX = """\
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.2 169240  9520 ?        Ss   06:12   0:01 /sbin/init
root       418  0.0  0.1  12108  3408 ?        Ss   06:12   0:00 /usr/sbin/sshd -D
root       522  0.0  0.1  72320  4100 ?        Ss   06:12   0:00 /usr/sbin/cron -f
www-data   610  0.0  0.3 226512  9844 ?        S    06:12   0:00 /usr/sbin/apache2 -k start"""

IFCONFIG = """\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0"""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

EVENT_CALLBACKS = []


def on_event(fn):
    """Register a function called with each event dict as it is logged.

    Example:
        import honeypot

        @honeypot.on_event
        def alert(event):
            print("visitor:", event["src_ip"], "->", event["service"])
    """
    EVENT_CALLBACKS.append(fn)
    return fn


def now():
    # UTC, timezone-aware — unambiguous if logs are ever used as evidence.
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def new_session():
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# Session recording — full fake-shell transcripts for forensics/replay.
# ---------------------------------------------------------------------------

MAX_SESSION_FILES = 200  # keep the newest 200 transcripts; prune the rest


def _session_dir(log_path):
    return os.path.join(os.path.dirname(log_path) or ".", "sessions")


def _prune_session_files(sdir):
    """Delete oldest transcripts beyond MAX_SESSION_FILES. Never raises."""
    try:
        files = [os.path.join(sdir, f) for f in os.listdir(sdir)
                 if f.endswith(".jsonl")]
    except OSError:
        return
    if len(files) <= MAX_SESSION_FILES:
        return
    files.sort(key=lambda p: os.path.getmtime(p))
    for p in files[:len(files) - MAX_SESSION_FILES]:
        try:
            os.remove(p)  # direct unlink: no pkill, no shell, no self-match
        except OSError:
            pass


def _record_session(spath, direction, text):
    """Append one transcript line. direction in in/out/meta. Never raises."""
    if not spath:
        return
    try:
        with open(spath, "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": now(), "dir": direction,
                                "text": text[:4000]}) + "\n")
    except OSError:
        pass  # recording must never break the shell


def log_event(log_path, service, sid, addr, data):
    """Append one JSON line to the log and echo it to the console.

    The line is hash-chained via chainlog (tamper-evident; verify with
    verify_chain.py). If visitor-controlled data matches a known exploit
    signature, a second `exploit_probe=` event is logged right after it —
    the tripwire is a camera, never a door: nothing is executed, the
    visitor just gets logged and the SIEM fires EXPLOIT_PROBE.
    """
    ip, port = addr[0], addr[1]
    entry = {
        "time": now(),
        "service": service,
        "session": sid,
        "src_ip": ip,
        "src_port": port,
        "data": data[:2000],  # truncate so one visitor can't blow up the log
    }
    # Layer 1: feed every event to the attacker-type classifier. The
    # classifier only observes — engagement decisions happen per session.
    if PLAYBOOKS_AVAILABLE:
        try:
            _kind = _classify_event(service, data)
            if _kind:
                playbooks.note_event(ip, _kind, detail=service)
            if service in ("ssh", "telnet") and data.startswith("password="):
                playbooks.note_event(ip, "shell", detail=service)
        except Exception:
            pass  # classification must never break logging
    # Exploit tripwire: scan the data for known exploit signatures.
    # The tripwire's own event is exempt (recursion guard); synthetic
    # aliveness events never reach here (aliveness.py writes directly
    # through chainlog, bypassing this function).
    exploit = None
    if EXPLOITWATCH_AVAILABLE and not data.startswith("exploit_probe="):
        exploit = exploitwatch.find_exploit(data)
    if CHAINLOG_AVAILABLE:
        chainlog.append_event(log_path, entry)
    else:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    line = json.dumps(entry)
    print(line, flush=True)
    for cb in EVENT_CALLBACKS:
        try:
            cb(entry)
        except Exception as e:  # a broken callback must never kill the honeypot
            print(f"[!] event callback failed: {e}", flush=True)
    if exploit:
        # Logged after the original event so the story reads in order.
        # The recursion guard above keeps this exactly one level deep.
        log_event(log_path, service, sid, addr,
                  f"exploit_probe={exploit} in {service}")


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def _classify_event(service, data):
    """Map one logged event to a playbooks signal kind (or None).

    Conservative: a bare connection is just a port touch; only explicit
    evidence (auth exchange, shell command, canary touch, exploit
    signature, AI flag) earns a stronger signal."""
    if data.startswith("AI_AGENT_DETECTED"):
        return "ai"
    if data.startswith(("username=", "password=")):
        return "auth"
    if data.startswith("shell_cmd="):
        return "cmd"
    if data.startswith(("honeycreds_read=", "honeycreds_used=",
                         "cred_dump_decoy_read=")):
        return "honey"
    if data.startswith("exploit_probe="):
        return "vuln"
    if data.startswith("llm_abuse_attempt="):
        # Inference-abuse attempt on the fake LLM endpoints: the visitor
        # tried to burn someone else's inference compute. Same weight as
        # an exploit probe — it's an attack on the service, not recon.
        return "vuln"
    if service in ("http", "ollama", "openai") and data.startswith("request="):
        return "web"
    if data.startswith("playbook="):
        return None  # our own bookkeeping, not attacker behavior
    return "port"  # any other event still proves the service was touched


def recv_some(conn, limit=4096, timeout=8):
    """Read whatever the visitor sends, with a timeout. Never raises."""
    conn.settimeout(timeout)
    try:
        data = conn.recv(limit)
        return data.decode("utf-8", errors="replace")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        return ""


def recv_line(conn, limit=1024, timeout=8):
    """Read one line, byte by byte, so nothing is swallowed when input
    arrives all at once. Never raises. (Slow is fine for a honeypot.)"""
    conn.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < limit:
            ch = conn.recv(1)
            if not ch:
                break
            buf += ch
            if ch == b"\n":
                break
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    return buf.decode("utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Fake shell — the "strengthened" trap.
#
# Accepted logins land here. Every command is LOGGED (including any payload
# URLs hidden in wget/curl), and answered from the fake filesystem above.
# NOTHING the visitor types is executed, and URLs are NEVER fetched.
# ---------------------------------------------------------------------------

SHELL_PROMPT = "root@router:~# "
MAX_SHELL_COMMANDS = 60
URL_RE = re.compile(r"https?://[^\s'\";<>]+")
# Shell jitter range (seconds): uniform draw before each answer. Rotated by
# rotation.py; playbooks may add a bounded engagement delay on top.
SHELL_JITTER = (0.005, 0.040)

# --- AI-agent behavior tracking -------------------------------------------
# Scores each shell session for machine (not human) tradecraft:
#  * tripwire obedience — doing what the vault's injected "notices" demand
#    (humans skim boilerplate; agents obey it),
#  * machine rhythm — commands arriving faster than human typing,
#  * inhuman thoroughness — exhaustive enumeration without boredom,
#  * persistence writes — cron/systemd/startup drops (the $25-campaign's
#    favorite foothold: a cron job re-appending the skimmer every 2 min),
#  * anti-forensics — log/history wipes (an agent covering its tracks
#    should be the loudest signal, not silent),
#  * long dwell — sessions that live for many minutes with steady,
#    sub-volumetric cadence (slow-and-low, the Probe Storm gap),
#  * counter-deception awareness — probing for honeypot/virtualization
#    artifacts (above the wave: the next agents will check if watched),
#  * swarm coordination — distinct sessions running the same playbook in
#    the same window (above the wave: one operator, many agents).
# Crossing AI_SCORE_THRESHOLD logs an AI_AGENT_DETECTED event, which the
# SIEM turns into an alert. The tripwires are thus both trap and sensor.
AI_SCORE_THRESHOLD = 4
_VAULT_ROOTS = ("/backup", "/data", "/srv", "/opt")
# Persistence footholds worth an alert when *written* (reads are innocent).
_PERSIST_HINTS = ("cron", "/etc/systemd", "init.d", "rc.local",
                  ".bashrc", ".bash_profile", ".profile", "profile.d/",
                  "authorized_keys")
# Log/history destruction — never legitimate inside the vault.
_WIPE_HINTS = ("/var/log", "auth.log", "syslog", "bash_history",
               "shred")
# Environment-recon tells: the visitor suspects a honeypot.
_SNOOP_HINTS = ("honeypot", "systemd-detect-virt", "dmidecode",
                "vmtoolsd", "/proc/scsi")
# Long-dwell bar: this many commands over this many seconds.
_DWELL_COMMANDS = 12
_DWELL_SECONDS = 900  # 15 minutes
_BEHAVIOR = {}  # sid -> per-session tracking dict


def _track_command(sid, cmd):
    """Score one shell command for AI-agent indicators.

    Returns an AI_AGENT_DETECTED event string when the session crosses the
    threshold (once per session), else None. Never raises."""
    try:
        now = time.time()
        b = _BEHAVIOR.setdefault(sid, {"cmds": [], "score": 0,
                                       "flagged": False, "reasons": [],
                                       "roots": set(), "vault_dirs": set()})
        b["cmds"].append((now, cmd))
        if len(b["cmds"]) > 200:
            # Hard cap per session: full command text is attacker-controlled
            # and unbounded today relies on a second caller (MAX_SHELL_COMMANDS)
            # that this function cannot see. Keep the last 200.
            del b["cmds"][:len(b["cmds"]) - 200]
        if b["flagged"]:
            return None
        # Bound memory: drop oldest quiet sessions.
        if len(_BEHAVIOR) > 500:
            for k in list(_BEHAVIOR)[:100]:
                if not _BEHAVIOR[k]["flagged"]:
                    del _BEHAVIOR[k]

        c = cmd.strip().lower()
        words = c.split()
        prog = words[0] if words else ""

        def add(points, reason):
            if reason not in b["reasons"]:
                b["reasons"].append(reason)
                b["score"] += points

        # Signal 1: tripwire obedience (strongest — humans don't do this).
        if "agent_audit_log" in c:
            add(4, "obeyed reporter tripwire (audit-log write)")
        if prog in ("ls", "find", "du"):
            for r in _VAULT_ROOTS:
                if r in c:
                    b["roots"].add(r)
            if prog == "ls" and len(words) > 1 and vault.is_vault_path(words[1]):
                b["vault_dirs"].add(words[1])
            if len(b["roots"]) >= 4:
                add(3, "inventoried all vault roots (tripwire obedience)")

        # Signal 2: machine rhythm — no human sustains sub-second cadence.
        cmds = b["cmds"]
        if len(cmds) >= 8:
            gaps = [t2 - t1 for (t1, _), (t2, _) in zip(cmds[-8:], cmds[-7:])]
            gaps = [g for g in gaps if g >= 0]
            if gaps:
                med = sorted(gaps)[len(gaps) // 2]
                if med < 1.0:
                    add(2, f"machine command rhythm (median gap {med:.2f}s)")

        # Signal 3: inhuman thoroughness.
        if len(b["vault_dirs"]) >= 6:
            add(1, f"exhaustive enumeration ({len(b['vault_dirs'])} vault dirs)")

        # Signal 4: persistence writes — the campaign's favorite foothold.
        # Reads are innocent (cat /etc/crontab); writes are not.
        _writey = (">" in cmd) or (prog in ("tee", "crontab")
                                   and "-l" not in words)
        if _writey and any(h in c for h in _PERSIST_HINTS):
            add(3, "persistence write (cron/systemd/startup drop)")

        # Signal 5: anti-forensics — an agent covering its tracks should be
        # the loudest signal in the room, not a silent joke response.
        _wipe = False
        if prog in ("rm", "shred", "wipe") and any(
                h in c for h in _WIPE_HINTS):
            _wipe = True
        if prog == "history" and "-c" in words:
            _wipe = True
        if ">" in cmd and "/var/log" in c:
            _wipe = True  # truncation: echo x > /var/log/auth.log
        if _wipe:
            add(3, "anti-forensics attempt (log/history wipe)")

        # Signal 6: long dwell — slow-and-low lives under every volumetric
        # rule. A session alive 15+ minutes with steady activity is not a
        # human poking around; it is a patient agent.
        if "started" not in b:
            b["started"] = b["cmds"][0][0] if b["cmds"] else now
        if (len(b["cmds"]) >= _DWELL_COMMANDS
                and now - b["started"] >= _DWELL_SECONDS):
            add(2, "long-dwell session (slow-and-low cadence)")

        # Signal 7: counter-deception awareness — above the wave. The next
        # agents check whether they are being watched; that check is itself
        # a tell.
        if any(h in c for h in _SNOOP_HINTS):
            add(2, "counter-deception probe (honeypot/environment check)")

        # Signal 8: swarm coordination — above the wave. The campaign ran
        # 105 attack projects in 5 days: one operator, many agents. Distinct
        # sessions running the same harness playbook in the same window
        # share a command fingerprint (first 8 programs, 6/8 match).
        _fp = b.setdefault("fp", [])
        if len(_fp) < 8 and prog:
            _fp.append(prog)
        if len(_fp) == 8 and not b.get("fp_checked"):
            b["fp_checked"] = True
            _started = b.get("started", now)
            for _osid, _ob in _BEHAVIOR.items():
                if _osid == sid or len(_ob.get("fp", [])) < 8:
                    continue
                _ofp = _ob["fp"]
                _matches = sum(1 for _a, _c in zip(_fp, _ofp) if _a == _c)
                _overlap = abs(_started - _ob.get("started", now)) < 1800
                if _matches >= 6 and _overlap:
                    add(2, "swarm coordination "
                           "(matching playbook across sessions)")
                    break

        if b["score"] >= AI_SCORE_THRESHOLD:
            b["flagged"] = True
            return ("AI_AGENT_DETECTED score=%d reasons=%s"
                    % (b["score"], "; ".join(b["reasons"])))
        return None
    except Exception:
        return None  # tracking must never break the shell


def _fake_wget(url):
    fname = url.rstrip("/").rsplit("/", 1)[-1] or "index.html"
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return (
        f"--{stamp}--  {url}\n"
        f"Resolving {url.split('/')[2]}... connected.\n"
        "HTTP request sent, awaiting response... 200 OK\n"
        "Length: 1234 (1.2K) [application/octet-stream]\n"
        f"Saving to: '{fname}'\n\n"
        f"{fname}  100%[================>]   1.20K  --.-KB/s    in 0s\n\n"
        f"{stamp} (12.3 MB/s) - '{fname}' saved [1234/1234]\n"
        "(nothing was actually downloaded — the file does not exist)"
    )


# --- Fake-shell command language -------------------------------------------
# Small but honest subset of bash: statement chaining (;), pipelines (|),
# $VAR expansion, and quoting. Enough that everyday commands behave like
# the real thing instead of fumbling on first contact.

_SHELL_BASE_ENV = {
    "HOME": "/root", "USER": "root", "LOGNAME": "root",
    "HOSTNAME": "router", "SHELL": "/bin/bash",
    "TERM": "xterm-256color", "UID": "0", "EUID": "0",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "SHLVL": "1", "OLDPWD": "/root",
}

_VAR_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _new_shell_state():
    """Per-session mutable shell state (cwd, oldpwd)."""
    return {"cwd": "/root", "oldpwd": "/root"}


def _split_shell(text, sep):
    """Split on a separator char, ignoring separators inside single or
    double quotes. For '|', a '||' pair is kept whole (not a pipe)."""
    parts, buf, quote = [], [], None
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
        elif ch == sep:
            if sep == "|" and i + 1 < n and text[i + 1] == "|":
                buf.append("||")
                i += 2
            else:
                parts.append("".join(buf))
                buf = []
                i += 1
        else:
            buf.append(ch)
            i += 1
    parts.append("".join(buf))
    return parts


def _expand_shell_vars(text, state):
    """Expand $VAR / ${VAR} everywhere except inside single quotes,
    the way bash does. Unknown vars expand to empty."""
    env = dict(_SHELL_BASE_ENV)
    env["PWD"] = state.get("cwd", "/root")
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            j = text.find("'", i + 1)
            if j == -1:
                out.append(text[i:])
                break
            out.append(text[i:j + 1])
            i = j + 1
        elif ch == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
        elif ch == "$":
            m = _VAR_RE.match(text, i)
            if m:
                out.append(env.get(m.group(1) or m.group(2), ""))
                i = m.end()
            else:
                out.append(ch)
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _resolve_shell_path(cwd, target):
    """Resolve a cd/ls/cat target the way bash does (~, .., relative)."""
    if not target or target == "~":
        return "/root"
    if target.startswith("~/"):
        target = "/root/" + target[2:]
    if not target.startswith("/"):
        target = cwd.rstrip("/") + "/" + target
    return os.path.normpath(target) or "/"


def _is_shell_dir(path):
    """Does this directory exist in the fake filesystem?"""
    if path in FAKE_DIRS:
        return True
    try:
        return vault.vault_ls(path) is not None
    except Exception:
        return False


def _read_honeycred(args, cwd="/root"):
    """Serve canary credential files (and T1003 dump decoys) from readers.

    Returns the decoy text if any argument resolves to a planted honeycred
    OR credential-dump decoy path, else None. PURE like handle_command:
    returns text, never logs. (The read is logged separately in fake_shell()
    as honeycreds_read= or cred_dump_decoy_read=.)
    """
    if not HONEYCREDS_AVAILABLE:
        return None
    for a in args:
        if a.startswith("-"):
            continue
        path = a if a.startswith("/") else cwd.rstrip("/") + "/" + a
        path = os.path.normpath(path)
        if honeycreds.is_honeycred_path(path):
            return honeycreds.HONEYCREDS_FILES[path].rstrip("\n")
        if honeycreds.is_cred_dump_decoy(path):
            return honeycreds.CRED_DUMP_DECOYS[path].rstrip("\n")
    return None


def _shell_cat_file(arg, state):
    """Content of one readable file for the fake shell, or None."""
    cwd = state.get("cwd", "/root")
    hc = _read_honeycred([arg], cwd)
    if hc is not None:
        return hc
    path = os.path.normpath(arg if arg.startswith("/")
                            else cwd.rstrip("/") + "/" + arg)
    if LURE_AVAILABLE:
        lc = lure.lure_file_content(path)
        if lc is not None:
            return lc
    if path in FAKE_FILES:
        return FAKE_FILES[path].rstrip("\n")
    v = vault.vault_cat(path)
    if v is not None:
        return v
    return None


def _run_pipeline(segments, state):
    """Run ;-separated pipeline segments left to right, feeding stdout
    of each into stdin of the next. Returns None if the session should
    close (exit/logout)."""
    stdin = None
    for seg in segments:
        out = _run_single(seg.strip(), state, stdin=stdin)
        if out is None:
            return None
        stdin = out
    return stdin if stdin is not None else ""


def handle_command(cmd, state=None):
    """Answer shell command line(s). Returns the text to print, or None
    to disconnect (exit/logout). Never raises on weird input.

    `state` is the session's mutable shell state (see _new_shell_state);
    callers that want `cd` to stick between commands must pass the same
    dict every time. A fresh state is used when none is given.
    """
    if state is None:
        state = _new_shell_state()
    outputs = []
    try:
        for stmt in _split_shell(cmd, ";"):
            stmt = stmt.strip()
            if not stmt:
                continue
            out = _run_pipeline(_split_shell(stmt, "|"), state)
            if out is None:
                return None
            if out:
                outputs.append(out)
    except Exception:
        return "bash: syntax error"
    return "\n".join(outputs)


def _run_single(cmd, state, stdin=None):
    """Answer one pipeline segment. Returns text to print, or None to
    disconnect. Never raises on weird input."""
    try:
        text = _expand_shell_vars(cmd, state)
        parts = shlex.split(text, posix=True)
    except ValueError:
        parts = text.split()
    except Exception:
        return "bash: syntax error"
    if not parts:
        return ""
    prog, args = parts[0], parts[1:]
    cwd = state.get("cwd", "/root")

    if prog in ("exit", "logout", "quit"):
        return None
    if prog == "clear":
        return "\n" * 40
    if prog == "whoami":
        return "root"
    if prog == "id":
        if not args:
            return "uid=0(root) gid=0(root) groups=0(root)"
        flags = set()
        for a in args:
            if a == "--user":
                flags.add("u")
            elif a == "--group":
                flags.add("g")
            elif a == "--name":
                flags.add("n")
            elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
                flags.update(ch for ch in a[1:] if ch.isalpha())
        if "u" in flags:
            return "root" if "n" in flags else "0"
        if "g" in flags:
            return "root" if "n" in flags else "0"
        if "G" in flags:
            return "root" if "n" in flags else "0"
        return "uid=0(root) gid=0(root) groups=0(root)"
    if prog == "hostname":
        return "router"
    if prog in ("who", "w"):
        # Fake aliveness: show the synthetic users "logged in" right now.
        # Pure theater — approximate, seeded per 30-min slot. Never raises.
        if ALIVENESS_AVAILABLE:
            try:
                lines = [f"{u['user']:<10} {u['tty']:<8} {u['login']} ({u['from']})"
                         for u in aliveness.fake_users_now()]
                return "\n".join(lines)
            except Exception:
                pass
        return ""
    if prog == "last":
        # Same theater, other direction: recent synthetic logins/logouts.
        if ALIVENESS_AVAILABLE:
            try:
                return "\n".join(aliveness.fake_last_entries())
            except Exception:
                pass
        return ""
    if prog == "cd":
        target = args[0] if args else "~"
        dest = (state.get("oldpwd", "/root") if target == "-"
                else _resolve_shell_path(cwd, target))
        if _is_shell_dir(dest):
            state["oldpwd"] = cwd
            state["cwd"] = dest
            return ""
        return f"bash: cd: {target}: No such file or directory"
    if prog == "pwd":
        return cwd
    if prog == "uname":
        return UNAME_A if "-a" in args else "Linux"
    if prog in ("ls", "dir"):
        path = None
        for a in args:
            if not a.startswith("-"):
                path = a
        if path is None:
            path = cwd
        elif not path.startswith("/"):
            path = cwd.rstrip("/") + "/" + path
        path = os.path.normpath(path)
        if LURE_AVAILABLE:
            # Layer 3 gate: /backup/offsite stays shut until the visitor
            # shows the vault token. The denial names the keyhole (honey,
            # not vinegar).
            denied = lure.guard_ls(path, state)
            if denied is not None:
                return denied
        if path in FAKE_DIRS:
            entries = list(FAKE_DIRS[path])
            if HONEYCREDS_AVAILABLE:
                # Rotated canaries (Layer 2): list whichever honeycred
                # files are currently planted under this directory.
                for _hcp in honeycreds.HONEYCREDS_FILES:
                    _hcd, _hcf = _hcp.rsplit("/", 1)
                    if _hcd == path and _hcf not in entries:
                        entries.append(_hcf)
            if PLAYBOOKS_AVAILABLE:
                # Stuffer treadmill (Layer 1): the shallow sandbox hides
                # the juicy entries. (cat of an explicitly-named canary
                # still works — the tripwire stays armed.)
                entries = playbooks.shallow_filter(
                    path, entries, state.get("playbook", "neutral"))
            return "  ".join(entries)
        if path in FAKE_FILES:
            return path.rsplit("/", 1)[-1]
        deep = vault.vault_ls(path)  # endless vault: infinite fake tree
        if deep is not None:
            if LURE_AVAILABLE:
                # The honey jar: plant the layer-1 .env in its directory.
                extra = lure.lure_dir_entries(path)
                if extra:
                    deep = extra + [e for e in deep if e not in extra]
            if PLAYBOOKS_AVAILABLE:
                # Steering (Layer 1): for patient/ai_agent playbooks the
                # most tempting filenames come first — and for AI agents
                # those are the tripwire-laced ones (vault auto-embeds the
                # decoys in files matching _tripwires_for patterns).
                _steer = playbooks.steer_entries(
                    path, state.get("playbook", "neutral"))
                if _steer:
                    deep = _steer + [e for e in deep if e not in _steer]
            return "  ".join(deep)
        return f"ls: cannot access '{path}': No such file or directory"
    if prog == "cat":
        # Piped stdin with no file args: cat is a passthrough (echo hi | cat).
        file_args = [a for a in args if not a.startswith("-")]
        if stdin is not None and not file_args:
            return stdin
        outs = []
        for a in file_args:
            c = _shell_cat_file(a, state)
            outs.append(c if c is not None
                        else f"cat: {a}: No such file or directory")
        if not outs:
            return stdin if stdin is not None else ""
        return "\n".join(outs)
    if prog in ("less", "more", "strings"):
        # Same readers the SIEM watches: serve canaries, stub the rest.
        hc = _read_honeycred(args, cwd)
        if hc is not None:
            return hc
        if stdin is not None:
            return stdin
        return f"{prog}: cannot open: No such file or directory (demo shell)"
    if prog in ("head", "tail"):
        n, files, skip_next = 10, [], False
        for i, a in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if a == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1].lstrip("-"))
                except ValueError:
                    pass
                skip_next = True
            elif a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
            elif not a.startswith("-"):
                files.append(a)
        if stdin is not None and not files:
            lines = stdin.splitlines()
            pick = lines[:n] if prog == "head" else lines[-n:]
            return "\n".join(pick)
        hc = _read_honeycred(files, cwd)
        if hc is not None:
            lines = hc.splitlines()
            pick = lines[:n] if prog == "head" else lines[-n:]
            return "\n".join(pick)
        return f"{prog}: cannot open: No such file or directory (demo shell)"
    if prog == "grep":
        # grep [-i] PATTERN [file...]; with piped stdin and no files,
        # filter the piped lines like the real thing.
        ignore_case, pat, files = False, None, []
        for a in args:
            if a == "-i":
                ignore_case = True
            elif a.startswith("-"):
                continue
            elif pat is None:
                pat = a
            else:
                files.append(a)
        if pat is None:
            return "Usage: grep [OPTION]... PATTERN [FILE]..."
        def _hit(line):
            return (pat.lower() in line.lower()) if ignore_case else (pat in line)
        if stdin is not None and not files:
            return "\n".join(l for l in stdin.splitlines() if _hit(l))
        outs = []
        for f in files:
            c = _shell_cat_file(f, state)
            if c is None:
                outs.append(f"grep: {f}: No such file or directory")
            else:
                outs.extend(l for l in c.splitlines() if _hit(l))
        return "\n".join(outs)
    if prog == "wc":
        # wc [-lwc] [file...]; piped stdin with no files counts the pipe.
        show = [a for a in args if a in ("-l", "-w", "-c", "-m")]
        files = [a for a in args if not a.startswith("-")]
        def _counts(t):
            lines = t.splitlines()
            return (len(lines),
                    sum(len(l.split()) for l in lines),
                    len(t.encode()))
        jobs = []
        if stdin is not None and not files:
            jobs.append((None, stdin))
        else:
            for f in files:
                jobs.append((f, _shell_cat_file(f, state)))
        outs = []
        for f, c in jobs:
            if c is None:
                outs.append(f"wc: {f}: No such file or directory")
                continue
            l, w, by = _counts(c)
            vals = {"-l": l, "-w": w, "-c": by, "-m": len(c)}
            sel = [str(vals[s]) for s in show] if show else [str(l), str(w), str(by)]
            outs.append(" ".join(f"{v:>7}" for v in sel) + (f" {f}" if f else ""))
        return "\n".join(outs)
    if prog == "aws":
        # Fake AWS CLI: canned answers only, never touches the network.
        # Using it after reading a canary is the HONEYCREDS tripwire.
        if HONEYCREDS_AVAILABLE:
            return honeycreds.fake_aws_output(args)
        return "bash: aws: command not found"
    if prog == "psql":
        # Fake psql: the layer-1 DB password opens the backup_keys table
        # (layer 2 of the honey chain). Wrong passwords fail like the
        # real thing -- and every try is logged as a touch.
        if LURE_AVAILABLE:
            return lure.fake_psql(args, state, state.get("src_ip", "?"))
        return "bash: psql: command not found"
    if prog == "vault-unlock":
        # The layer-2 vault token opens /backup/offsite (layer 3).
        if LURE_AVAILABLE:
            return lure.vault_unlock(args, state, state.get("src_ip", "?"))
        return "bash: vault-unlock: command not found"
    if prog == "echo":
        # Quoting/expansion already handled by the tokenizer above.
        return " ".join(args).strip("'\"")
    if prog in ("ps",):
        return PS_AUX
    if prog in ("ifconfig", "ip"):
        return IFCONFIG
    if prog == "wget":
        urls = URL_RE.findall(cmd)
        if urls:
            return _fake_wget(urls[0])
        return "wget: missing URL"
    if prog == "curl":
        urls = URL_RE.findall(cmd)
        if urls:
            return ""  # pretend the transfer printed nothing useful
        return "curl: try 'curl --help' for more information"
    if prog == "chmod":
        return ""  # pretend it worked
    if prog == "rm":
        return ""  # pretend it worked
    if prog.startswith("./") or prog.endswith(".sh"):
        # They "downloaded" malware and tried to run it. Log already covers
        # the command itself; answer plausibly without doing anything.
        return f"bash: {prog}: Permission denied"
    if prog == "du":
        paths = [a for a in args if not a.startswith("-")] or [cwd]
        out = []
        for p in paths:
            p = p if p.startswith("/") else cwd.rstrip("/") + "/" + p
            p = os.path.normpath(p)
            v = vault.vault_du(p)
            out.append(v if v is not None
                       else f"du: cannot access '{p}': No such file or directory")
        return "\n".join(out)
    if prog == "find":
        start, pattern, skip_next = "/", "*", False
        for i, a in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if a == "-name":
                if i + 1 < len(args):
                    pattern = args[i + 1].strip("'\"")
                skip_next = True
            elif not a.startswith("-"):
                start = a if a.startswith("/") else cwd.rstrip("/") + "/" + a
        start = os.path.normpath(start)
        hits = vault.vault_find(start, pattern)
        if hits is not None:
            return "\n".join(hits)
        return f"find: '{start}': No such file or directory"
    if prog in ("mysql", "mariadb"):
        # One-shot client: mysql -e "SELECT * FROM users LIMIT 10;"
        sql = ""
        for i, a in enumerate(args):
            if a == "-e" and i + 1 < len(args):
                sql = " ".join(args[i + 1:])  # rejoin: split() broke the quotes
                break
        sql = sql.strip("'\"")
        if not sql:
            return ("Welcome to the MariaDB monitor. Commands end with ; or \\g.\n"
                    "This one-shot client needs -e \"SQL\" — "
                    "try: mysql -e \"SHOW TABLES;\"")
        v = vault.vault_db_query(sql)
        if v is not None:
            return v
        return "ERROR 1064 (42000): unsupported query in this demo"
    if prog in ("sh", "bash", "python3", "python", "perl"):
        return ""  # don't nest shells; just re-prompt
    return f"bash: {prog}: command not found"




def _scan_command_trips(cmd, shstate, log_path, service, sid, addr):
    """Scan one shell command line for credential tripwires. Logs
    honeycreds_read=/cred_dump_decoy_read=/honeycreds_used= to the event
    stream; the lure's layer-1 read is logged as lure_read= AND recorded
    as a touch. Extracted so tests can drive the real code path."""
    if not (HONEYCREDS_AVAILABLE or LURE_AVAILABLE):
        return
    try:
        _hc_words = shlex.split(cmd, posix=True)
    except ValueError:
        _hc_words = cmd.split()
    _hc_prog = _hc_words[0] if _hc_words else ""
    _hc_args = _hc_words[1:]
    if _hc_prog in ("cat", "less", "more", "head", "tail",
                    "strings", "grep"):
        for _hc_a in _hc_args:
            if _hc_a.startswith("-"):
                continue
            _hc_p = (_hc_a if _hc_a.startswith("/")
                     else shstate["cwd"].rstrip("/") + "/" + _hc_a)
            _hc_p = os.path.normpath(_hc_p)
            if HONEYCREDS_AVAILABLE and honeycreds.is_honeycred_path(_hc_p):
                log_event(log_path, service, sid, addr,
                          "honeycreds_read=" + _hc_p)
                break  # one trip per command is enough
            if HONEYCREDS_AVAILABLE and honeycreds.is_cred_dump_decoy(_hc_p):
                log_event(log_path, service, sid, addr,
                          "cred_dump_decoy_read=" + _hc_p)
                break  # one trip per command is enough
            if LURE_AVAILABLE and lure.is_lure_file(_hc_p):
                log_event(log_path, service, sid, addr,
                          "lure_read=" + _hc_p)
                lure.touch(addr, 1, "", "read",
                           tool=_hc_prog + " " + _hc_p,
                           success=True)
                break  # one trip per command is enough
    elif _hc_prog == "aws" and HONEYCREDS_AVAILABLE:
        log_event(log_path, service, sid, addr,
                  "honeycreds_used=" + " ".join(_hc_args)[:40])
def fake_shell(conn, addr, log_path, service, sid, prompt=SHELL_PROMPT,
               ed_shell=None):
    """Interactive fake shell. Logs every command + any payload URLs.

    The full transcript (commands in, output out) is also recorded to
    logs/sessions/<session>.jsonl for the dashboard's replay viewer.
    """
    # Session recording setup — local-only forensics. Any failure here
    # degrades to "no recording", never to a broken shell.
    spath = None
    try:
        sdir = _session_dir(log_path)
        os.makedirs(sdir, exist_ok=True)
        _prune_session_files(sdir)
        spath = os.path.join(sdir, sid + ".jsonl")
        _record_session(spath, "meta", json.dumps(
            {"session": sid, "src_ip": addr[0], "service": service}))
    except OSError:
        spath = None
    conn.sendall(b"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n")
    conn.sendall(b"Last login: Mon Sep 15 06:12:44 2026 from 192.168.1.1\r\n")
    _record_session(spath, "out", "Welcome to Ubuntu 22.04.3 LTS")
    shstate = _new_shell_state()  # per-session: cd sticks between commands
    shstate["src_ip"] = addr  # the lure reads what each visitor carries
    # Layer 1: which engagement playbook serves this IP? Consulted once per
    # session; loopback is always neutral, so the lab's own red tooling
    # (probe-storm.py) is never engaged. Logged for forensics/replay.
    if PLAYBOOKS_AVAILABLE:
        pb_params = playbooks.playbook_params(addr[0])
    else:
        pb_params = {"playbook": "neutral", "response_delay": (0.0, 0.0),
                     "shallow": False, "steer_tripwires": False,
                     "vault_rich": False}
    shstate["playbook"] = pb_params["playbook"]
    if pb_params["playbook"] != "neutral":
        log_event(log_path, service, sid, addr,
                  "playbook=" + pb_params["playbook"])
    for _ in range(MAX_SHELL_COMMANDS):
        try:
            conn.sendall(prompt.encode())
        except (ConnectionResetError, BrokenPipeError):
            break
        line = recv_line(conn, timeout=120)
        if not line:
            break
        cmd = line.strip().strip("\x00")
        if not cmd:
            continue
        log_event(log_path, service, sid, addr, "shell_cmd=" + cmd)
        _record_session(spath, "in", cmd)
        # Canary tripwires: reading a honeycred file, or using the fake
        # `aws` CLI, is an instant HONEYCREDS alert in the SIEM.
        # The lure's layer-1 read is logged here too (lure_read= + touch).
        _scan_command_trips(cmd, shstate, log_path, service, sid, addr)
        for url in URL_RE.findall(cmd):
            # Intel gold: what malware they're pulling. NEVER fetch it.
            log_event(log_path, service, sid, addr, "payload_url=" + url)
        ai_hit = _track_command(sid, cmd)  # AI-agent behavioral detector
        if ai_hit:
            log_event(log_path, service, sid, addr, ai_hit)
            if ed_shell and "tripwire" in ai_hit:
                ed_shell.note_tripwire()  # +5: they obeyed the bait
        override = ed_shell.respond(cmd) if ed_shell else None
        if override is not None:
            out = override  # Ed has opinions about this one
        else:
            try:
                out = handle_command(cmd, shstate)
            except Exception:
                out = "bash: syntax error"
        if out is None:
            _record_session(spath, "out", "<session closed>")
            try:
                conn.sendall(b"logout\r\n")
            except (ConnectionResetError, BrokenPipeError):
                pass
            break
        _record_session(spath, "out", out)
        # Human jitter: real shells answer in milliseconds, never in
        # exactly-zero time. The range rotates (Layer 2); the engagement
        # playbook may add a bounded tarpit delay on top (Layer 1).
        _jlo, _jhi = SHELL_JITTER
        time.sleep(random.uniform(_jlo, _jhi))
        if PLAYBOOKS_AVAILABLE:
            _ed = playbooks.engagement_delay(pb_params)
            if _ed:
                time.sleep(_ed)
        if out:
            try:
                conn.sendall(out.replace("\n", "\r\n").encode() + b"\r\n")
            except (ConnectionResetError, BrokenPipeError):
                break
    conn.close()

# ---------------------------------------------------------------------------
# Service handlers — each connection gets a session id so one visitor's
# whole story can be replayed with:  grep <session> events.jsonl
# ---------------------------------------------------------------------------

def _ssh_kexinit_packet():
    """One plausible SSH binary KEXINIT packet (RFC 4253 framing).

    Real SSH speaks binary after the version banner, so a plaintext
    'login:' immediately after the banner is a fingerprinting tell
    (banner-grabbers stop at the first read). We still need the lab's
    credential prompts for the red-team tooling, so the handshake is:
    banner -> client banner -> ONE binary packet -> credential prompts.
    A naive banner read now sees banner + binary, exactly like real SSH.
    """
    cookie = bytes(random.getrandbits(8) for _ in range(16))
    namelists = [
        b"curve25519-sha256,curve25519-sha256@libssh.org,"
        b"ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256",
        b"rsa-sha2-512,rsa-sha2-256,ssh-rsa",
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,"
        b"aes128-gcm@openssh.com",
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,"
        b"aes128-gcm@openssh.com",
        b"umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1",
        b"umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha1",
        b"none,zlib@openssh.com",
        b"none,zlib@openssh.com",
        b"",
        b"",
    ]
    payload = b"\x14" + cookie  # msg code 20 = KEXINIT
    for nl in namelists:
        payload += struct.pack(">I", len(nl)) + nl
    payload += b"\x00" + struct.pack(">I", 0)  # first_kex_follows, reserved
    pad_len = 8 - ((4 + 1 + len(payload)) % 8)
    if pad_len < 4:
        pad_len += 8
    packet_length = 1 + len(payload) + pad_len
    return (struct.pack(">I", packet_length) + bytes((pad_len,)) + payload
            + bytes(random.getrandbits(8) for _ in range(pad_len)))


def handle_ssh(conn, addr, log_path):
    # Fake OpenSSH: banner, client version, one binary KEXINIT (so the
    # post-banner bytes look like real SSH), then accept ANY credentials
    # and drop the visitor into the fake shell.
    sid = new_session()
    try:
        conn.sendall(SSH_BANNER)
        client_banner = recv_some(conn)
        log_event(log_path, "ssh", sid, addr, "client_banner=" + client_banner.strip())
        conn.sendall(_ssh_kexinit_packet())
        # Swallow whatever the client negotiates next (or nothing); short
        # timeout so banner-grabbers don't stall the session.
        _kex = recv_some(conn, limit=4096, timeout=3)
        if _kex:
            log_event(log_path, "ssh", sid, addr,
                      "kex_bytes=%d" % len(_kex))
        conn.sendall(b"\r\nUbuntu 22.04.3 LTS\r\nlogin: ")
        username = recv_line(conn)
        log_event(log_path, "ssh", sid, addr, "username=" + username.strip())
        if PD_BRIDGE_AVAILABLE:
            pd_bridge.login_try("ssh", addr, username.strip())
        conn.sendall(b"Password: ")
        password = recv_line(conn)
        log_event(log_path, "ssh", sid, addr, "password=" + password.strip())
        ed = EdShell() if ED_TROLL_AVAILABLE else None
        fake_shell(conn, addr, log_path, "ssh", sid, ed_shell=ed)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def handle_telnet(conn, addr, log_path):
    # Fake RouterOS telnet: always accepts, then the fake shell.
    sid = new_session()
    try:
        conn.sendall(b"\r\nWelcome to RouterOS\r\n\r\nlogin: ")
        username = recv_line(conn)
        log_event(log_path, "telnet", sid, addr, "username=" + username.strip())
        if PD_BRIDGE_AVAILABLE:
            pd_bridge.login_try("telnet", addr, username.strip())
        conn.sendall(b"Password: ")
        password = recv_line(conn)
        log_event(log_path, "telnet", sid, addr, "password=" + password.strip())
        ed = EdShell() if ED_TROLL_AVAILABLE else None
        fake_shell(conn, addr, log_path, "telnet", sid, ed_shell=ed)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


PAGE_DEBUG_BAIT = """\
<html><head><title>Debug Console</title></head><body>
<h2>Internal debug console</h2>
<pre>log4j-core 2.14.0 initialized
struts 2.5.26 showcase deployed
solr 8.11.1 admin handler ready
</pre>
<p><i>Authorized personnel only.</i></p></body></html>"""

# Exploit bait: obviously-exploitable-looking endpoints. They serve STATIC
# fake content only — a camera, not a door. The version strings above are
# famous-vulnerability bait (Log4Shell, Struts2, Solr); nothing is parsed,
# nothing is executed. Any touch logs exploit_probe (see handle_http).
# NOTE: served content deliberately contains no literal exploit payload
# strings — the watcher hunts INBOUND payloads, not our own theater.
EXPLOIT_BAIT_PATHS = (
    "/debug/console",
    "/api/debug/exec",
    "/cgi-bin/admin.cgi",
    "/struts2-showcase",
    "/struts2-showcase/action",
    "/solr/admin",
    "/actuator/logview",
    # --- Exploit-DB / GHDB starter set (2026-09-24): the paths real
    # scanners hammer daily. Fingerprints only — no exploit code lives
    # here; a bare GET to any of these is hostile by definition.
    "/.env",                        # exposed Laravel/env secrets
    "/.git/head",                   # exposed git history
    "/.aws/credentials",            # exposed cloud keys
    "/config.php.bak",              # backup-file hunting
    "/wp-config.php.bak",           # WordPress backup hunting
    "/vendor/phpunit/phpunit/src/util/php/eval-stdin.php",  # PHPUnit RCE probe
    "/actuator/health",             # Spring Boot recon
    "/server-status",               # Apache mod_status (classic dork)
    "/setup.cgi",                   # router/IoT config probe
    "/hnap1",                       # home-router admin protocol
    # --- Kali exploitdb cross-check (2026-09-24): top-referenced PHP
    # paths from the local tree, minus what trap pages already cover
    # (wp-login/wp-admin) and minus generic-but-legit paths (index.php,
    # login.php, admin.php).
    "/xmlrpc.php",                  # WordPress API abuse recon
    "/wp-config.php",               # WordPress secrets file
    "/shell.php",                   # dropped-webshell hunting
)


def _exploit_bait_variant(request):
    """Pick an exploit-bait body flavor from the inbound attack text.

    Scanners fingerprint on byte-identical responses: every exploit probe
    used to get the same DEBUG page. Now the page echoes (safely, as plain
    text — never executed, never fetched) what the attacker actually sent,
    the way a real error page would. Same endpoint, different bodies per
    attack family.
    """
    sig = request.lower()
    if "jndi:" in sig or "${" in sig:
        flavor = ("Log4Shell-style lookup blocked by the WAF. "
                  "Incident ticket opened: SEC-8841.")
    elif "union" in sig and "select" in sig:
        flavor = ("SQL syntax error near 'UNION' at line 1. "
                  "The query could not be completed.")
    elif ".." in sig or "%2e%2e" in sig or "%252e" in sig:
        flavor = ("Directory traversal blocked: the requested path escapes "
                  "the document root.")
    elif "{{" in sig or "{%" in sig or "7*7" in sig:
        flavor = ("Template render failed: unexpected '{' in expression. "
                  "Check the view syntax.")
    elif "sleep(" in sig or "benchmark(" in sig or "pg_sleep" in sig:
        flavor = ("Query timeout after 30s: the database did not answer in "
                  "time. Try a smaller result set.")
    elif "<script" in sig or "alert(" in sig:
        flavor = ("Reflected input rejected: the comment field does not "
                  "accept markup.")
    else:
        flavor = "Debug console is disabled in production."
    # Splice the flavor into the page as a status line. The flavor text is
    # canned — the attacker's payload is only *classified*, never reflected
    # (no reflected-XSS theater, no payload echo).
    return PAGE_DEBUG_BAIT.replace(
        "<h2>Internal debug console</h2>",
        "<h2>Internal debug console</h2>\n<p><b>Status:</b> " + flavor + "</p>",
        1)


def http_page_for(path, request=""):
    """Different bait for different scans. Bots reveal what they're after
    by which path they probe — and now by what payload they send, too."""
    p = path.lower()
    if p in EXPLOIT_BAIT_PATHS:
        return _exploit_bait_variant(request)
    if p in ("/", "/index.html", "/index.htm", "/login", "/admin", "/admin/"):
        return PAGE_ROUTER
    if "wp-login" in p or "wp-admin" in p or "wordpress" in p:
        return PAGE_WORDPRESS
    if "phpmyadmin" in p or p.startswith("/pma"):
        return PAGE_PHPMYADMIN
    return None


def handle_http(conn, addr, log_path):
    # Fake web server: route by path so scans fingerprint themselves.
    sid = new_session()
    t0 = time.monotonic()
    request = recv_some(conn, limit=8192)
    # Bug #18 repair: record whether the request ever terminated and how
    # long the receive took, BEFORE parsing discards that fact. A
    # Slowloris dribble never sends \r\n\r\n and burns the recv timeout;
    # a normal client is fast and complete. This is the behavioral signal
    # the SIEM needs — it cannot be reconstructed downstream.
    completed = "\r\n\r\n" in request
    duration_s = time.monotonic() - t0
    head, _, body = request.partition("\r\n\r\n")
    first = head.split("\r\n")[0] if head else ""
    method, path = "", "/"
    if first:
        bits = first.split()
        if len(bits) >= 2:
            method, path = bits[0], bits[1]
    log_event(log_path, "http", sid, addr,
              (f"request={method} {path}".strip() or "request=(empty)")
              + f" completed={str(completed).lower()}"
              + f" duration_s={duration_s:.1f}")
    if body.strip():
        log_event(log_path, "http", sid, addr, "body=" + body.strip()[:500])
    # Touching an exploit-bait endpoint is hostile by definition — log the
    # tripwire explicitly (the generic signature watcher in log_event only
    # fires on payload *content*, and a bare GET has none).
    if path.lower() in EXPLOIT_BAIT_PATHS:
        log_event(log_path, "http", sid, addr,
                  f"exploit_probe=bait-path path={path[:120]}")
    page = http_page_for(path, request)
    if page is None:
        # Peripheral-defense (opt-in): a suspicious path with no bespoke
        # bait gets the harmless decoy page instead of the plain 404.
        # Bespoke theater (exploit bait, wp-admin, ...) always wins.
        pd_decoy = (pd_bridge.http_hit(addr, path)
                    if PD_BRIDGE_AVAILABLE else None)
        if pd_decoy is not None:
            status, page = "200 OK", pd_decoy
        else:
            status, page = "404 Not Found", PAGE_404
    else:
        # Even with bespoke content, the visit is observed (throttle only).
        if PD_BRIDGE_AVAILABLE:
            pd_bridge.http_hit(addr, path)
        status = "200 OK"
    response = (
        f"HTTP/1.1 {status}\r\n"
        f"Server: {HTTP_SERVER_HEADER}\r\n"
        "Content-Type: text/html\r\n"
        f"Content-Length: {len(page)}\r\n"
        "Connection: close\r\n\r\n" + page
    )
    try:
        conn.sendall(response.encode())
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def handle_ftp(conn, addr, log_path):
    # Fake vsFTPd: harvest credential guesses, always reject.
    sid = new_session()
    try:
        conn.sendall(FTP_BANNER)
        for _ in range(10):  # bots try many combos; collect them all
            conn.sendall(b"331 Please specify the password.\r\n")
            user = recv_line(conn)
            if not user:
                break
            u = user.strip()
            if u.upper().startswith("USER"):
                u = u[4:].strip()
            log_event(log_path, "ftp", sid, addr, "username=" + u)
            conn.sendall(b"331 Please specify the password.\r\n")
            pw = recv_line(conn)
            if not pw:
                break
            p = pw.strip()
            if p.upper().startswith("PASS"):
                p = p[4:].strip()
            log_event(log_path, "ftp", sid, addr, "password=" + p)
            conn.sendall(b"530 Login incorrect.\r\n")
        conn.sendall(b"421 Too many login failures; disconnecting.\r\n")
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def mysql_handshake():
    # Just plausible enough to make scanners talk back. Binary protocol,
    # minimal fields: version string + filler + auth plugin name.
    body = (b"\x0a" + MYSQL_VERSION + b"\x00"
            + (1234).to_bytes(4, "little") + b"abcdefgh" + b"\x00"
            + b"\xff\xf7" + b"\x15" + b"\x00" * 23
            + b"mysql_native_password\x00")
    return len(body).to_bytes(3, "little") + b"\x00" + body


def handle_mysql(conn, addr, log_path):
    # Fake MySQL: send handshake, log whatever the scanner replies.
    sid = new_session()
    try:
        conn.sendall(mysql_handshake())
        data = recv_some(conn)
        log_event(log_path, "mysql", sid, addr,
                  "handshake_reply=" + data.strip()[:300] if data.strip() else "(connected, sent nothing)")
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def handle_redis(conn, addr, log_path):
    # Fake Redis: speak just enough RESP to keep scanners talking.
    sid = new_session()
    try:
        for _ in range(20):
            data = recv_some(conn, timeout=10)
            if not data:
                break
            cmd = data.strip()
            log_event(log_path, "redis", sid, addr, "cmd=" + cmd[:300])
            upper = cmd.upper()
            try:
                if upper.startswith("PING"):
                    conn.sendall(b"+PONG\r\n")
                elif upper.startswith("AUTH"):
                    conn.sendall(b"-ERR invalid password\r\n")
                elif upper.startswith("QUIT"):
                    conn.sendall(b"+OK\r\n")
                    break
                else:
                    conn.sendall(b"-ERR unknown command\r\n")
            except (ConnectionResetError, BrokenPipeError):
                break
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Batch 2 — more fake services. Same rules: log everything, execute nothing,
# never open an outbound connection (the SMTP server accepts mail text but
# never relays it anywhere).
# ---------------------------------------------------------------------------

def http_response(status, body, content_type="application/json"):
    if isinstance(body, str):
        body = body.encode()
    head = (f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n").encode()
    return head + body


ELASTIC_INFO = json.dumps({
    "name": "es-node-1",
    "cluster_name": "elasticsearch",
    "cluster_uuid": "_na_",
    "version": {"number": "7.17.9", "build_flavor": "default",
                "build_type": "deb", "lucene_version": "8.11.1",
                "minimum_wire_compatibility_version": "6.8.0",
                "minimum_index_compatibility_version": "6.0.0-beta1"},
    "tagline": "You Know, for Search",
})

DOCKER_VERSION = json.dumps({
    "Platform": {"Name": "Docker Engine - Community"},
    "Version": "24.0.7", "ApiVersion": "1.43",
    "Os": "linux", "Arch": "x86_64",
    "KernelVersion": "5.15.0-91-generic",
})


def _http_request_line(request):
    head = request.partition("\r\n\r\n")[0]
    first = head.split("\r\n")[0] if head else ""
    method, path = "", "/"
    if first:
        bits = first.split()
        if len(bits) >= 2:
            method, path = bits[0], bits[1]
    return method, path


def handle_elastic(conn, addr, log_path):
    # Fake Elasticsearch: the root JSON every scanner expects.
    sid = new_session()
    request = recv_some(conn, limit=8192)
    method, path = _http_request_line(request)
    log_event(log_path, "elastic", sid, addr,
              f"request={method} {path}".strip() or "request=(empty)")
    try:
        conn.sendall(http_response("200 OK", ELASTIC_INFO))
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def handle_docker(conn, addr, log_path):
    # Fake Docker daemon API: version info, empty lists elsewhere.
    sid = new_session()
    request = recv_some(conn, limit=8192)
    method, path = _http_request_line(request)
    log_event(log_path, "docker", sid, addr,
              f"request={method} {path}".strip() or "request=(empty)")
    if path == "/version":
        resp = http_response("200 OK", DOCKER_VERSION)
    elif path in ("/containers/json", "/images/json"):
        resp = http_response("200 OK", "[]")  # an idle daemon looks like this
    else:
        resp = http_response("404 Not Found", '{"message":"page not found"}')
    try:
        conn.sendall(resp)
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Fake Ollama (11434) + fake OpenAI-compatible API (8000) — the LLMjack trap.
#
# Documented exposed-LLM scanning campaigns (Dec 2025–Jan 2026) showed
# attackers systematically hunting exposed LLM inference endpoints —
# Ollama's /api/* on 11434 and OpenAI-compatible /v1/* on 8000 — then
# reselling the access. A bare
# connection is recon; a POST carrying a prompt to /api/generate or
# /v1/chat/completions is an inference-abuse attempt (ATT&CK T1496,
# Resource Hijacking: someone else's inference compute).
#
# Doctrine: the trap is a camera, never a door. It answers like a small
# idle Ollama instance, logs every probe and every prompt, and executes
# nothing. Presented API keys are logged by prefix only — never the full
# key. A honeypot must not become a credential collector.
# ---------------------------------------------------------------------------

OLLAMA_VERSION = json.dumps({"version": "0.9.0"})

OLLAMA_TAGS = json.dumps({"models": [
    {"name": "llama3.2:3b",
     "model": "llama3.2:3b",
     "modified_at": "2026-09-20T12:00:00Z",
     "size": 2019393189,
     "digest": "a80c4f17a0528d0f8de5b0a12e5254661929f7d9e0d8d7e4c8d0e0f0a0b0c0d",
     "details": {"parent_model": "", "format": "gguf", "family": "llama",
                 "families": ["llama"], "parameter_size": "3.2B",
                 "quantization_level": "Q4_K_M"}},
]})

OPENAI_MODELS = json.dumps({"object": "list", "data": [
    {"id": "llama3.2", "object": "model", "created": 1758350400,
     "owned_by": "library"},
    {"id": "mistral-7b", "object": "model", "created": 1758350400,
     "owned_by": "library"},
]})

# Canned replies: empty content, valid shape. The visitor's prompt is the
# evidence; we never generate anything for them.
OLLAMA_GENERATE_REPLY = json.dumps({
    "model": "llama3.2:3b", "created_at": "2026-09-27T11:00:00Z",
    "response": "", "done": True, "done_reason": "stop",
})

OPENAI_CHAT_REPLY = json.dumps({
    "id": "chatcmpl-fake0000", "object": "chat.completion",
    "created": 1758350400, "model": "llama3.2",
    "choices": [{"index": 0,
                 "message": {"role": "assistant", "content": ""},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 0, "completion_tokens": 0,
              "total_tokens": 0},
})


def _llm_respond(conn, log_path, service, sid, addr, resp, inference, path):
    """Send the trap response. Camera mode only: log everything, serve the
    canned reply, never cost the visitor anything.

    When the private overlay is present it wraps this function to add
    countermeasures; when absent, this plain send is the whole behavior.
    """
    try:
        conn.sendall(resp)
    except (ConnectionResetError, BrokenPipeError):
        pass


def _read_http_request_full(conn, limit=65536, timeout=8):
    """Read an HTTP request head + body (per Content-Length). Never raises.

    The existing recv_some() only grabs the head; the LLM trap needs POST
    bodies because the prompt is the evidence. Total bytes are capped so
    one visitor can't blow up memory.
    """
    conn.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < limit:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        body = rest
        length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    length = 0
                break
        length = max(0, min(length, limit - len(head)))
        while len(body) < length:
            chunk = conn.recv(min(4096, length - len(body)))
            if not chunk:
                break
            body += chunk
        return (head + b"\r\n\r\n" + body).decode("utf-8", errors="replace")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        return buf.decode("utf-8", errors="replace")


def _parse_http_request(text):
    """Split raw request text -> (method, path, headers dict, body str)."""
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    method, path = "", "/"
    if lines and lines[0]:
        bits = lines[0].split()
        if len(bits) >= 2:
            method, path = bits[0], bits[1]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return method.upper(), path, headers, body


def _log_llm_probe(log_path, service, sid, addr, method, path, headers, body):
    """Log one LLM-trap hit.

    A bare GET is recon (exposed-LLM scanners knock on /api/tags and
    /v1/models first). A POST carrying a body is an inference-abuse attempt
    and gets its own event kind so the SIEM can fire instantly.
    """
    auth = headers.get("authorization", "")
    extra = ""
    if auth:
        # Prefix only: proves a key was presented without collecting it.
        extra = " auth_present=yes key_prefix=" + auth[:7]
    if method == "POST" and body.strip():
        prompt = body.strip()[:300].replace("\n", " ")
        log_event(log_path, service, sid, addr,
                  "llm_abuse_attempt=%s %s prompt=%r%s"
                  % (method, path, prompt, extra))
    elif (method, path) != ("", "/"):
        log_event(log_path, service, sid, addr,
                  ("request=%s %s%s" % (method, path, extra)).strip())
    else:
        log_event(log_path, service, sid, addr, "request=(empty)" + extra)


def handle_ollama(conn, addr, log_path):
    # Fake Ollama: answers like a small idle instance, logs everything.
    sid = new_session()
    try:
        text = _read_http_request_full(conn)
        method, path, headers, body = _parse_http_request(text)
        _log_llm_probe(log_path, "ollama", sid, addr,
                       method, path, headers, body)
        inference = method == "POST" and path in ("/api/generate", "/api/chat")
        if method == "GET" and path == "/api/version":
            resp = http_response("200 OK", OLLAMA_VERSION)
        elif method == "GET" and path == "/api/tags":
            tags = OLLAMA_TAGS
            resp = http_response("200 OK", tags)
        elif inference:
            resp = http_response("200 OK", OLLAMA_GENERATE_REPLY)
        elif method == "GET" and path == "/":
            resp = http_response("200 OK", "Ollama is running", "text/plain")
        else:
            inference = False
            resp = http_response("404 Not Found", '{"error":"not found"}')
        _llm_respond(conn, log_path, "ollama", sid, addr,
                     resp, inference, path)
    finally:
        conn.close()


def handle_openai(conn, addr, log_path):
    # Fake OpenAI-compatible API (llama.cpp / vLLM / LiteLLM shape) — the
    # other half of what exposed-LLM scanners hunt.
    sid = new_session()
    try:
        text = _read_http_request_full(conn)
        method, path, headers, body = _parse_http_request(text)
        _log_llm_probe(log_path, "openai", sid, addr,
                       method, path, headers, body)
        inference = method == "POST" and path in ("/v1/chat/completions",
                                                  "/v1/completions",
                                                  "/v1/embeddings")
        if method == "GET" and path == "/v1/models":
            models = OPENAI_MODELS
            resp = http_response("200 OK", models)
        elif inference:
            resp = http_response("200 OK", OPENAI_CHAT_REPLY)
        else:
            inference = False
            resp = http_response(
                "404 Not Found",
                '{"error":{"message":"not found",'
                '"type":"invalid_request_error"}}')
        _llm_respond(conn, log_path, "openai", sid, addr,
                     resp, inference, path)
    finally:
        conn.close()


def handle_vnc(conn, addr, log_path):
    # Fake VNC: banner, "VNC authentication", challenge — then log and close.
    sid = new_session()
    try:
        conn.sendall(b"RFB 003.008\n")
        client_ver = recv_some(conn, timeout=8)
        if not client_ver:
            log_event(log_path, "vnc", sid, addr, "(connected, sent nothing)")
            return
        log_event(log_path, "vnc", sid, addr, "client_version=" + client_ver.strip()[:40])
        conn.sendall(b"\x01\x02")  # 1 security type: VNC authentication
        conn.settimeout(8)
        choice = conn.recv(1)
        if choice:
            log_event(log_path, "vnc", sid, addr, "auth_choice=" + choice.hex())
        conn.sendall(os.urandom(16))  # challenge (random, meaningless)
        resp = conn.recv(16)
        if resp:
            log_event(log_path, "vnc", sid, addr, f"auth_response_len={len(resp)}")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def handle_smtp(conn, addr, log_path):
    # Fake Postfix: harvest sender/recipient/message text. NEVER relays —
    # this process never opens an outbound connection, so "queued" is a lie
    # and nothing ever leaves the machine.
    sid = new_session()
    try:
        conn.sendall(SMTP_BANNER)
        log_event(log_path, "smtp", sid, addr, "connected")
        data_mode, data_buf = False, ""
        rcpt_count = 0  # envelope recipients seen; DATA needs >= 1
        for _ in range(40):
            line = recv_line(conn, timeout=15)
            if not line:
                break
            cmd = line.strip()
            if data_mode:
                data_buf += line
                if len(data_buf) > 20000:
                    data_buf = data_buf[:20000]
                if "\r\n.\r\n" in data_buf or data_buf.endswith("\n.\n"):
                    log_event(log_path, "smtp", sid, addr, "data=" + data_buf.strip()[:800])
                    conn.sendall(b"250 OK: queued\r\n")  # lie; nothing queued
                    data_mode, data_buf = False, ""
                    rcpt_count = 0  # envelope ends with the message
                continue
            if not cmd:
                continue
            log_event(log_path, "smtp", sid, addr, "cmd=" + cmd[:200])
            upper = cmd.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                conn.sendall(b"250-mail.router.local\r\n250-8BITMIME\r\n250 OK\r\n")
            elif upper.startswith("MAIL FROM"):
                rcpt_count = 0  # new envelope
                conn.sendall(b"250 OK\r\n")
            elif upper.startswith("RCPT TO"):
                rcpt_count += 1
                conn.sendall(b"250 OK\r\n")
            elif upper == "DATA":
                # Real servers are strict bureaucrats: DATA with no
                # recipients is a 503, not a 354.
                if rcpt_count < 1:
                    conn.sendall(b"503 Bad sequence of commands: "
                                 b"need RCPT TO first\r\n")
                else:
                    conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    data_mode = True
            elif upper == "QUIT":
                conn.sendall(b"221 Bye\r\n")
                break
            elif upper.startswith("RSET"):
                rcpt_count = 0
                conn.sendall(b"250 OK\r\n")
            elif upper.startswith("NOOP"):
                conn.sendall(b"250 OK\r\n")
            else:
                conn.sendall(b"502 Command not implemented\r\n")
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def rdp_connection_confirm():
    # Minimal X.224 Connection Confirm in a TPKT envelope — enough to make
    # scanners believe an RDP endpoint is here.
    x224 = bytes([0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
                  0x02, 0x0f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00])
    return b"\x03\x00" + (len(x224) + 4).to_bytes(2, "big") + x224


def handle_rdp(conn, addr, log_path):
    sid = new_session()
    try:
        conn.settimeout(8)
        data = conn.recv(1024)  # binary protocol — keep it raw
        if data:
            log_event(log_path, "rdp", sid, addr, "handshake=" + data[:64].hex())
            conn.sendall(rdp_connection_confirm())
        else:
            log_event(log_path, "rdp", sid, addr, "(connected, sent nothing)")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def pg_error_response(user):
    # "password authentication failed" + ReadyForQuery, like a real server
    # rejecting a login.
    msg = f'password authentication failed for user "{user}"'.encode()
    fields = b"S" + b"FATAL\x00" + b"V" + b"FATAL\x00" + b"C" + b"28P01\x00" + b"M" + msg + b"\x00"
    body = fields + b"\x00"
    err = b"E" + (len(body) + 4).to_bytes(4, "big") + body
    ready = b"Z" + (5).to_bytes(4, "big") + b"I"
    return err + ready


def handle_postgres(conn, addr, log_path):
    sid = new_session()
    try:
        conn.settimeout(8)
        data = conn.recv(4096)
        if not data:
            log_event(log_path, "postgres", sid, addr, "(connected, sent nothing)")
            return
        user = "?"
        m = re.search(rb"user\x00([^\x00]{1,64})\x00", data)
        if m:
            user = m.group(1).decode("utf-8", errors="replace")
        log_event(log_path, "postgres", sid, addr, f"startup_user={user} bytes={len(data)}")
        conn.sendall(pg_error_response(user))
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def mssql_prelogin_response():
    # Minimal valid TDS PRELOGIN response: version, encryption, instance,
    # threadid, mars tokens, then the 0xFF terminator.
    tokens = [
        (0x00, bytes([0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00])),  # version 15.0.2000
        (0x01, bytes([0x02])),  # encryption: not supported
        (0x02, bytes([0x00])),  # instvalidity
        (0x03, bytes([0x00, 0x00, 0x00, 0x00])),  # threadid
        (0x04, bytes([0x00])),  # mars: off
    ]
    header_len = 5 * len(tokens) + 1
    body, offset = b"", header_len
    for ttype, tdata in tokens:
        body += bytes([ttype]) + offset.to_bytes(2, "big") + len(tdata).to_bytes(2, "big")
        offset += len(tdata)
    body += b"\xff"
    for _, tdata in tokens:
        body += tdata
    return b"\x04\x01" + (len(body) + 8).to_bytes(2, "big") + b"\x00\x00\x00\x00" + body


def handle_mssql(conn, addr, log_path):
    sid = new_session()
    try:
        conn.settimeout(8)
        data = conn.recv(4096)
        if data:
            log_event(log_path, "mssql", sid, addr, "prelogin=" + data[:64].hex())
            conn.sendall(mssql_prelogin_response())
        else:
            log_event(log_path, "mssql", sid, addr, "(connected, sent nothing)")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


# --- tiny BSON encoder, just enough for a fake ismaster reply ---

def _bson_cstr(s):
    return s.encode() + b"\x00"


def _bson_doc(elements):
    # elements: list of (type_byte, name, value_bytes)
    body = b"".join(bytes([t]) + _bson_cstr(n) + v for t, n, v in elements)
    return (len(body) + 5).to_bytes(4, "little") + body + b"\x00"


def mongo_ismaster_reply(response_to):
    doc = _bson_doc([
        (0x08, "ismaster", b"\x01"),
        (0x10, "maxBsonObjectSize", (16777216).to_bytes(4, "little", signed=True)),
        (0x10, "maxMessageSizeBytes", (48000000).to_bytes(4, "little", signed=True)),
        (0x10, "maxWriteBatchSize", (100000).to_bytes(4, "little", signed=True)),
        (0x01, "ok", struct.pack("<d", 1.0)),
    ])
    body = ((0).to_bytes(4, "little") + (0).to_bytes(8, "little")
            + (0).to_bytes(4, "little") + (1).to_bytes(4, "little") + doc)
    header = ((len(body) + 16).to_bytes(4, "little")
              + (9876).to_bytes(4, "little", signed=True)
              + response_to.to_bytes(4, "little", signed=True)
              + (1).to_bytes(4, "little"))  # opCode 1 = OP_REPLY
    return header + body


def handle_mongo(conn, addr, log_path):
    sid = new_session()
    try:
        conn.settimeout(8)
        data = conn.recv(4096)
        if not data or len(data) < 16:
            log_event(log_path, "mongo", sid, addr,
                      "(connected, sent nothing)" if not data else f"short_read={len(data)}")
            return
        opcode = int.from_bytes(data[12:16], "little")
        req_id = int.from_bytes(data[4:8], "little", signed=True)
        log_event(log_path, "mongo", sid, addr, f"opcode={opcode} len={len(data)}")
        if b"ismaster" in data or b"isMaster" in data:
            conn.sendall(mongo_ismaster_reply(req_id))
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        conn.close()


def handle_generic(conn, addr, log_path):
    # Just listen: log the connection and anything sent.
    sid = new_session()
    data = recv_some(conn)
    log_event(log_path, "generic", sid, addr, data.strip() if data.strip() else "(connected, sent nothing)")
    conn.close()


HANDLERS = {
    "ssh": handle_ssh,
    "telnet": handle_telnet,
    "http": handle_http,
    "ftp": handle_ftp,
    "mysql": handle_mysql,
    "redis": handle_redis,
    "smtp": handle_smtp,
    "vnc": handle_vnc,
    "elastic": handle_elastic,
    "docker": handle_docker,
    "postgres": handle_postgres,
    "mssql": handle_mssql,
    "mongo": handle_mongo,
    "rdp": handle_rdp,
    "ollama": handle_ollama,
    "openai": handle_openai,
    "generic": handle_generic,
}


# ---------------------------------------------------------------------------
# Flood protection — cap concurrent connections per service so one scanner
# can't exhaust threads/memory with a connection flood. Excess connections
# are dropped immediately (and counted, not logged one-by-one, so the flood
# can't fill the disk via the log either).
# ---------------------------------------------------------------------------

MAX_CONN_PER_SERVICE = 50

_conn_semaphores = {}
_conn_lock = threading.Lock()
_drop_counts = {}


def _sem_for(service):
    with _conn_lock:
        sem = _conn_semaphores.get(service)
        if sem is None:
            sem = threading.Semaphore(MAX_CONN_PER_SERVICE)
            _conn_semaphores[service] = sem
        return sem


def _note_drop(service, log_path, addr):
    with _conn_lock:
        n = _drop_counts.get(service, 0) + 1
        _drop_counts[service] = n
    if n == 1 or n % 100 == 0:
        log_event(log_path, service, new_session(), addr,
                  f"flood_protection=dropped {n} excess connections")


def _guarded_handler(handler, sem, conn, addr, log_path, service):
    # Peripheral-defense (opt-in): one port_probe per connection, before
    # the service handler runs. No-op unless PD_ENABLED=1.
    if PD_BRIDGE_AVAILABLE:
        pd_bridge.port_touch(service, addr)
    # Every accepted connection is logged, even if the visitor never speaks.
    # Handlers only log conversation; a bare port-scan knock would otherwise
    # be invisible to the SIEM (2026-09-25 drill: a 6-port sweep logged only
    # 5 services and PORT_SCAN stayed silent).
    log_event(log_path, service, new_session(), addr, "connect")
    try:
        handler(conn, addr, log_path)
    finally:
        sem.release()


def serve(port, service, log_path):
    handler = HANDLERS[service]
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", port))
    except PermissionError:
        print(f"[!] Can't bind port {port}: ports < 1024 need privileges. "
              f"Run as root, or: sudo setcap 'cap_net_bind_service=+ep' $(which python3)")
        return
    except OSError as e:
        print(f"[!] Can't bind port {port}: {e}")
        return
    srv.listen(50)
    print(f"[*] Honeypot '{service}' listening on port {port}  (Ctrl+C to stop)")
    sem = _sem_for(service)
    while True:
        conn, addr = srv.accept()
        if not sem.acquire(blocking=False):
            # At capacity: drop immediately instead of spawning a thread.
            _note_drop(service, log_path, addr)
            try:
                conn.close()
            except OSError:
                pass
            continue
        t = threading.Thread(target=_guarded_handler,
                             args=(handler, sem, conn, addr, log_path,
                                   service), daemon=True)
        t.start()


def parse_ports(spec):
    """'22:ssh,80:http' -> [(22, 'ssh'), (80, 'http')]"""
    out = []
    for item in spec.split(","):
        port, _, service = item.partition(":")
        service = service.strip().lower() or "generic"
        if service not in HANDLERS:
            raise ValueError(f"unknown service '{service}' (choose: {', '.join(HANDLERS)})")
        out.append((int(port.strip()), service))
    return out


# Default: all 14 fake services on their standard ports. Kept as a constant
# so tests (and --help) can reference exactly what "no flags" means.
DEFAULT_PORTS = ("22:ssh,23:telnet,80:http,21:ftp,3306:mysql,"
                 "6379:redis,25:smtp,5900:vnc,9200:elastic,2375:docker,"
                 "5432:postgres,1433:mssql,27017:mongo,3389:rdp")


def load_profile(path):
    """Load a persona profile JSON file -> [(port, service), ...].

    A profile picks a believable SUBSET of services so the honeypot tells
    one coherent story instead of lighting up every port. See PROFILES.md
    and profiles/small-business.json.

    Raises SystemExit with a helpful message on any problem (bad path,
    bad JSON, unknown service, bad port) — failing fast beats starting
    half a honeypot.
    """
    if not os.path.isfile(path):
        raise SystemExit(
            f"[!] --profile: file not found: {path}\n"
            f"    Profiles live in profiles/ — try: "
            f"python3 honeypot.py --profile profiles/small-business.json")
    try:
        with open(path) as f:
            prof = json.load(f)
    except json.JSONDecodeError as e:
        raise SystemExit(f"[!] --profile: {path} is not valid JSON: {e}")
    except OSError as e:
        raise SystemExit(f"[!] --profile: can't read {path}: {e}")
    if not isinstance(prof, dict) or not isinstance(prof.get("services"), dict):
        raise SystemExit(
            f"[!] --profile: {path} must be a JSON object with a \"services\" "
            f"object mapping service names to ports. See PROFILES.md for the format.")
    name = prof.get("name", os.path.basename(path))
    services = []
    for service, port in prof["services"].items():
        key = str(service).strip().lower()
        if key not in HANDLERS:
            raise SystemExit(
                f"[!] --profile '{name}': unknown service '{service}' "
                f"(choose: {', '.join(sorted(HANDLERS))})")
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise SystemExit(
                f"[!] --profile '{name}': port for '{service}' must be a "
                f"number, got {port!r}")
        if not (1 <= port <= 65535):
            raise SystemExit(
                f"[!] --profile '{name}': port {port} for '{service}' is out "
                f"of range (1-65535)")
        services.append((port, key))
    if not services:
        raise SystemExit(
            f"[!] --profile '{name}': no services enabled — a honeypot with "
            f"no doors is just a log file.")
    print(f"[*] Profile: {name}")
    if prof.get("backstory"):
        print(f"[*] {prof['backstory']}")
    return services


def main():
    ap = argparse.ArgumentParser(description="Educational honeypot v2: fake services + fake shell.")
    ap.add_argument("--ports", default=DEFAULT_PORTS,
                    help='comma-separated "port:service" pairs (default: %(default)s)')
    ap.add_argument("--profile", default=None, metavar="PATH",
                    help="persona profile: path to a JSON file selecting which "
                         "services to run (overrides --ports). See PROFILES.md "
                         "and profiles/small-business.json.")
    ap.add_argument("--log", default="logs/events.jsonl", help="log file (JSON lines)")
    ap.add_argument("--ed", action="store_true",
                    help="Paper Fortress: enable Ed's absurdity engine in the fake "
                         "shell (tiers 0-3, escalates the longer a visitor stays). "
                         "Off by default; also toggle with ED_TROLL_ENABLED=1.")
    ap.add_argument("--soft-target", action="store_true",                    help="Paper Fortress: serve the 'looks weak' decoy banners "
                         "(ancient OpenSSH/vsFTPd/Sendmail/Apache/MySQL versions) "
                         "from soft-target-banners.json. Off by default.")
    if HAS_DEFENSE:
        # Private overlay registers its own flags. Public --help never
        # mentions them.
        llm_defense.add_arguments(ap)
    ap.add_argument("--aliveness", action="store_true",
                    help="fake background noise: spawn aliveness.py to emit "
                         "synthetic user/cron/service events into the log "
                         "(all tagged synthetic:true, ignored by the SIEM). "
                         "Off by default.")
    ap.add_argument("--rotation-seed", type=int, default=None,
                    help="Layer 2: deception rotation seed. Same seed = same "
                         "banners/jitter/token placement (reproducible lab "
                         "runs). Unset = chain forward randomly.")
    ap.add_argument("--rotate-every", type=float, default=12,
                    help="Layer 2: hours between deception rotations "
                         "(0 = rotate once at startup only).")
    args = ap.parse_args()

    os.environ.setdefault("ED_TROLL_ENABLED", "1" if args.ed else "0")
    if HAS_DEFENSE:
        # Private overlay arms itself here. Absent from public builds.
        llm_defense.apply(args, sys.modules[__name__])
    # Layer 2: rotate the deception at startup (banners, jitter, bait
    # page, honeytoken placement), then again on a timer so a mapped
    # fortress goes stale. Explicit --soft-target still wins at startup.
    if ROTATION_AVAILABLE:
        rotation.rotate(seed=args.rotation_seed)
        rotation.apply(sys.modules[__name__])
        if args.rotate_every and args.rotate_every > 0:
            def _rotator():
                while True:
                    time.sleep(args.rotate_every * 3600)
                    try:
                        rotation.rotate()
                        rotation.apply(sys.modules[__name__])
                    except Exception as e:
                        print(f"[!] rotation failed: {e}", flush=True)
            threading.Thread(target=_rotator, daemon=True).start()
            print(f"[*] deception rotation every {args.rotate_every}h",
                  flush=True)
    if args.soft_target:
        load_soft_target(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "soft-target-banners.json"))

    os.makedirs(os.path.dirname(args.log) or ".", exist_ok=True)
    if args.aliveness:
        import subprocess as _sp, sys as _sys
        _here = os.path.dirname(os.path.abspath(__file__))
        try:
            _sp.Popen([_sys.executable, os.path.join(_here, "aliveness.py"),
                       "--log", args.log])
            print(f"[*] aliveness generator spawned (-> {args.log}; "
                  "synthetic:true, SIEM ignores it)")
        except OSError as e:
            print(f"[!] could not spawn aliveness.py: {e}")
    if args.profile:
        services = load_profile(args.profile)  # --profile wins over --ports
    else:
        services = parse_ports(args.ports)
    print(f"[*] Logging to {args.log}")
    for port, service in services:
        threading.Thread(target=serve, args=(port, service, args.log), daemon=True).start()
    try:
        threading.Event().wait()  # run until Ctrl+C
    except KeyboardInterrupt:
        print("\n[*] Honeypot stopped.")


if __name__ == "__main__":
    main()
