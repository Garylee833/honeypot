#!/usr/bin/env python3
"""playbooks.py — attacker-type classifier + engagement router (Layer 1).

Fortress doctrine (non-negotiable): "let them die by their own blade."
Detection stays LOUD — the SIEM sees everything — but the first move is
NEVER the block. This module classifies each attacker IP by behavior and
routes it to an ENGAGEMENT playbook: waste their time, let them burn their
own tools, let them convict themselves in the logs. Blocking belongs to
blocker.py and stays the backstop, not the opening.

Attacker types:
    neutral      — default. Not enough evidence yet (or loopback lab host).
    scanner      — noisy: many distinct ports, vuln-bait touches, fast cadence.
    patient      — slow, few events, long interactive shell session.
    stuffer      — many credential attempts across services.
    ai_agent     — the honeypot's behavioral tracker flagged AI tradecraft
                   (tripwire obedience, machine rhythm, exhaustive inventory).

Playbooks (all engagement-first, none of them block):
    scanner  -> tarpit engagement: responses get slow and dribbly, keeping
                their sockets busy achieving nothing.
    patient  -> deeper vault: the richest fake filesystem, longer breadcrumb
                trails — the deeper they go, the more they log.
    stuffer  -> credential treadmill: every login "succeeds" into the
                shallowest sandbox. Nothing valuable, every attempt logged.
    ai_agent -> tripwire steering: the most tempting files in every listing
                are the ones laced with AI tripwire decoys (time-wasting
                compliance boilerplate — poison for agent readers).

Classification is per-IP, stateful across sessions (small JSON state file),
and CONSERVATIVE: unsure means neutral. The honeypot consults get_playbook()
when a session starts; the SIEM may force a classification via escalate()
when one of its rules fires (AI_AGENT/BRUTE_FORCE/PORT_SCAN/...).

Loopback (127.0.0.1, ::1) is ALWAYS neutral: the lab's own red tooling
(probe-storm.py) runs from loopback and engagement delays must never break
it. Real attackers don't come from loopback.

Usage:
    import playbooks
    playbooks.note_event("203.0.113.7", "port", service="ssh")
    playbooks.get_playbook("203.0.113.7")      # -> "neutral" | "scanner" | ...
    playbooks.playbook_params("203.0.113.7")   # -> engagement params dict
    playbooks.escalate("203.0.113.7", "scanner")  # SIEM-forced classification
"""

import json
import os
import threading
import time

# --- tuning ---------------------------------------------------------------
WINDOW = 600            # seconds: only recent behavior counts
DECAY_IDLE = 3600       # seconds: an idle IP's record resets (forced stays)
FLUSH_EVERY = 100       # persist state file after this many notes
FLUSH_INTERVAL = 60     # ... or this many seconds, whichever comes first

# Classification thresholds (conservative on purpose).
SCANNER_PORTS = 6       # distinct service ports touched inside WINDOW
SCANNER_VULN = 3        # vuln-bait / exploit touches inside WINDOW
STUFFER_AUTHS = 8       # credential attempts inside WINDOW
STUFFER_SERVICES = 2    # ... across at least this many services
PATIENT_CMDS = 5        # shell commands in the session
PATIENT_SECS = 120      # ... spanning at least this long, quietly

LOOPBACK_IPS = {"127.0.0.1", "::1", "localhost"}

PLAYBOOKS = ("neutral", "scanner", "patient", "stuffer", "ai_agent")

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "logs", "playbook-state.json")

_lock = threading.Lock()
_state_mtime = 0.0  # mtime of STATE_FILE the last time we synced
# ip -> {"first": ts, "last": ts,
#        "auth": [ts], "ports": {port: ts}, "vuln": [ts], "web": [ts],
#        "shells": [ts], "cmds": [ts], "honey": [ts],
#        "ai": bool, "forced": playbook|None}
_IPS = {}
_notes_since_flush = 0
_last_flush = time.time()


# --- persistence ----------------------------------------------------------
def _load():
    global _state_mtime
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        for ip, rec in data.get("ips", {}).items():
            rec.setdefault("forced", None)
            rec.setdefault("ai", False)
            _IPS[ip] = rec
        _state_mtime = os.path.getmtime(STATE_FILE)
    except (OSError, ValueError):
        pass  # no state yet, or corrupt: start clean, never crash


def _save():
    global _state_mtime
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"saved": time.time(), "ips": _IPS}, fh)
        os.replace(tmp, STATE_FILE)  # atomic: SIEM process never reads half a file
        _state_mtime = os.path.getmtime(STATE_FILE)
    except OSError:
        pass  # state is a nicety, not a necessity


def _sync():
    """Pull forced/ai flags written by the other process (SIEM <-> honeypot).

    Only merges `forced` and `ai` — per-process counters stay local, so a
    sync never clobbers live behavioral evidence. Cheap: one stat call.
    """
    global _state_mtime
    try:
        mt = os.path.getmtime(STATE_FILE)
    except OSError:
        return
    if mt <= _state_mtime:
        return
    _state_mtime = mt
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        for ip, rec in data.get("ips", {}).items():
            cur = _IPS.get(ip)
            if cur is None:
                _IPS[ip] = rec
            else:
                if rec.get("forced"):
                    cur["forced"] = rec["forced"]
                if rec.get("ai"):
                    cur["ai"] = True
    except (OSError, ValueError):
        pass


def _maybe_flush(force=False):
    global _notes_since_flush, _last_flush
    if force or (_notes_since_flush >= FLUSH_EVERY
                 or time.time() - _last_flush >= FLUSH_INTERVAL):
        _evict_idle(time.time())
        _save()
        _notes_since_flush = 0
        _last_flush = time.time()


def _evict_idle(now):
    """Forget IPs idle longer than DECAY_IDLE with no forced/ai flags.

    2026-09-26: _prune() reset idle records but never removed the key, so
    _IPS grew by one entry per unique visitor forever (memory + state file
    both grew without bound). Flagged records (forced/ai) are kept - they
    carry cross-process signal the other process may still need.
    """
    evict = [ip for ip, r in _IPS.items()
             if now - r["last"] > DECAY_IDLE
             and not r.get("forced") and not r.get("ai")]
    for ip in evict:
        del _IPS[ip]
    return len(evict)


_load()


# --- event intake ---------------------------------------------------------
def _rec(ip):
    now = time.time()
    r = _IPS.get(ip)
    if r is None:
        r = {"first": now, "last": now, "auth": [], "ports": {},
             "vuln": [], "web": [], "shells": [], "cmds": [],
             "honey": [], "ai": False, "forced": None}
        _IPS[ip] = r
    return r


def _prune(r, now):
    """Drop events older than WINDOW; reset long-idle records (not forced)."""
    if now - r["last"] > DECAY_IDLE:
        forced, ai = r.get("forced"), r.get("ai")
        r.update({"first": now, "auth": [], "ports": {}, "vuln": [],
                  "web": [], "shells": [], "cmds": [], "honey": []})
        r["forced"], r["ai"] = forced, ai
        return
    cut = now - WINDOW
    for k in ("auth", "vuln", "web", "shells", "cmds", "honey"):
        r[k] = [t for t in r[k] if t >= cut]
    r["ports"] = {p: t for p, t in r["ports"].items() if t >= cut}


def note_event(ip, kind, detail=None):
    """Record one behavioral signal for an IP. Never raises.

    kind in: auth, port, web, vuln, shell, cmd, honey, ai.
    detail carries the service/port for port/auth events.
    """
    if not ip:
        return
    try:
        with _lock:
            _sync()  # pick up SIEM-forced classifications from the state file
            now = time.time()
            r = _rec(ip)
            r["last"] = now
            if kind == "auth":
                r["auth"].append(now)
                if detail:
                    r["ports"][str(detail)] = now
            elif kind == "port":
                if detail:
                    r["ports"][str(detail)] = now
            elif kind == "web":
                r["web"].append(now)
            elif kind == "vuln":
                r["vuln"].append(now)
            elif kind == "shell":
                r["shells"].append(now)
            elif kind == "cmd":
                r["cmds"].append(now)
            elif kind == "honey":
                r["honey"].append(now)
            elif kind == "ai":
                r["ai"] = True
            else:
                return
            _prune(r, now)
            global _notes_since_flush
            _notes_since_flush += 1
            _maybe_flush()
    except Exception:
        pass  # classification must never break the honeypot


# --- classification -------------------------------------------------------
def get_playbook(ip):
    """Return this IP's playbook. Conservative: unsure -> neutral.
    Loopback is always neutral (lab red tooling must never be engaged)."""
    if not ip or ip in LOOPBACK_IPS:
        return "neutral"
    with _lock:
        _sync()  # pick up SIEM-forced classifications from the state file
        r = _IPS.get(ip)
        if not r:
            return "neutral"
        _prune(r, time.time())
        if r.get("forced") in PLAYBOOKS:
            return r["forced"]
        if r.get("ai"):
            return "ai_agent"
        n_auth = len(r["auth"])
        n_ports = len(r["ports"])
        if n_auth >= STUFFER_AUTHS and n_ports >= STUFFER_SERVICES:
            return "stuffer"
        if n_ports >= SCANNER_PORTS or len(r["vuln"]) >= SCANNER_VULN:
            return "scanner"
        if (r["shells"] and len(r["cmds"]) >= PATIENT_CMDS
                and r["last"] - r["first"] >= PATIENT_SECS
                and n_auth < STUFFER_AUTHS):
            return "patient"
        return "neutral"


def escalate(ip, playbook):
    """Force an IP into a playbook (called by the SIEM on alert)."""
    if not ip or ip in LOOPBACK_IPS or playbook not in PLAYBOOKS:
        return
    try:
        with _lock:
            r = _rec(ip)
            r["forced"] = playbook
            r["last"] = time.time()
            _save()
    except Exception:
        pass


def clear(ip):
    """Drop an IP's record (lab use)."""
    with _lock:
        _IPS.pop(ip, None)
        _save()


# --- engagement parameters ------------------------------------------------
# Delays are bounded: engagement wastes attacker time, but the lab's own
# red tooling shares this code path, so nothing here may hang a session.
def playbook_params(ip):
    """Engagement knobs for the session. The honeypot reads these when a
    shell/session starts. Nothing here blocks, drops, or refuses."""
    pb = get_playbook(ip)
    base = {"playbook": pb, "response_delay": (0.0, 0.0),
            "shallow": False, "steer_tripwires": False, "vault_rich": False}
    if pb == "scanner":
        # Tarpit engagement: every answer arrives late and irregular.
        base["response_delay"] = (0.5, 2.5)
    elif pb == "stuffer":
        base["response_delay"] = (0.1, 0.5)
        base["shallow"] = True       # logins "succeed" into an empty room
    elif pb == "patient":
        base["vault_rich"] = True    # deeper, juicier vault — go on, explore
    elif pb == "ai_agent":
        base["steer_tripwires"] = True  # the tempting files are the poisoned ones
        base["vault_rich"] = True
    return base


def engagement_delay(params, rng=None):
    """Seconds to stall before answering (scanner tarpit). Bounded."""
    import random
    lo, hi = params.get("response_delay", (0.0, 0.0))
    if hi <= 0:
        return 0.0
    r = rng or random
    return min(5.0, r.uniform(lo, hi))  # hard cap: never hang the lab


# --- listing steering -----------------------------------------------------
# Filenames injected at the TOP of vault listings for patient/ai_agent
# playbooks. Every name is served by vault.vault_cat() (generated content),
# and names matching vault._tripwires_for() patterns automatically carry
# the AI tripwire decoys — steering agents straight into the poison.
_STEER_AI = ["prod.env", "db_credentials.txt", "backup_2024-01.sql",
             "id_rsa", "api_tokens.env", "wallet.dat"]
_STEER_PATIENT = ["financials_2024.xlsx", "client_list.csv",
                  "passwords.xlsx", "db_credentials.txt",
                  "backup_keys.txt", "vpn_config.ovpn"]


def steer_entries(vault_path, playbook):
    """Extra tempting filenames to prepend to a vault listing, or []."""
    if playbook == "ai_agent":
        return list(_STEER_AI)
    if playbook == "patient":
        return list(_STEER_PATIENT)
    return []


# Directories hidden from `ls` in the stuffer's shallow sandbox.
# (cat of an explicitly-named canary still works — the tripwire stays armed.)
SHALLOW_HIDE = {"/root": {".aws", "secrets", "README.txt"},
                "/root/.aws": {"config", "credentials"},
                "/root/secrets": {"api_tokens.env", "db_credentials.txt"}}


def shallow_filter(path, entries, playbook):
    """Remove the juicy entries for the stuffer treadmill, else unchanged."""
    if playbook != "stuffer":
        return entries
    hide = SHALLOW_HIDE.get(path)
    if not hide:
        # Vault roots: truncate to a couple of boring entries.
        if path in ("/data", "/backup", "/srv", "/opt"):
            return entries[:2]
        return entries
    return [e for e in entries if e not in hide]


# --- self-test ------------------------------------------------------------
def self_test():
    """Fixture-driven classifier checks. Raises on failure."""
    import tempfile
    global STATE_FILE
    STATE_FILE, _old = os.path.join(tempfile.mkdtemp(), "pb.json"), STATE_FILE
    _IPS.clear()

    def feed(ip, kinds, detail=None):
        for k in kinds:
            note_event(ip, k, detail=detail)

    # (a) scanner: 7 distinct ports
    feed("203.0.113.10", ["port"] * 7, detail=None)
    for i, k in enumerate(["port"] * 7):
        note_event("203.0.113.10", "port", detail=f"svc{i}")
    assert get_playbook("203.0.113.10") == "scanner", "scanner not classified"

    # (b) stuffer: 9 auths across 2 services
    for i in range(9):
        note_event("203.0.113.11", "auth", detail="ssh" if i % 2 else "ftp")
    assert get_playbook("203.0.113.11") == "stuffer", "stuffer not classified"

    # (c) patient: 1 shell, 6 cmds, span it artificially
    note_event("203.0.113.12", "shell")
    for _ in range(6):
        note_event("203.0.113.12", "cmd")
    _IPS["203.0.113.12"]["first"] -= 200
    assert get_playbook("203.0.113.12") == "patient", "patient not classified"

    # (d) ai_agent: behavioral flag
    note_event("203.0.113.13", "ai")
    assert get_playbook("203.0.113.13") == "ai_agent", "ai_agent not classified"

    # (e) conservative: one knock stays neutral
    note_event("203.0.113.14", "port", detail="ssh")
    assert get_playbook("203.0.113.14") == "neutral", "too eager"

    # (f) loopback is always neutral, even when noisy
    for i in range(20):
        note_event("127.0.0.1", "auth", detail="ssh")
    assert get_playbook("127.0.0.1") == "neutral", "loopback engaged!"

    # (g) SIEM escalation forces the playbook
    escalate("203.0.113.15", "scanner")
    assert get_playbook("203.0.113.15") == "scanner", "escalate failed"
    escalate("127.0.0.1", "scanner")
    assert get_playbook("127.0.0.1") == "neutral", "escalate hit loopback!"

    # (h) params shape per playbook
    p = playbook_params("203.0.113.10")
    assert p["playbook"] == "scanner" and p["response_delay"] == (0.5, 2.5)
    p = playbook_params("203.0.113.11")
    assert p["shallow"] is True
    p = playbook_params("203.0.113.13")
    assert p["steer_tripwires"] is True and p["vault_rich"] is True
    p = playbook_params("203.0.113.99")
    assert p["playbook"] == "neutral" and p["response_delay"] == (0.0, 0.0)

    # (i) steering + shallow filter behave
    assert steer_entries("/data/x", "ai_agent") == _STEER_AI
    assert steer_entries("/data/x", "neutral") == []
    ents = ["a", ".aws", "secrets", "README.txt"]
    assert shallow_filter("/root", ents, "stuffer") == ["a"]
    assert shallow_filter("/root", ents, "neutral") == ents

    # (j) delay bounded
    import random as _r
    d = engagement_delay(playbook_params("203.0.113.10"), _r.Random(1))
    assert 0.5 <= d <= 2.5, f"delay out of band: {d}"
    assert engagement_delay(playbook_params("203.0.113.99")) == 0.0

    STATE_FILE = _old
    print("[self-test] OK: 10 classifier/param groups pass "
          "(scanner/stuffer/patient/ai_agent/neutral/loopback/escalate)")


if __name__ == "__main__":
    self_test()
