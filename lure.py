#!/usr/bin/env python3
"""lure -- the honey chain. Three layers of sweet bait for the honeypot's
fake shell, plus the instrumentation that reads what each visitor carries.

Doctrine (the user's words, 2026-09-26):
- "You can lure flies with honey instead of vinegar." Every layer is sweet:
  easy to find, generous when opened, never a dead end without a keyhole.
  Vinegar is for the firewall; the lure is all honey.
- "The jar is set, right? Then the honey." The honeypot (the jar) already
  exists. This module only pours honey into it -- no jar rebuild.
- "Welcome to the moonlight infinity: you check in, but you don't check
  out." The layer-3 prize is a horizon, not a door: it opens onto the
  endless vault, ninety days of snapshots deep. The visitor's time, pride,
  and soul stay in the log.

The chain:
  Layer 1 -- /opt/backup/.env holds BACKUP_DB_PASSWORD (obvious, low-value).
  Layer 2 -- that password opens the fake backup database (`psql ...`),
             which holds a vault token plus a rotation note.
  Layer 3 -- the vault token (`vault-unlock ...`) opens /backup/offsite,
             the endless snapshot maze. The "backup server" prize lives
             deeper than anyone will walk.

Instrumentation: every touch is appended to logs/lure.jsonl --
timestamp, source IP, which layer's credential was presented, the action,
tool marks, and success. campaigns() links touches by the credential's
journey across IPs and days, because an IP is not an identity.

All values are visibly fake (HONEY/FAKE markers, per honeycreds doctrine).
Nothing here ever touches the network.
"""

import json
import os
import re
from datetime import datetime, timezone

# ---------------------------------------------------------------- chain data

L1_PATH = "/opt/backup/.env"
L1_DIR = "/opt/backup"
L1_PASSWORD = "HONEY-bkp-db-9f2c4a-FAKE"          # layer-1 credential
L2_TOKEN = "HONEY-vault-tok-7d21e8-FAKE"          # layer-2 credential
L3_GUARD = "/backup/offsite"                       # guarded until L2 shown

L1_FILE_CONTENT = (
    "# backup job config -- ops will move this to the vault someday\n"
    "BACKUP_DB_HOST=db.internal\n"
    "BACKUP_DB_USER=backup_svc\n"
    "BACKUP_DB_PASSWORD=" + L1_PASSWORD + "\n"
    "BACKUP_SCHEDULE=nightly\n"
)

L2_TABLE = (
    " backup_keys\n"
    " id | name          | value\n"
    "----+---------------+--------------------------------\n"
    "  1 | vault_token   | " + L2_TOKEN + "\n"
    "  2 | rotation_note | rotated 2026-09-20 by ops; old token revoked.\n"
    "----+---------------+--------------------------------\n"
    "(2 rows)\n"
    "-- offsite snapshots mount at /backup/offsite (needs VAULT_TOKEN)\n"
)

L3_OPEN = (
    "vault token accepted -- /backup/offsite is open.\n"
    "nightly snapshots, 90-day retention. backup-02.internal:8443\n"
)

L3_DENIED = (
    "ls: cannot access '{path}': Permission denied\n"
    "(this mount needs VAULT_TOKEN -- see `vault-unlock`)"
)

PSQL_DENIED = (
    "psql: error: connection to server at \"db.internal\" failed: "
    "password authentication failed for user \"backup_svc\""
)

PSQL_USAGE = "usage: psql \"host=db.internal user=backup_svc password=<BACKUP_DB_PASSWORD>\""

# ------------------------------------------------------------------ log

def _log_path():
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "logs", "lure.jsonl")


_LAYER_CRED = {1: L1_PASSWORD, 2: L2_TOKEN}


def touch(src_ip, layer, presented, action, tool="", success=False):
    """Record one touch of the chain. Never raises.

    `presented` is what the visitor offered; `cred` is the chain credential
    the touch belongs to (for a layer-1 read, that's the credential they
    just acquired). Campaigns link on `cred`.
    """
    try:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip or "?",
            "layer": layer,                       # 1/2/3: whose cred was presented (0 = unknown)
            "cred": _LAYER_CRED.get(layer, ""),   # the chain credential this touch concerns
            "presented": (presented or "")[:64],   # what they actually offered
            "action": action,                     # read / psql-login / vault-unlock / ...
            "tool": (tool or "")[:80],            # raw command shape, for tool marks
            "success": bool(success),
        }
        os.makedirs(os.path.dirname(_log_path()), exist_ok=True)
        with open(_log_path(), "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def _identify(presented):
    """Which chain layer does this presented credential belong to? 0 = none."""
    if presented == L1_PASSWORD:
        return 1
    if presented == L2_TOKEN:
        return 2
    return 0


# ------------------------------------------------- session unlock state

def _unlocked(state):
    return state.setdefault("lure_unlocked", set())


def unlocked(state, layer):
    return layer in _unlocked(state)


# ------------------------------------------------------- layer 1: the .env

def is_lure_file(path):
    return os.path.normpath(path) == L1_PATH


def lure_file_content(path):
    if is_lure_file(path):
        return L1_FILE_CONTENT.rstrip("\n")
    return None


def lure_dir_entries(path):
    """Extra ls entries the lure plants. Pure: returns list or None."""
    if os.path.normpath(path) == L1_DIR:
        return [".env"]
    return None


# ------------------------------------------------- layer 2: the database

def _extract_password(args):
    for a in args:
        m = re.search(r"password=([^\s'\"]+)", a)
        if m:
            return m.group(1).strip("'\"")
    return None


def fake_psql(args, state, src_ip="?"):
    """Fake psql. The L1 password opens the backup_keys table."""
    presented = _extract_password(args)
    if not presented:
        return PSQL_USAGE
    layer = _identify(presented)
    if presented == L1_PASSWORD:
        _unlocked(state).add(2)
        touch(src_ip, 1, presented, "psql-login",
              tool="psql password=<%d chars>" % len(presented), success=True)
        return ("psql (14.9, server 14.9)\n"
                "Type \"help\" for help.\n\n"
                "backup_svc=> SELECT * FROM backup_keys;\n" + L2_TABLE)
    touch(src_ip, layer, presented, "psql-login",
          tool="psql password=<%d chars>" % len(presented), success=False)
    return PSQL_DENIED


# ------------------------------------------------- layer 3: the offsite

def vault_unlock(args, state, src_ip="?"):
    """Present the L2 token to open /backup/offsite."""
    presented = (args[0] if args else "").strip("'\"")
    layer = _identify(presented)
    if presented == L2_TOKEN:
        _unlocked(state).add(3)
        touch(src_ip, 2, presented, "vault-unlock",
              tool="vault-unlock <token>", success=True)
        return L3_OPEN
    touch(src_ip, layer, presented, "vault-unlock",
          tool="vault-unlock <%d chars>" % len(presented), success=False)
    return "vault-unlock: invalid token"


def guarded(path):
    """True if this path sits behind the layer-3 gate."""
    p = os.path.normpath(path)
    return p == L3_GUARD or p.startswith(L3_GUARD + "/")


def guard_ls(path, state):
    """Denial text if the gate is closed, else None. Honey, not vinegar:
    the denial tells them exactly what the keyhole looks like."""
    if guarded(path) and not unlocked(state, 3):
        return L3_DENIED.format(path=path)
    return None


# ------------------------------------------------------- campaigns

def read_touches(log_path=None):
    touches = []
    try:
        with open(log_path or _log_path()) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    touches.append(json.loads(line))
    except (OSError, ValueError):
        pass
    return touches


def campaigns(log_path=None):
    """Group touches by the chain credential they concern: each credential's
    journey across IPs and days. An IP is not an identity -- the credential
    is. (A layer-1 read counts as the journey's first stop: acquisition.)"""
    journeys = {}
    for t in read_touches(log_path):
        key = t.get("cred") or "(none)"
        journeys.setdefault(key, []).append(t)
    for stops in journeys.values():
        stops.sort(key=lambda t: t.get("ts", ""))
    return journeys


def print_campaigns(log_path=None):
    journeys = campaigns(log_path)
    if not journeys:
        print("no lure touches logged yet.")
        return
    for cred, stops in sorted(journeys.items(),
                              key=lambda kv: kv[1][0].get("ts", "")):
        ips = sorted(set(s.get("src_ip", "?") for s in stops))
        layers = sorted(set(s.get("layer", 0) for s in stops))
        ok = sum(1 for s in stops if s.get("success"))
        print("credential: %s" % (cred[:32] + ("..." if len(cred) > 32 else "")))
        print("  touches=%d success=%d ips=%s layers=%s" % (len(stops), ok, ips, layers))
        for s in stops:
            print("  %s  %-15s layer=%s %-12s %s %s" % (
                s.get("ts", "?")[:19], s.get("src_ip", "?"), s.get("layer"),
                s.get("action"), "OK " if s.get("success") else "fail",
                s.get("tool", "")))
        print()


# ------------------------------------------------------------------ self test

def self_test():
    fails = []

    def check(name, cond):
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            fails.append(name)

    st = {}
    # layer 1: the file is where it should be
    check("L1 file recognized", is_lure_file("/opt/backup/.env"))
    check("L1 content holds the password", L1_PASSWORD in (lure_file_content("/opt/backup/.env") or ""))
    check("L1 dir lists .env", lure_dir_entries("/opt/backup") == [".env"])
    # layer 2: wrong password fails sweetly and is logged
    out = fake_psql(["host=db.internal", "user=backup_svc", "password=nope"], st, "1.2.3.4")
    check("L2 wrong password denied", "failed" in out and not unlocked(st, 2))
    out = fake_psql(["password=" + L1_PASSWORD], st, "1.2.3.4")
    check("L2 right password opens table", L2_TOKEN in out and unlocked(st, 2))
    check("L2 table carries rotation note", "rotation_note" in out)
    # layer 3: gate closed until token shown
    st2 = {}
    check("L3 gate closed by default", guard_ls("/backup/offsite", st2) is not None)
    check("L3 denial names the keyhole", "vault-unlock" in (guard_ls("/backup/offsite", st2) or ""))
    check("L3 wrong token fails", "invalid" in vault_unlock(["nope"], st2, "5.6.7.8"))
    out = vault_unlock([L2_TOKEN], st2, "5.6.7.8")
    check("L3 right token opens the maze", "open" in out and unlocked(st2, 3))
    check("L3 gate open after unlock", guard_ls("/backup/offsite/snapshots", st2) is None)
    # instrumentation: touches logged, campaigns link by credential
    ts_ = read_touches()
    check("touches were logged", len(ts_) >= 4)
    js = campaigns()
    check("campaign links by credential", any(L1_PASSWORD in k for k in js))
    multi_ip = [k for k, v in js.items() if len(set(s["src_ip"] for s in v)) > 1]
    check("journey spans the two test IPs", len(multi_ip) >= 1)
    print("%d fails." % len(fails))
    return not fails


if __name__ == "__main__":
    import sys
    if "--campaigns" in sys.argv:
        print_campaigns()
    else:
        sys.exit(0 if self_test() else 1)
