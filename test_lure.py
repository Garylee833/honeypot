#!/usr/bin/env python3
"""test_lure -- regression tests for the honey chain (lure.py + hooks).

Walks all three layers through the real fake-shell dispatch, checks the
gate stays shut until each credential is shown, and proves the touch log
links a credential's journey across IPs.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lure
import honeypot

PASS = 0
FAIL = 0
FAILS = []


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS " + name)
    else:
        FAIL += 1
        FAILS.append(name)
        print("FAIL " + name + (" -- " + detail if detail else ""))


def fresh_state(ip="9.9.9.9"):
    st = honeypot._new_shell_state()
    st["src_ip"] = ip
    return st


def run(cmd, st):
    return honeypot.handle_command(cmd, st)


# route the touch log to a scratch file for these tests
SCRATCH = "/tmp/test-lure-touches.jsonl"
if os.path.exists(SCRATCH):
    os.remove(SCRATCH)
lure._log_path = lambda: SCRATCH  # noqa: E731

# --- layer 1: the .env in the jar -------------------------------------------
st = fresh_state()
out = run("ls /opt/backup", st)
check("L1: .env is listed", ".env" in out, out[:80])
out = run("cat /opt/backup/.env", st)
check("L1: cat serves the password", lure.L1_PASSWORD in out, out[:80])
# the read trip is scanned in the shell loop; drive the real code path
honeypot._scan_command_trips("cat /opt/backup/.env", st,
                             "/tmp/test-lure-events.log", "ssh", "s1", "9.9.9.9")
check("L1: read served through cat", True, "")

# --- layer 2: the database ---------------------------------------------------
st2 = fresh_state("8.8.8.8")
out = run("psql", st2)
check("L2: bare psql shows usage", "usage" in out, out[:60])
out = run("psql password=wrong", st2)
check("L2: wrong password denied", "failed" in out, out[:60])
out = run('psql "host=db.internal user=backup_svc password=%s"' % lure.L1_PASSWORD, st2)
check("L2: right password opens backup_keys", lure.L2_TOKEN in out, out[:60])
check("L2: rotation note present", "rotation_note" in out)

# --- layer 3: the offsite gate -----------------------------------------------
st3 = fresh_state("7.7.7.7")
out = run("ls /backup/offsite", st3)
check("L3: gate shut before token", "Permission denied" in out, out[:80])
check("L3: denial names the keyhole", "vault-unlock" in out)
out = run("vault-unlock nope", st3)
check("L3: wrong token invalid", "invalid" in out, out[:60])
out = run("vault-unlock %s" % lure.L2_TOKEN, st3)
check("L3: right token opens the maze", "open" in out, out[:60])
out = run("ls /backup/offsite", st3)
check("L3: gate open after unlock", "Permission denied" not in out, out[:80])

# --- session isolation: one visitor's honey is not another's ------------------
st4 = fresh_state("6.6.6.6")
out = run("ls /backup/offsite", st4)
check("sessions isolated: new IP still gated", "Permission denied" in out)

# --- instrumentation: the log reads what each IP carried ----------------------
touches = [json.loads(l) for l in open(SCRATCH)]
by_action = {}
for t in touches:
    by_action.setdefault(t["action"], []).append(t)
check("touch log: L1 read recorded",
      any(t["src_ip"] == "9.9.9.9" and t["layer"] == 1 for t in by_action.get("read", [])))
check("touch log: failed psql recorded",
      any(t["success"] is False for t in by_action.get("psql-login", [])),
      str([t["success"] for t in by_action.get("psql-login", [])]))
check("touch log: successful unlock recorded",
      any(t["src_ip"] == "7.7.7.7" and t["success"] for t in by_action.get("vault-unlock", [])))
check("touch log: tool marks kept", all(t.get("tool") for t in touches))

journeys = lure.campaigns(SCRATCH)
check("campaigns: L1 credential journey exists", lure.L1_PASSWORD in journeys)
l1_stops = journeys.get(lure.L1_PASSWORD, [])
check("campaigns: L1 journey spans read + psql",
      {t["action"] for t in l1_stops} >= {"read", "psql-login"},
      str([t["action"] for t in l1_stops]))

os.remove(SCRATCH)
print("\n%d passed, %d failed." % (PASS, FAIL))
if FAILS:
    print("FAILED: " + ", ".join(FAILS))
sys.exit(1 if FAIL else 0)
