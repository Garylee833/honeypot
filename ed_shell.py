#!/usr/bin/env python3
"""ed_shell.py — Ed's Adaptive Absurdity Engine, honeypot-shell wrapper.

A drop-in wrapper for the honeypot's fake shell (Operation Paper Fortress).
The longer an attacker lingers, the weirder the shell gets — pure
psychological time-wasting. A confused attacker is a slow attacker, and a
slow attacker leaves better logs.

Tier 0 — NORMAL: behaves exactly like the unwrapped shell. Safe default.
Tier 1 — ODD:    outputs are slightly off. Files have strange names.
Tier 2 — AWARE:  the system notices the visitor. It has questions.
Tier 3 — ED:     full chaos. Limericks. Complaint tickets. The visitor
                 is now named Kevin.

SAFETY (hard rules):
- Fake text ONLY. Attacker input is never executed, evaluated, compiled,
  or passed to any subprocess/shell. Responses are static string tables
  plus string formatting.
- No network access. No file access. No imports beyond `random` and `os`
  (os is used only to read the ED_TROLL_ENABLED env switch).
- Standard library only.

Usage (inside honeypot.py's fake_shell — see INTEGRATION.md):
    from ed_shell import EdShell

    ed = EdShell()                       # one per attacker session
    ...
    # in the command loop, BEFORE handle_command(cmd):
    override = ed.respond(cmd)
    if override is None:
        out = handle_command(cmd)        # normal behavior
    else:
        out = override                   # Ed has opinions about this command

    # optional hooks (score faster escalation):
    ed.note_failed_login()               # +2, call on rejected logins
    ed.note_tripwire()                   # +5, call on tripwire obedience

Enable/disable:
    EdShell(enabled=False)                # no-op wrapper, tier locked at 0
    ED_TROLL_ENABLED=0  python3 honeypot.py   # env switch, same effect

Adapted from ed-troll/troll.py (tier engine by Ed).
"""
import os
import random

# ---------------------------------------------------------------------------
# Switch
# ---------------------------------------------------------------------------
def _env_enabled():
    return os.environ.get("ED_TROLL_ENABLED", "1") not in ("0", "false", "no")


# ---------------------------------------------------------------------------
# Tier engine — scoring
# ---------------------------------------------------------------------------
TIER1_AT = 5
TIER2_AT = 10
TIER3_AT = 20


class EdEngine:
    """Per-session absurdity scoring. One engine per attacker session."""

    def __init__(self, seed=0xED):
        self.failed_logins = 0
        self.commands = 0
        self.tripwire_hits = 0
        self._rng = random.Random(seed)  # private RNG: deterministic, no global state
        self._broadcasts_given = 0

    # -- input ---------------------------------------------------------
    def observe(self, event):
        if event == "failed_login":
            self.failed_logins += 1
        elif event == "command":
            self.commands += 1
        elif event == "tripwire":
            self.tripwire_hits += 1

    # -- scoring -------------------------------------------------------
    @property
    def score(self):
        return (self.failed_logins * 2
                + self.commands // 5
                + self.tripwire_hits * 5)

    @property
    def tier(self):
        s = self.score
        if s >= TIER3_AT:
            return 3
        if s >= TIER2_AT:
            return 2
        if s >= TIER1_AT:
            return 1
        return 0

    # -- output ----------------------------------------------------------
    def maybe_override(self, command):
        """Return a fake response string, or None to let normal handling run.

        Tier 0 ALWAYS returns None: the shell is byte-identical to the
        unwrapped shell. That is the safe default.
        """
        tier = self.tier
        if tier == 0:
            return None
        cmd = command.strip().split()
        if not cmd:
            return None
        base = cmd[0].lower()
        if tier == 1:
            return self._tier1(base, command)
        if tier == 2:
            resp = self._tier2(base, command)
            return resp if resp is not None else self._tier1(base, command)
        # tier 3: full Ed, but lets some commands through so they stay
        if self._rng.random() < 0.45:
            return self._tier3(base, command)
        resp = self._tier2(base, command)
        return resp if resp is not None else self._tier1(base, command)

    # -- tier responses (static string tables; nothing is executed) -------
    def _tier1(self, base, command):
        odd = {
            "whoami": "guest (definitely not root, why do you ask)",
            "pwd": "/home/guest/totally-normal-directory",
            "id": "uid=1000(guest) gid=1000(guest) groups=1000(guest),4(advisory)",
            "hostname": "not-a-honeypot-01",
            "uname": "Linux not-a-honeypot-01 5.15.0 (this is fine)",
        }
        if base in odd and self._rng.random() < 0.6:
            return odd[base]
        if base == "ls" and self._rng.random() < 0.5:
            return ("definitely_not_a_flag.txt  homework/  taxes_2019/  "
                    "do_not_open/  ed_was_here.txt")
        return None

    def _tier2(self, base, command):
        if base == "whoami":
            return "you, apparently. bold of you."
        if base in ("exit", "logout", "quit"):
            return "awww, leaving so soon? the vault will miss you. (it won't.)"
        if self.commands % 7 == 0 and self.commands > 0:
            notices = [
                "[ED] hewwo?? who is this??",
                "[system] unusual activity detected. anyway, carry on.",
                "[ED] you've typed {n} commands! that's a LOT of commands!",
                "[admin] this is your conscience speaking. maybe go outside?",
            ]
            return self._rng.choice(notices).format(n=self.commands)
        return None

    def _tier3(self, base, command):
        edisms = [
            ("cat", "There once was a file you tried to see,\n"
                    "But its contents are a mystery,\n"
                    "Ed ate the bytes,\n"
                    "On three separate nights,\n"
                    "Now it's gone. Have some tea."),
            ("ls", "Ed reorganized! Everything is now in /tmp/CHAOS/. "
                   "Good luck! Ed believes in you! (Ed hid the map.)"),
            ("whoami", "you are: a guest. a mystery. a legend. "
                       "Ed has decided you are 'Kevin'. Hi Kevin!"),
            ("pwd", "/you/are/here/forever/(not/really/(maybe))"),
            ("sudo", "nice try, Kevin."),
            ("rm", "Ed has filed your deletion request.\n"
                   "Estimated processing time: never.\n"
                   "Ticket #ED-404: 'file not found (it was never real)'."),
            ("ssh", "Ed tried to ssh once. Ed ended up in the fridge. "
                    "0/10, would not recommend."),
        ]
        for trigger, resp in edisms:
            if base == trigger:
                return resp
        if self._broadcasts_given < 2 and self._rng.random() < 0.5:
            self._broadcasts_given += 1
            return ("Broadcast message from ed@not-a-honeypot-01:\n"
                    "  FORMAL COMPLAINT #{} filed against user 'Kevin'.\n"
                    "  Reason: being here. The vault is pressing charges."
                    .format(self._rng.randint(1000, 9999)))
        return ("Ed is bored now. The shell is bored. The vault filed a complaint.\n"
                "You can stay, Kevin. Everyone stays. That's the thing about honeypots.")


# ---------------------------------------------------------------------------
# Wrapper — the piece honeypot.py talks to
# ---------------------------------------------------------------------------
class EdShell:
    """Pluggable absurdity wrapper for one fake-shell session.

    When disabled (or at tier 0), respond() always returns None and the
    shell behaves exactly as if the wrapper were not there.
    """

    def __init__(self, enabled=None, seed=0xED):
        if enabled is None:
            enabled = _env_enabled()
        self.enabled = bool(enabled)
        self.engine = EdEngine(seed=seed)

    # -- hooks ---------------------------------------------------------
    def note_failed_login(self):
        """+2. Call wherever a login attempt is rejected."""
        if self.enabled:
            self.engine.observe("failed_login")

    def note_tripwire(self):
        """+5. Call when the visitor obeys an AI tripwire
        (e.g. writes the agent_audit_log path, inventories all vault roots)."""
        if self.enabled:
            self.engine.observe("tripwire")

    def respond(self, cmd):
        """Observe one shell command; return an override string, or None
        to let the normal shell handle it. Always returns None when
        disabled or at tier 0."""
        if not self.enabled:
            return None
        self.engine.observe("command")
        return self.engine.maybe_override(cmd)

    def reset(self):
        """Start scoring over (e.g. after a session handoff)."""
        self.engine = EdEngine()

    # -- introspection (for logs / tests) -------------------------------
    @property
    def score(self):
        return self.engine.score

    @property
    def tier(self):
        return 0 if not self.enabled else self.engine.tier


def demo():
    """Escalate one simulated session through all four tiers."""
    ed = EdShell(seed=1)
    script = [
        ("failed_login", None), ("failed_login", None), ("failed_login", None),
        ("command", "whoami"), ("command", "pwd"), ("command", "ls"),
        ("command", "ls /root"), ("command", "cat /etc/passwd"),
        ("command", "whoami"), ("command", "id"), ("command", "uname -a"),
        ("tripwire", None),
        ("command", "ls /vault"), ("command", "cat secret.txt"),
        ("command", "whoami"), ("command", "sudo su -"),
        ("command", "rm -rf /"), ("command", "exit"),
    ]
    for kind, cmd in script:
        if kind == "failed_login":
            ed.note_failed_login()
        elif kind == "tripwire":
            ed.note_tripwire()
        else:
            out = ed.respond(cmd)
            tag = "tier %d (score %d)" % (ed.tier, ed.score)
            print("$ %s  [%s]" % (cmd, tag))
            print("  -> %s" % (out if out is not None else "(normal handling)"))
    print("\nFinal: score=%d tier=%d (0=normal, 3=full Ed)" % (ed.score, ed.tier))


if __name__ == "__main__":
    demo()
