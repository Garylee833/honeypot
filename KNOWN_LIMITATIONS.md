# Known Limitations — read before you trust the green lights

Last updated: 2026-09-27

## 1. Slow-and-low evasion (the big one)

The SIEM's volumetric rules count events inside fixed time windows:

| Rule | Threshold |
|------|-----------|
| BRUTE_FORCE | ≥5 logins / 60s |
| PORT_SCAN | ≥6 ports / 30s |
| WEB_PROBING | ≥3 requests / 60s |

**A patient attacker defeats every one of these by waiting.** Proven 2026-09-18:
- 13-port scan with 8-second gaps (112s total) → zero alerts
- 3 web requests 20s apart → zero alerts
- 3 SSH credential attempts → zero alerts (under the brute-force floor)

Widening the windows does not fix this — it just moves the evasion bar
(the attacker waits longer) and raises false positives from background noise.
This is an industry-wide hard problem, not a bug in this build.

**Compensating controls (what we do instead):**
- The tarpit wastes slow scanners' time whether or not we detect them.
- Every connection is still LOGGED to events.jsonl — a human analyst
  (or the AI-SIEM) reviewing the timeline can spot the pattern the
  thresholds miss. Detection ≠ alerting.
- Thresholds are documented, not secret: assume the attacker has read them.

## 2. Blocker ladder needs repeated alerts

Non-CRITICAL rules (BRUTE_FORCE, PORT_SCAN, WEB_PROBING, AI_AGENT) need
3 strikes before a block. A single sub-threshold brush gets WATCH/ESCALATE
only. CRITICAL rules (SHELL_ACCESS, HONEYCREDS, EXPLOIT_PROBE) block on
the first alert. This is deliberate — see blocker.py LADDER_POLICY.

## 3. Loopback is never blocked

127.0.0.1 / ::1 and the host's own IPs are always SKIPped, even in
--enforce mode. Lab-safe by design; verify this stays true after edits.

## 4. Alerts are only as honest as alerts.jsonl

blocker.py acts on whatever the SIEM writes. That file must be writable
only by the SIEM user — a forged alert is a forged block.

## 5. CRED_DUMP_TRIPWIRE is a decoy-contact tripwire, not LSASS detection

Added 2026-09-23. The rule fires CRITICAL/T1003 when a visitor reads one of
three planted fake credential caches (`/backup/db_passwords.txt`,
`/home/admin/.aws/credentials`, `/opt/deploy/.env`). Honest boundaries:

- It detects **contact with planted fake credentials**, not real OS
  credential dumping. There is no LSASS/memory telemetry here — a real
  Mimikatz run against a real host would not trip this.
- **Reader coverage is partial.** The shell hooks `cat`, `less`, `more`,
  `head`, `tail`, `strings`, `grep`. NOT hooked: `sed -n`, `awk`, `xxd`,
  `base64 <file>`, and copy-then-read (`cp <decoy> /tmp/x`, then read the
  copy). A skilled attacker who exfiltrates the file without a hooked
  reader evades the *read* trip. (Same limitation the HONEYCREDS canaries
  have always carried — documented in honeycreds.py.)
- Unlike the HONEYCREDS canaries, these decoys have **no use-as-creds
  tripwire** — there is no fake service that accepts a DB password the way
  the fake `aws` CLI accepts canary keys. Detection ends at the read.
- W1 verdict is PARTIAL for exactly these reasons. Do not brief it as
  "T1003 covered."
