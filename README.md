# Honeypot v2 — quick start

An educational honeypot in one file: `honeypot.py`.

## What it does

Listens on ports you choose and pretends to be common internet services.
Every knock is logged as JSON lines: UTC time, service, a session id, source
IP/port, and what the visitor sent. Accepted logins drop into a **fake
shell** — attackers reveal their commands and payload URLs while nothing
they type is ever executed and nothing is ever downloaded.

| Port (default) | Service  | What it fakes                                  |
|----------------|----------|------------------------------------------------|
| 22             | ssh      | OpenSSH banner, accepts any login → fake shell |
| 23             | telnet   | RouterOS-style login → fake shell              |
| 80             | http     | Router / WordPress / phpMyAdmin login pages    |
| 21             | ftp      | vsFTPd banner, harvests credential guesses    |
| 3306           | mysql    | Plausible handshake, logs scanner replies     |
| 6379           | redis    | Answers PING, rejects AUTH, logs commands     |
| 25             | smtp     | Fake Postfix, logs mail attempts (never relays) |
| 5900           | vnc      | RFB banner + auth challenge                   |
| 9200           | elastic  | Fake Elasticsearch node info (JSON)           |
| 2375           | docker   | Fake Docker Engine API                        |
| 5432           | postgres | Rejects logins, logs attempted usernames      |
| 1433           | mssql    | TDS prelogin handshake                        |
| 27017          | mongo    | Answers ismaster probes                       |
| 3389           | rdp      | X.224 connection confirm                      |

The fake shell answers `whoami`, `uname -a`, `ls`, `cat /etc/passwd`, `ps`,
`ifconfig`, `wget`/`curl` (URLs are **logged, never fetched**), and more —
up to 60 commands per session, then disconnects.

Replay one visitor's whole session with:

```bash
grep <session-id> logs/events.jsonl
```

## Run it

Standard ports need privileges — either run as root or grant the capability
once:

```bash
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
python3 honeypot.py
```

Then, in another terminal, pretend to be an attacker:

```bash
# knock on the fake SSH (any password works — that's the trap)
ssh -p 22 root@localhost

# try the fake WordPress login
curl http://localhost/wp-login.php

# talk to the fake redis
printf 'PING\r\n' | nc localhost 6379
```

Watch the console — or open `logs/events.jsonl` — to see each attempt logged.

## Customize

```bash
# high ports, no privileges needed (good for local testing)
python3 honeypot.py --ports "2222:ssh,8080:http,2121:ftp"

# persona mode: present a coherent cover identity, not all 14 services
python3 honeypot.py --profile profiles/small-business.json

# different log file
python3 honeypot.py --log /tmp/honeypot.jsonl

# live monitoring hook (see monitor_example.py)
```

Services available: `ssh`, `telnet`, `http`, `ftp`, `mysql`, `redis`, `smtp`,
`vnc`, `elastic`, `docker`, `postgres`, `mssql`, `mongo`, `rdp`, `generic`.

**Persona profiles** (`--profile`): instead of all 14 services at once, run a
believable subset so the honeypot reads as one real machine. A scanner that
sees every port open knows it's a honeypot — coherent story beats a
40-port buffet. See `PROFILES.md` and `profiles/small-business.json`.

## Who's knocking?

Every event already logs the visitor's `src_ip`. To see all attacker IPs
with GeoIP + ISP/ASN info:

```bash
python3 ip_intel.py
```

Sample output:

```
IP              HITS  COUNTRY       CITY              ISP / ORG
8.8.8.8         2     United States Ashburn           Google LLC AS15169
```

Heads-up: GeoIP is approximate, and an IP is not a person — scanners usually
come from compromised hosts, VPNs, or cloud servers. Treat it as intel about
infrastructure, not proof of who did it.

## Safety rules (hard)

- Nothing a visitor sends is executed, evaluated, or fetched. The fake `wget`
  prints a convincing "saved" message, but the file never exists.
- Flood protection: each service caps at 50 concurrent connections; excess
  connections are dropped immediately (counted in the log, not logged
  one-by-one) so a connection flood can't exhaust the machine or the disk.
- Only run it on machines/networks you own or have permission to test. A
  public honeypot **will** attract real scanners — that is the point, but go
  in with your eyes open.

## Notes for learning

- Deliberately low-interaction: convincing enough to harvest credentials,
  commands, and payload URLs, but it can never be turned into a weapon.
- Interesting next steps: GeoIP-enrich the logs, count unique attacker IPs
  per day, alert on first-seen payload URLs, or compare notes with public
  honeypot datasets (e.g. GreyNoise).

## mini-SIEM (`siem.py`)

A tiny detection engine that tails the honeypot log and fires alerts —
your first step into detection engineering (the blue-team half of purple).

```bash
python3 siem.py              # live mode: watch for new attacks as they happen
python3 siem.py --replay     # analyze the existing log from the top
```

Detection rules (tune the thresholds at the top of the file — that's the job):

| Rule | ATT&CK | Severity | Fires when |
|------|--------|----------|------------|
| BRUTE_FORCE | T1110 | HIGH | 5+ logins from one IP in 60s |
| PORT_SCAN | T1046 | MEDIUM | 6+ distinct ports from one IP in 30s |
| WEB_PROBING | T1595.002 | MEDIUM | 3+ suspicious paths from one IP in 60s |
| SHELL_ACCESS | T1078 | CRITICAL | any interactive shell session, ever |
| AI_AGENT | T1595 | HIGH | session shows AI-agent tradecraft: tripwire obedience, machine command rhythm, exhaustive enumeration |
| HONEYCREDS | T1078 | CRITICAL | a canary credential file is read, or fake creds are used in the shell (`aws ...`) — instant, no threshold |
| EXPLOIT_PROBE | T1190 | CRITICAL | a known exploit signature (Log4Shell, path traversal, command/SQL injection) appears in any visitor input, or an exploit-bait endpoint is touched — instant, no threshold |

Try it: start the honeypot, run `siem.py` in a second terminal, then attack
from a third — run Lab 0's scan and watch your own attack get detected.
That's the purple-team loop in one screen: red on the left, blue on the right.

## Fortress upgrade pack — four new countermeasures

Built adversarially: each one assumes a skilled red team, not a script
kiddie. Every countermeasure documents what it catches *and* its honest
blind spots — in the code comments and below.

### 1. Honey credentials (`honeycreds.py`)

Canary decoy credentials planted where attackers look first:

```bash
python3 honeycreds.py          # self-test: verifies all 6 canary files
```

- Plants fake AWS keys (`/root/.aws/credentials`), AWS config, DB
  credentials (`/root/secrets/db_credentials.txt`), API tokens
  (`/root/secrets/api_tokens.env`), a vault-path variant
  (`/backup/secure/db_credentials.txt`), and an in-character breadcrumb
  (`/root/keys_readme.txt`) pointing at them all.
- Every value is obviously fake (`AKIAHONEY…`, `HONEY_FAKE_…`) and every
  file carries a `HONEYTOKEN — FAKE CREDENTIALS` header. The "this is a
  decoy" disclosure lives in file headers and code comments, never in the
  attacker's face.
- The fake shell grew a fake `aws` command: any invocation
  "authenticates" and returns canned output (never touches the network).
- Reading a canary (`cat`, `less`, `head`, `tail`, `more`, `strings`,
  `grep`) logs `honeycreds_read=<path>`; using one logs
  `honeycreds_used=<args>`. The SIEM's **HONEYCREDS** rule fires CRITICAL
  instantly on either — no threshold to stay under, so low-and-slow
  doesn't help the attacker.
- Honest blind spots: exotic readers (`sed -n`, `awk`, `xxd`,
  copy-then-read via `cp`) bypass the read hook — but the moment stolen
  creds get *used*, the use-tripwire fires. Cross-service reuse (fake AWS
  secret tried as an SSH password) is logged at the service layer;
  correlating "same secret, many services" is future work. A skilled
  attacker may recognize canary formats and avoid them — accepted:
  canaries are for the greedy and cost nothing to plant.

### 2. Tarpit everything (`tarpit.py`)

The SSH tarpit now has siblings — same JSON event schema, same drip
philosophy, new protocols:

```bash
python3 tarpit.py --mode ssh                  # :2222 (original)
python3 tarpit.py --mode http --port 8080     # dribbles HTTP headers forever
python3 tarpit.py --mode smtp --port 2525     # dribbles SMTP greetings forever
```

- HTTP mode reads the request line, then dribbles one response header per
  interval — the blank end-of-headers line and the body never come.
- SMTP mode sends its `220` banner, then dribbles `250-` capability lines;
  the final `250 ` (space form) that would let the client proceed is never
  sent.
- Anti-fingerprinting: every drip interval is jittered
  (`delay × uniform(0.7, 1.4)`, `--no-jitter` for demo contrast) and line
  content rotates per connection, specifically to frustrate timing
  analysis. Garbage input is logged and silently discarded, never echoed.
- Self-defense: `--max-conn` (default 200) sheds excess connections with
  a `tarpit_shed` log entry; default ports (2222/8080/2525) deliberately
  avoid the honeypot's real trap ports (22/80/25).
- Honest blind spots: short client timeouts defeat any tarpit trivially
  (accepted — the threat model is time-theft, not invisibility); a
  patient analyst will eventually classify the never-finishing drip.
  Even a detected tarpit costs the attacker analysis time.

### 3. Graduated response (`blocker.py`)

The blocker no longer slams the door on the first alert. Per-IP, per-rule
escalation ladder:

| Strike | Level | Action |
|--------|-------|--------|
| 1 | WATCH | log only — no firewall touch |
| 2 | ESCALATE | prominent log + persisted flag — still no firewall |
| 3+ | BLOCK | iptables DROP, duration doubles per strike (base → 2× → 4×, capped 24h) |

Base durations: SHELL_ACCESS 120m, HONEYCREDS 120m, BRUTE_FORCE 60m,
PORT_SCAN 30m, WEB_PROBING 30m. Dry-run stays the default; loopback, the
host's own addresses, the allowlist, and invalid IPs are never blocked;
strikes decay after 24h of silence; state persists in
`blocker-state.json` (old-format entries load as strike-3 blocks).

- **Distributed-IP evasion:** the ladder is per-IP, so N IPs with 1–2
  strikes each never reach BLOCK. Counter: a log-only SWARM tripwire —
  5+ distinct IPs reaching WATCH+ on the same rule within 10 minutes logs
  `SWARM suspected distributed <rule>` (never auto-blocks; aggregate
  auto-blocking is a self-DoS footgun).
- Honest blind spots: an attacker holding at exactly 2 strikes per IP
  lives in ESCALATE forever — accepted on purpose, since WATCH/ESCALATE's
  value is the analyst's log trail, not the block. SIEM cooldowns mean
  strikes arrive ~10 min apart per rule, so BLOCK needs ~20+ min of
  sustained malice — that's the point. `alerts.jsonl` must be writable
  only by the SIEM user: forged alerts could farm blocks in --enforce.
- A true tarpit-redirect (`iptables -j REDIRECT` into the tarpit instead
  of DROP) is sketched in the code comments but deliberately not
  enforced — it needs topology decisions this lab doesn't make for you.

### 4. Watermarked decoys (`vault.py`, `verify_watermark.py`)

Every SQL dump and CSV the vault generates now carries this deployment's
unique id in three places — header, footer, and mid-file row checkpoints:

```bash
python3 verify_watermark.py suspect_dump.sql
# MATCH <id>        -> leaked from THIS fortress (exit 0)
# NO-MATCH <id>     -> leaked from a DIFFERENT deployment (exit 2)
# NO-WATERMARK      -> stripped, or never ours (exit 1)
```

- The id is minted once per deployment (`vault_id.txt`, runtime-only —
  never shipped in the zip) and overridable via `VAULT_ID` for
  replicas/tests. 16 hex chars: unguessable, and output stays
  deterministic within a deployment.
- Checkpoints survive truncation (head/tail cuts, header-only deletion),
  but a full comment-strip (`grep -v '^--'`) removes every mark at once —
  the three markers defend against sloppy handling, not a determined
  cleaner. The verifier reports *all* ids found in chaffed (mixed-source)
  files, each marked THIS/FOREIGN.

**How watermarking works in the real world.** This is a *canary trap* —
the oldest trick in counter-intelligence: give each suspect a slightly
different document, then see which version leaks. The same idea is
everywhere today: publishers fingerprint review copies to catch leakers,
data vendors trace which customer re-sold a dataset, and AI labs
watermark training data to detect their corpora inside someone else's
model. Honest limits: normalization is the hard blind spot (re-export
just the rows, or CSV→JSON, and every comment-mark dies); a watermark
proves a leak's **source**, never the leaker's identity; and one marker
is never enough — which is why we embed three.

## Fortress full stack — four more countermeasures

Built adversarially like the upgrade pack: each one assumes a skilled red
team, documents what it catches *and* its honest blind spots.

### 5. Fake aliveness (`aliveness.py`)

A background-noise generator so the "server" looks lived-in when no
attacker is around:

```bash
python3 honeypot.py --aliveness        # spawn it alongside the honeypot
python3 aliveness.py --once           # emit one event (testing)
python3 aliveness.py --self-test      # 9 checks: schema, clean data, chain
```

- Emits ~90 synthetic events/hour at defaults: SSH logins/logouts, cron
  completions, HTTP health-check hits, FTP backup logins, nightly backup
  notices (01:00–05:00 UTC). Interval (`--interval`, default 45s) and
  jitter are tunable; `--seed` reproduces a run.
- **Every synthetic event carries `"synthetic": true`** and the SIEM
  skips synthetic events *first* in `Engine.handle()` — the fortress can
  never detect itself. Synthetic data is also scrubbed of all
  exploit-signature substrings (defense in depth).
- The fake shell's `who`/`last` show the synthetic users (deterministic
  per 30-minute slot, 0–2 users) — pure theater for anyone who breaks in.
- Honest blind spots: events, the `who` roster, and `last` output are
  only loosely consistent (a login event doesn't put that user in the
  roster) — approximate theater, not a lie that survives a careful
  adversary. The roster can be empty and flickers at slot boundaries.

### 6. Tamper-evident logging (`chainlog.py`, `verify_chain.py`)

Every event the honeypot or aliveness writes is hash-chained:

```bash
python3 verify_chain.py                 # verify logs/events.jsonl
# OK: 128 chained lines verified ...   -> exit 0 (intact)
# BROKEN at line 57: hash mismatch      -> exit 1 (tampered)
```

- Each line gains `prev_hash` + `hash` = SHA256(prev_hash +
  canonical-JSON-of-event). Appends happen under an exclusive file lock,
  so the honeypot's threads and the aliveness process can't fork the chain.
- `verify_chain.py` tolerates pre-chain (unchained) lines and reports the
  chain-start boundary instead of crying tamper.
- Honest blind spots: **tail truncation still verifies** — deleting lines
  off the end is invisible to the chain (pair with external line-count
  monitoring). Only the last 64 KiB is scanned for the chain tip, so
  rotate logs on a busy honeypot.

### 7. Fake vulnerabilities as tripwires (`exploitwatch.py`)

A signature watcher over *all* visitor input — a camera, never a door:

```bash
python3 exploitwatch.py --self-test   # 13 patterns, 24 checks
```

- 13 substring patterns: Log4Shell (`${jndi:`), path traversal
  (`../..`, `%2e%2e`, `..;/`), command injection (`;cat /etc/passwd`,
  `|/bin/id`, …), command substitution (`$(`, `` `id` ``), SQLi
  (`union select`, `' or '1'='1`, …). `find_exploit()` never raises and
  never matches the honeypot's own normal traffic (bare `cat
  /etc/passwd`, bare `id`, plain requests stay silent).
- Any match logs `exploit_probe=<pattern>` and the SIEM's
  **EXPLOIT_PROBE** rule fires CRITICAL instantly — the payload is never
  executed, the event *is* the tripwire.
- Seven exploit-bait HTTP paths (`/debug/console`, `/struts2-showcase`,
  `/solr/admin`, …) serve a static fake "debug console" with
  famous-vulnerability version strings; any touch logs `exploit_probe`.
- Honest blind spots: double-encoded/obfuscated payloads, payloads split
  across multiple events, polyglot evasions, and novel signatures all
  evade substring matching; only the first matching pattern is reported.

### 8. Session recording (fake shell + `dashboard.py`)

Every fake-shell session's full transcript is recorded to
`logs/sessions/<session-id>.jsonl` (timestamped commands in, output out)
— newest 200 kept, oldest pruned automatically. The dashboard grew a
**SESSION REPLAYS** section: newest-first session list, click any row to
replay the transcript in the browser. Forensics gold: watch exactly what
an intruder typed and what the fortress showed them.

## Dashboard (`dashboard.py`)

A SOC-style web interface for the mini-SIEM. Run it alongside the honeypot:

```bash
python3 dashboard.py
# open http://127.0.0.1:8080 in your browser
```

Live stat cards (events seen, alerts by severity) plus a streaming alert table
with severity badges, rule names, and MITRE ATT&CK IDs. It refreshes every
2 seconds. Attack the honeypot from another terminal and watch the alerts
land in real time — red team on the left, blue team in the browser.

## Sandboxed deployment (Docker)

For internet-facing deployments, run the honeypot in a container so a bug
in the honeypot itself can't become a foothold on your host:

```bash
docker compose up --build -d
```

Hardening in place: non-root user, read-only filesystem, all Linux
capabilities dropped except `NET_BIND_SERVICE`, `no-new-privileges`, and
logs written to `./logs/` on the host (where `siem.py` and `dashboard.py`
can still read them — run those on the host, not in the container).
