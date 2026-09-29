# Persona profiles — one coherent cover identity

By default the honeypot runs all 14 fake services at once. That's great for
learning and for catching the widest range of scanners. But a scanner that
sees *every* port open knows it's looking at a honeypot — no real machine
runs FTP, Telnet, VNC, Redis, MongoDB, Elasticsearch, Docker, Postgres,
MSSQL, MySQL, RDP, SMTP, SSH, and a web server all at once.

**Coherent story beats a 40-port buffet.** A profile picks a believable
subset of services so the honeypot reads as one real machine with one job.
Attackers bite on stories, not buffets — and the best trap is the one that
doesn't look like one.

## Usage

```bash
# persona mode: only the profile's services start
python3 honeypot.py --profile profiles/small-business.json

# --profile overrides --ports when both are given
```

Default behavior is unchanged: run with no flags and all 14 services start
exactly as before.

## The bundled profile: small-business.json

**"Small Business Server"** — the single do-everything box of a fictional
20-person outdoor-gear retailer (Harbor & Pine Outfitters): company website,
mail, file sharing, and the store database on one machine, because that's
what small businesses actually do.

| Port | Service | Role in the story |
|------|---------|-------------------|
| 22   | ssh     | remote admin |
| 80   | http    | company website |
| 25   | smtp    | company mail |
| 21   | ftp     | file sharing with vendors |
| 3306 | mysql   | database behind the website |
| 3389 | rdp     | Windows admin |

Deliberately left out (documented in the profile's `deception_notes`):
**telnet** (dead giveaway on a modern box), **redis / elasticsearch /
mongodb** (exotic for a 20-person retailer), **docker** (dev-ops smell, not
retail), **vnc** (redundant next to RDP), **postgres / mssql** (one database
is the believable choice — MySQL backs the website).

## Writing your own profile

A profile is a JSON object:

```json
{
  "name": "Small Business Server",
  "company": "Harbor & Pine Outfitters (fictional)",
  "backstory": "One or two sentences: what is this machine supposed to be?",
  "deception_notes": "Why these services, and why the rest are left out. Future-you will thank present-you.",
  "services": {
    "ssh": 22,
    "http": 8080
  }
}
```

Rules:

- `services` maps a **service key** (see list below) to a **port number**.
- Unknown service keys, non-numeric ports, and out-of-range ports fail fast
  with a clear error — better than starting half a honeypot.
- An empty `services` object is rejected: a honeypot with no doors is just
  a log file.
- Only `name`, `company`, `backstory`, `deception_notes`, and `services`
  are read; extra fields are ignored.

**Picking services — the deception checklist:**

1. Tell ONE story (a web shop, a dev server, a branch-office file server).
2. Every open port must earn its place in that story.
3. Leave out anything anachronistic (telnet in 2026) or redundant (two
   databases, two remote-desktop protocols).
4. Fewer, believable doors beat many suspicious ones.

## Available service keys

| Key | Default port | What it fakes |
|-----|--------------|---------------|
| `ssh` | 22 | OpenSSH banner, accepts any login → fake shell |
| `telnet` | 23 | RouterOS-style login → fake shell |
| `http` | 80 | Router / WordPress / phpMyAdmin login pages |
| `ftp` | 21 | vsFTPd banner, harvests credential guesses |
| `mysql` | 3306 | Plausible handshake, logs scanner replies |
| `redis` | 6379 | Answers PING, rejects AUTH, logs commands |
| `smtp` | 25 | Fake Postfix, logs mail attempts (never relays) |
| `vnc` | 5900 | RFB banner + auth challenge |
| `elastic` | 9200 | Fake Elasticsearch node info |
| `docker` | 2375 | Fake Docker Engine API |
| `postgres` | 5432 | Rejects logins, logs attempted usernames |
| `mssql` | 1433 | TDS prelogin handshake |
| `mongo` | 27017 | Answers ismaster probes |
| `rdp` | 3389 | X.224 connection confirm |
| `generic` | — | Just listens and logs (no default port) |

## Why profiles can't change banners or hostnames

The fake hostname (`router`), the SSH/FTP banners, and the HTTP `Server:`
header are baked into the service handlers and the fake shell's filesystem
(a small-business box wouldn't call itself "router"). Making them
per-profile would mean threading configuration through every handler and the
fake shell — doable, but it risks breaking the tested deception behavior for
little gain. The port *selection* is what sells the story; the banners are
already generic enough to pass. If you need a different hostname, edit the
constants at the top of `honeypot.py` (`SSH_BANNER`, `FTP_BANNER`,
`FAKE_FILES["/etc/hostname"]`, `SHELL_PROMPT`).
