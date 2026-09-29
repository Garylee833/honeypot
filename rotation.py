#!/usr/bin/env python3
"""rotation.py — rotating deception (Layer 2).

An attacker who maps the fortress once must not own a permanent map.
This module rotates the externally-visible details on a schedule (and on
every fortress restart): service banners, shell jitter ranges, honeytoken
file placement, and exploit-bait page dressing.

Design:
  - Variant pools live below. rotate(seed=None) picks one variant per slot
    with a seeded PRNG, stores the pick in ACTIVE, and persists
    {seed, rotated_at, count} to logs/rotation-state.json.
  - Deterministic-seedable: rotate(seed=X) twice yields the identical ACTIVE
    dict — lab runs stay reproducible. Unseeded rotations chain forward
    (seed = base + count) so a long-lived fortress never repeats itself.
  - The honeypot calls rotate() once at startup and again on a timer
    (see honeypot.py main()); apply() pushes the pick into the honeypot's
    banner globals, jitter range, bait page, and honeycred planting.
  - Honeytoken VALUES stay deployment-stable (honeycreds.DEFAULT_SEED):
    only placement/names rotate. The SIEM loads canary values once at its
    own import, so rotating values would blind its use-detection in a
    separate process. Placement rotation is the safe win.

Nothing here opens a listener, blocks, or drops. It only changes what the
theater looks like.
"""

import json
import os
import random
import time

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "logs", "rotation-state.json")

# --- variant pools --------------------------------------------------------
SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    b"SSH-2.0-OpenSSH_9.3p1 Debian-1\r\n",
    b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
    b"SSH-2.0-dropbear_2020.81\r\n",
]

FTP_BANNERS = [
    b"220 (vsFTPd 3.0.3)\r\n",
    b"220 ProFTPD 1.3.7a Server (Debian)\r\n",
    b"220---------- Welcome to Pure-FTPd [privsep] ----------\r\n",
]

HTTP_SERVER_HEADERS = [
    "nginx/1.18.0",
    "Apache/2.4.41 (Ubuntu)",
    "nginx/1.24.0",
]

SMTP_BANNERS = [
    b"220 mail.router.local ESMTP Postfix 3.6.4\r\n",
    b"220 router.local ESMTP Sendmail 8.17.1\r\n",
    b"220 mail.router.local ESMTP Exim 4.96\r\n",
]

MYSQL_VERSIONS = [
    b"5.7.44-log",
    b"8.0.35",
    b"10.6.12-MariaDB",
]

# Shell jitter ranges (seconds): the fake shell sleeps a uniform draw from
# the active range before answering. Rotation keeps timing analysis stale.
JITTER_RANGES = [
    (0.005, 0.040),
    (0.010, 0.080),
    (0.020, 0.120),
]

# Exploit-bait dressing: version strings spliced into the debug-console
# bait page. (Per-attack-string variance already lives in honeypot.py's
# _exploit_bait_variant(); this rotates the page's background details.)
BAIT_DRESSINGS = [
    {"log4j": "2.14.0", "struts": "2.5.26", "solr": "8.11.1",
     "ticket": "SEC-8841"},
    {"log4j": "2.17.1", "struts": "2.5.30", "solr": "8.11.2",
     "ticket": "SEC-9120"},
    {"log4j": "2.14.1", "struts": "6.1.2", "solr": "9.3.0",
     "ticket": "SEC-7702"},
]

# Honeytoken placements: path -> content kind. Parent dirs must exist in
# the shell (honeypot.py FAKE_DIRS lists them all, so `cd`/`ls` work).
# Kinds: aws, aws_config, db, api, backup_db, readme.
TOKEN_PLACEMENTS = [
    {  # 0: the classic scattered layout
        "/root/.aws/credentials": "aws",
        "/root/.aws/config": "aws_config",
        "/root/secrets/db_credentials.txt": "db",
        "/root/secrets/api_tokens.env": "api",
        "/backup/secure/db_credentials.txt": "backup_db",
        "/root/keys_readme.txt": "readme",
    },
    {  # 1: deploy-user layout
        "/home/deploy/.aws/credentials": "aws",
        "/home/deploy/.aws/config": "aws_config",
        "/srv/app/.env.production": "db",
        "/root/.config/tokens.env": "api",
        "/var/backups/db_credentials.txt": "backup_db",
        "/home/deploy/NOTES.txt": "readme",
    },
    {  # 2: ops-toolbox layout
        "/opt/keys/aws_credentials": "aws",
        "/opt/keys/aws_config": "aws_config",
        "/root/db_credentials.txt": "db",
        "/srv/app/api_tokens.env": "api",
        "/backup/secure/db_credentials.txt": "backup_db",
        "/root/keys_readme.txt": "readme",
    },
]

# Parent dirs for every path used above (wired into FAKE_DIRS by apply()).
TOKEN_PARENT_DIRS = ["/home/deploy", "/home/deploy/.aws", "/srv/app",
                     "/root/.config", "/opt/keys", "/var/backups",
                     "/root/.aws", "/root/secrets"]

# Directories whose listings are PURELY canary homes: apply() rewrites
# their FAKE_DIRS entry from the live placement so `ls` never shows
# files that are no longer planted (no stale-listing seam).
CANARY_HOME_DIRS = ("/root/.aws", "/root/secrets")

ACTIVE = {}          # the current pick: slot -> variant
_ROTATION_COUNT = 0
_BASE_SEED = None


# --- core -----------------------------------------------------------------
def _pick(rng):
    return {
        "ssh_banner": rng.choice(SSH_BANNERS).decode("utf-8", "replace"),
        "ftp_banner": rng.choice(FTP_BANNERS).decode("utf-8", "replace"),
        "http_header": rng.choice(HTTP_SERVER_HEADERS),
        "smtp_banner": rng.choice(SMTP_BANNERS).decode("utf-8", "replace"),
        "mysql_version": rng.choice(MYSQL_VERSIONS).decode("utf-8", "replace"),
        "jitter": rng.choice(JITTER_RANGES),
        "bait": rng.choice(BAIT_DRESSINGS),
        "tokens": rng.choice(TOKEN_PLACEMENTS),
    }


def rotate(seed=None):
    """Pick a fresh deception config. Seedable: same seed -> same ACTIVE."""
    global ACTIVE, _ROTATION_COUNT, _BASE_SEED
    if seed is None:
        seed = (_BASE_SEED + _ROTATION_COUNT) if _BASE_SEED is not None \
            else random.SystemRandom().randint(0, 2**31 - 1)
    else:
        _BASE_SEED = seed
    rng = random.Random(seed)
    ACTIVE = _pick(rng)
    _ROTATION_COUNT += 1
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"seed": seed, "rotated_at": time.time(),
                       "count": _ROTATION_COUNT, "active": {
                           k: (list(v) if isinstance(v, tuple) else v)
                           for k, v in ACTIVE.items()
                           if k != "tokens"}},
                      fh)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass  # rotation state is a nicety
    return ACTIVE


def current(slot, default=None):
    """Read the active variant for a slot ("" for the whole dict)."""
    if not slot:
        return dict(ACTIVE)
    return ACTIVE.get(slot, default)


# --- application ----------------------------------------------------------
def _readme_for(placement):
    """In-character breadcrumb pointing at the CURRENT token paths."""
    lines = ["keys & creds - jdoe, updated mar"]
    label = {"aws": "aws cli creds", "aws_config": "aws cli config",
             "db": "db creds", "api": "api tokens",
             "backup_db": "old backup creds copy"}
    for path, kind in placement.items():
        if kind in label:
            lines.append(f"- {label[kind]}: {path}")
    lines.append("TODO: move all this to the vault already (ticket EXAMPLE-2041)")
    lines.append("")
    return "\n".join(lines)


def replant_honeycreds(placement, seed=None):
    """Re-plant canary files at the rotated paths (values stay stable).

    Atomically REBINDS honeycreds.HONEYCREDS_FILES (one pointer swap) so
    is_honeycred_path() and the shell's cat hook follow the rotation with
    no restart. Mutating in place instead would leave a window where
    concurrent lookups see the post-reload default placement — a real
    canary read could go untripped while threads run.
    """
    import honeycreds
    import importlib
    importlib.reload(honeycreds)  # fresh deterministic values
    full = honeycreds.HONEYCREDS_FILES
    by_kind = {
        "aws": full["/root/.aws/credentials"],
        "aws_config": full["/root/.aws/config"],
        "db": full["/root/secrets/db_credentials.txt"],
        "api": full["/root/secrets/api_tokens.env"],
        "backup_db": full["/backup/secure/db_credentials.txt"],
    }
    new = {}
    for path, kind in placement.items():
        if kind == "readme":
            new[path] = _readme_for(placement)
        else:
            new[path] = by_kind[kind]
    honeycreds.HONEYCREDS_FILES = new  # atomic: no torn intermediate state
    return sorted(new)


def apply(honeypot):
    """Push ACTIVE into the honeypot module's globals. Never raises."""
    try:
        if not ACTIVE:
            rotate()
        honeypot.SSH_BANNER = ACTIVE["ssh_banner"].encode()
        honeypot.FTP_BANNER = ACTIVE["ftp_banner"].encode()
        honeypot.HTTP_SERVER_HEADER = ACTIVE["http_header"]
        honeypot.SMTP_BANNER = ACTIVE["smtp_banner"].encode()
        honeypot.MYSQL_VERSION = ACTIVE["mysql_version"].encode()
        honeypot.SHELL_JITTER = ACTIVE["jitter"]
        for d in TOKEN_PARENT_DIRS:
            honeypot.FAKE_DIRS.setdefault(d, [])
        # Rebuild the exploit-bait page with the rotated dressing.
        b = ACTIVE["bait"]
        honeypot.PAGE_DEBUG_BAIT = (
            "<html><head><title>Debug Console</title></head><body>\n"
            "<h2>Internal debug console</h2>\n"
            "<pre>log4j-core %s initialized\n"
            "struts %s showcase deployed\n"
            "solr %s admin handler ready\n"
            "</pre>\n"
            "<p><i>Authorized personnel only. Ticket %s.</i></p></body></html>"
            % (b["log4j"], b["struts"], b["solr"], b["ticket"]))
        planted = replant_honeycreds(ACTIVE["tokens"])
        # Rewrite pure canary-home listings from the live placement.
        for _d in CANARY_HOME_DIRS:
            honeypot.FAKE_DIRS[_d] = sorted(
                p.rsplit("/", 1)[-1] for p in planted if p.rsplit("/", 1)[0] == _d)
        print(f"[*] rotation applied: banners/jitter/bait/tokens "
              f"({len(planted)} canaries planted)", flush=True)
        return True
    except Exception as e:
        print(f"[!] rotation apply failed ({e}); keeping defaults", flush=True)
        return False


# --- self-test ------------------------------------------------------------
def self_test():
    """Seedability + variance + apply() checks. Raises on failure."""
    import tempfile
    global STATE_FILE
    STATE_FILE, _old = os.path.join(tempfile.mkdtemp(), "rot.json"), STATE_FILE

    a1 = rotate(seed=42)
    a2 = rotate(seed=42)
    assert a1 == a2, "same seed gave different ACTIVE"
    b = rotate(seed=43)
    diff = sum(1 for k in a1 if a1[k] != b[k])
    assert diff >= 3, f"seed 43 barely differs from 42 ({diff} slots)"

    # jitter is a sane (lo, hi) range
    lo, hi = a1["jitter"]
    assert 0 <= lo < hi <= 0.5, f"jitter range insane: {(lo, hi)}"

    # tokens: every placement covers all 6 kinds, paths are absolute
    for placement in TOKEN_PLACEMENTS:
        assert sorted(placement.values()) == \
            ["api", "aws", "aws_config", "backup_db", "db", "readme"], \
            f"placement missing kinds: {placement}"
        assert all(p.startswith("/") for p in placement), "relative token path"

    # apply() against a fake honeypot module namespace
    import types
    hp = types.SimpleNamespace(
        SSH_BANNER=b"", FTP_BANNER=b"", HTTP_SERVER_HEADER="",
        SMTP_BANNER=b"", MYSQL_VERSION=b"", SHELL_JITTER=(0, 0),
        FAKE_DIRS={"/root": ["x"]}, PAGE_DEBUG_BAIT="")
    rotate(seed=7)
    assert apply(hp) is True
    assert hp.SSH_BANNER.startswith(b"SSH-2.0-")
    assert hp.HTTP_SERVER_HEADER in HTTP_SERVER_HEADERS
    lo, hi = hp.SHELL_JITTER
    assert 0 <= lo < hi
    for d in TOKEN_PARENT_DIRS:
        assert d in hp.FAKE_DIRS, f"parent dir not registered: {d}"
    assert "log4j-core" in hp.PAGE_DEBUG_BAIT
    import honeycreds
    assert len(honeycreds.HONEYCREDS_FILES) == 6
    # readme points at the actually-planted paths (no stale breadcrumbs)
    readme = next(v for k, v in honeycreds.HONEYCREDS_FILES.items()
                  if k.endswith("NOTES.txt") or k.endswith("keys_readme.txt"))
    for p in honeycreds.HONEYCREDS_FILES:
        if "NOTES" in p or "readme" in p:
            continue
        assert p in readme, f"readme stale: {p} not mentioned"

    # unseeded rotation still works and advances the count
    c1 = rotate()
    c2 = rotate()
    assert isinstance(c1, dict) and isinstance(c2, dict)

    STATE_FILE = _old
    print("[self-test] OK: seedable, variant pools sane, apply() pushes "
          "banners/jitter/bait/tokens, readme tracks placement")


if __name__ == "__main__":
    self_test()
