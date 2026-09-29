#!/usr/bin/env python3
"""honeycreds — canary (decoy) credentials for the educational honeypot.

Plants obviously-fake credential files in the fake shell's filesystem so that
any visitor who reads or *uses* them trips a HONEYCREDS alert in the SIEM.
These are canaries, not traps for the innocent: every fake secret contains
an obvious in-value marker (HONEY / FAKE / EXAMPLE), and the values could
never authenticate anywhere real. Nothing here ever touches the network —
the fake `aws` command answers from canned text.

Deception doctrine: the planted files carry NO explanatory labels or
disclosures ("HONEYTOKEN", "decoy", "not real"). A real leaked-credentials
file never announces itself, and a label is a fingerprinting tell. The
values themselves stay visibly fake (AKIA...HONEY..., HONEY_FAKE_...)
so a human reader can tell at a glance — the honesty lives in the values,
never in a whispered warning.

Adversarial notes (think like the red team):
- Low-and-slow: IRRELEVANT here. HONEYCREDS is an instant tripwire — one read
  or one `aws` use fires immediately. There is no threshold to stay under.
- Reader coverage: the shell hooks cat/less/more/head/tail/strings (and grep
  for logging). Readers NOT hooked: sed -n, awk, xxd, `base64 <file>`, and
  copy-then-read (`cp /root/.aws/credentials /tmp/x` + read /tmp/x). Be
  honest about that: a skilled attacker who copies the file elsewhere and
  reads the copy evades the *read* hook. But the kill chain doesn't end at
  the read — the moment they actually USE the creds (`aws sts ...`) the
  honeycreds_used tripwire fires. The canary's primary trip is use-as-creds,
  not just eyeballing the file.
- Credential reuse across services: if the attacker tries the fake AWS secret
  as an SSH password or MySQL login, the honeypot already logs
  "password=<value>" at the service layer. Correlating "same presented
  secret across services" in the SIEM is future work; the canary's primary
  trip today is use-as-AWS-creds via the fake `aws` command.
- Canary-format recognition: a skilled attacker may recognize canary token
  formats and deliberately avoid touching them. Accepted blind spot —
  canaries are for the greedy and the careless, and the tripwire costs us
  nothing to plant.
- Distributed IPs: each source IP trips independently; there is no
  cross-IP correlation in this build.

Usage:
    import honeycreds
    honeycreds.HONEYCREDS_FILES["/root/.aws/credentials"]  # decoy content
    honeycreds.is_honeycred_path(".aws/credentials")       # True
    honeycreds.fake_aws_output(["sts", "get-caller-identity"])
"""

import json
import os
import random

# Fixed seed -> every deployment plants identical decoys. Re-seed for a
# real deployment if you want unique canaries per site.
DEFAULT_SEED = 20260917

# Obvious in-value markers. Every planted file must contain at least one;
# they are the "this is fake" signal now that disclosure headers are gone.
_FAKE_MARKERS = ("HONEY", "FAKE", "EXAMPLE")

# Disclosure labels that must NEVER appear in planted content. A real
# leaked file never announces itself; these strings are a deception tell.
# (Realistic in-character admin notes like "DO NOT COMMIT" are fine and
# stay — they are what a sloppy admin would actually write.)
_BANNED_LABELS = ("honeytoken", "decoy", "not real", "fake credentials",
                  "this is a canary")


def _rand_b64(rng, n):
    alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/")
    return "".join(rng.choice(alphabet) for _ in range(n))


def generate(seed=DEFAULT_SEED):
    """Build the canary file map: absolute shell path -> file content.

    Deterministic for a given seed (seeded PRNG), so every deployment of
    the honeypot plants the same decoys. Real deployments can pass a
    different seed for site-unique canaries.
    """
    rng = random.Random(seed)

    # AWS access key id: exactly 20 chars, starts with AKIA (real format),
    # but stuffed with HONEY so no scanner mistakes it for a live key.
    # 4 (AKIA) + 5 (HONEY) + 11 = 20. Count it, don't trust it.
    aws_key_id = "AKIA" + "HONEY" + "".join(
        rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(11))
    assert len(aws_key_id) == 20, "AWS key id must be exactly 20 chars"
    aws_secret = "HONEY" + _rand_b64(rng, 35)

    db_pass = "HONEY_FAKE_prod_" + "".join(
        rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(6)) + "!"
    backup_db_pass = "FAKEHONEY_backup_" + "".join(
        rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(6)) + "!"
    stripe_key = "sk_live_HONEYFAKE" + "".join(
        rng.choice("0123456789") for _ in range(16))
    github_token = "ghp_HONEYFAKEEXAMPLE" + "".join(
        rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(20))
    # AI API keys: the exact shape attackers hunt (thousands of hardcoded
    # LLM keys have turned up in public scans). Real format, HONEY-stuffed
    # so no scanner mistakes them for live keys. A read trips the canary;
    # a *use* trips it harder — same mechanics as every other honeycred.
    openai_key = "sk-proj-HONEYFAKE" + "".join(
        rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                   "0123456789") for _ in range(24))
    anthropic_key = "sk-ant-HONEYFAKE-" + "".join(
        rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                   "0123456789-_") for _ in range(24))

    return {
        "/root/.aws/credentials": "\n".join([
            "# aws cli credentials - prod backup account (rotated quarterly)",
            "[default]",
            "aws_access_key_id = " + aws_key_id,
            "aws_secret_access_key = " + aws_secret,
            "",
        ]),
        "/root/.aws/config": "\n".join([
            "[default]",
            "region = us-east-1",
            "output = json",
            "[profile prod-backup]",
            "region = us-east-1",
            "output = json",
            "# old sso (migrated mar): https://honey-example.awsapps.com",
            "",
        ]),
        "/root/secrets/db_credentials.txt": "\n".join([
            "# production database - rotated weekly, definitely not stale",
            "DB_HOST=db.internal.example",
            "DB_PORT=3306",
            "DB_NAME=prod_customers",
            "DB_USER=svc_backup",
            "DB_PASS=" + db_pass,
            "",
        ]),
        "/root/secrets/api_tokens.env": "\n".join([
            "# deploy tokens - do not paste into chat (learned that the hard way)",
            "STRIPE_SECRET_KEY=" + stripe_key,
            "GITHUB_TOKEN=" + github_token,
            "SLACK_WEBHOOK=https://hooks.slack.com/services/HONEY/FAKE/EXAMPLE",
            "",
        ]),
        # Vault path: vault.vault_ls("/backup/secure") lists this filename,
        # and the shell serves this fixed content (never vault's generated
        # text) via the honeycred hook in handle_command.
        "/backup/secure/db_credentials.txt": "\n".join([
            "# nightly backup credentials - DO NOT COMMIT",
            "DB_HOST=backup-db.internal.example",
            "DB_PORT=3306",
            "DB_NAME=prod_customers",
            "DB_USER=svc_backup_nightly",
            "DB_PASS=" + backup_db_pass,
            "",
        ]),
        # Breadcrumb: in-character sloppy-admin note pointing at the others.
        # No disclosure header — a real admin's keys_readme.txt would never
        # carry one. The honesty lives in the HONEY/FAKE-marked values.
        "/root/keys_readme.txt": "\n".join([
            "keys & creds - jdoe, updated mar",
            "- aws cli creds: ~/.aws/credentials (prod backup acct, has s3)",
            "- db creds: ~/secrets/db_credentials.txt",
            "- api tokens: ~/secrets/api_tokens.env",
            "- old backup creds copy: /backup/secure/db_credentials.txt",
            "- llm api keys: ~/.config/openai, ~/.config/anthropic (billing!)",
            "TODO: move all this to the vault already (ticket EXAMPLE-2041)",
            "",
        ]),
        # AI API-key canaries: the shape Bizarre Bazaar crews actually steal
        # and resell. Sloppy-admin placement — exactly where a real dev
        # leaves them.
        "/root/.config/openai/api_key": "\n".join([
            "# openai api key - billing acct, do not commit (again)",
            "OPENAI_API_KEY=" + openai_key,
            "",
        ]),
        "/root/.config/anthropic/api_key": "\n".join([
            "# anthropic api key - console, has usage quota",
            "ANTHROPIC_API_KEY=" + anthropic_key,
            "",
        ]),
    }


# Planted at import so the shell can serve them like FAKE_FILES.
HONEYCREDS_FILES = generate()

# The shell's `aws` command may reference this fake account id.
FAKE_AWS_ACCOUNT = "999988887777"  # obviously not a real account


# ---------------------------------------------------------------------------
# CRED_DUMP_DECOYS — credential-dump tripwire decoys (T1003 layer).
#
# Same planting mechanics as HONEYCREDS_FILES, but these exist for a different
# detection story: they look like the credential material an attacker
# *collects* (dumped DB passwords, an .aws bundle, a deploy .env) rather than
# canaries meant to be *used*. Reads of these files fire the SIEM's
# CRED_DUMP_TRIPWIRE rule (mapped T1003 — decoy-credential contact, honest
# PARTIAL: this does NOT detect real LSASS/memory dumping).
#
# Same doctrine as the canaries above: NO disclosure labels in the content
# ("HONEYTOKEN"/"decoy"/"not real" never appear — a real leaked file never
# announces itself). The values themselves are visibly fake
# (EXAMPLE / HONEY / FAKE markers) so a human reader can tell at a glance.
# Nothing here could authenticate anywhere real.
# ---------------------------------------------------------------------------
CRED_DUMP_DECOYS = {
    "/backup/db_passwords.txt": "\n".join([
        "# staging database passwords - rotated 2026-08-30 (ops ticket EXAMPLE-1187)",
        "# DO NOT COMMIT - Jenkins job DB-ROTATE pulls from here",
        "",
        "prod_replica:  dbadmin / HONEYpw_STAGing_FAKE_9x2",
        "analytics_ro:  reports  / FAKE_pw_analytics_EXAMPLE_77",
        "legacy_mysql:  root     / EXAMPLElegacy_FAKEpw_1969",
        "",
        "# old entries below, kept for rollback",
        "# billing_2019: svc_billing / HONEY_old_FAKE_2019",
        "",
    ]),
    "/home/admin/.aws/credentials": "\n".join([
        "[default]",
        "aws_access_key_id = AKIAHONEYFAKEEXAMPLE0",
        "aws_secret_access_key = HONEYfake/EXAMPLE+secret/key000000000000",
        "region = us-east-1",
        "",
        "[backup]",
        "aws_access_key_id = AKIAFAKEHONEYEXAMPLE1",
        "aws_secret_access_key = FAKEexample/HONEY+backup/key111111111111",
        "region = us-west-2",
        "",
    ]),
    "/opt/deploy/.env": "\n".join([
        "# deploy env - generated by ansible 2026-09-02, DO NOT EDIT BY HAND",
        "APP_ENV=production",
        "DB_HOST=db.internal.example",
        "DB_USER=deployer",
        'DB_PASS="HONEY_FAKE_deploy_EXAMPLE_pw42"',
        "REDIS_URL=redis://:FAKEhoneyEXAMPLEredis99@cache.internal.example:6379/0",
        "STRIPE_KEY=sk_test_FAKEHONEYEXAMPLE00000000000000",
        "ADMIN_TOKEN=HONEY_admin_FAKE_token_EXAMPLE_5150",
        "",
    ]),
}


def is_cred_dump_decoy(path):
    """True if path resolves to a planted credential-dump decoy file.

    Same normalization contract as is_honeycred_path: relative paths resolve
    against /root (matching the shell's cat), ".." and "//" collapse, so
    equivalent spellings still trip.
    """
    if not path:
        return False
    p = path if path.startswith("/") else "/root/" + path
    p = os.path.normpath(p.rstrip("/")) or "/"
    return p in CRED_DUMP_DECOYS


def is_honeycred_path(path):
    """True if path resolves to a planted canary file.

    Normalizes /root-relative paths exactly the way the shell's cat does
    ("foo" -> "/root/foo"), so `cat .aws/credentials` and
    `cat /root/.aws/credentials` both trip. Collapses ".." and "//" so
    sneaky-but-equivalent spellings still resolve.
    """
    if not path:
        return False
    p = path if path.startswith("/") else "/root/" + path
    p = os.path.normpath(p.rstrip("/")) or "/"
    return p in HONEYCREDS_FILES


def fake_aws_output(argv):
    """Plausible fake output for the shell's `aws` command.

    NEVER touches the network — every response is canned text. `argv` is
    the argument list after `aws` (already split, like handle_command does).
    """
    args = list(argv or [])
    if args[:2] == ["sts", "get-caller-identity"]:
        return json.dumps({
            "UserId": "AIDAHONEYEXAMPLEUSER01",
            "Account": FAKE_AWS_ACCOUNT,
            "Arn": "arn:aws:iam::%s:user/honeypot-canary" % FAKE_AWS_ACCOUNT,
        }, indent=4)
    if args[:2] == ["s3", "ls"]:
        return ("2023-11-02 06:12:44 honey-fake-backups\n"
                "2024-02-19 11:03:01 honey-fake-logs")
    if args[:2] == ["ec2", "describe-instances"]:
        return json.dumps({"Reservations": []}, indent=4)
    op = " ".join(args[:2]) or "(no command)"
    # Plausible denial; values stay fake. The decoy disclosure lives in the
    # planted files' headers and in code comments, not whispered here —
    # but the account id and markers make it obvious to any human reader.
    return ("An error occurred (AccessDeniedException) when calling the "
            "%s operation: User arn:aws:iam::%s:user/honeypot-canary is not "
            "authorized to perform this action. (No real AWS call was made.)"
            % (op, FAKE_AWS_ACCOUNT))


def self_test():
    """Run under `python3 honeycreds.py`. Raises on any failure."""
    files = generate()
    expected = {"/root/.aws/credentials", "/root/.aws/config",
                "/root/secrets/db_credentials.txt",
                "/root/secrets/api_tokens.env",
                "/backup/secure/db_credentials.txt",
                "/root/keys_readme.txt"}
    assert set(files) == expected, f"planted paths changed: {set(files) ^ expected}"

    # Every file: NO disclosure labels, but a fake marker somewhere in the
    # values. The honesty lives in the values, never in a header.
    for path, content in files.items():
        lowered = content.lower()
        for banned in _BANNED_LABELS:
            assert banned not in lowered, \
                f"{path}: banned disclosure label {banned!r}"
        upper = content.upper()
        assert any(m in upper for m in _FAKE_MARKERS), \
            f"{path}: no HONEY/FAKE/EXAMPLE marker"

    # AWS key ids: real format (AKIA + 16), exactly 20 chars.
    creds = files["/root/.aws/credentials"]
    key_ids = [ln.split("=", 1)[1].strip() for ln in creds.splitlines()
               if ln.strip().startswith("aws_access_key_id")]
    assert key_ids, "no aws_access_key_id in credentials file"
    for kid in key_ids:
        assert len(kid) == 20, f"key id not 20 chars: {kid!r} ({len(kid)})"
        assert kid.startswith("AKIA"), f"key id must start with AKIA: {kid!r}"
        assert "HONEY" in kid, f"key id missing fake marker: {kid!r}"

    # Determinism: same seed -> same decoys; different seed -> different.
    assert generate() == generate(), "generate() not deterministic"
    assert generate(seed=1) != generate(seed=2), "seed has no effect"

    # Path normalization (mirrors the shell's cat).
    assert is_honeycred_path("/root/.aws/credentials")
    assert is_honeycred_path(".aws/credentials")
    assert is_honeycred_path("secrets/api_tokens.env")
    assert is_honeycred_path("/backup/secure/db_credentials.txt")
    assert is_honeycred_path("/root/keys_readme.txt")
    assert not is_honeycred_path("/etc/passwd")
    assert not is_honeycred_path("/root/.aws")      # a directory, not a file
    assert not is_honeycred_path("")
    assert not is_honeycred_path("/root/.aws/credentials.bak")

    # Fake aws output: canned JSON for sts, stub otherwise, never network.
    ident = fake_aws_output(["sts", "get-caller-identity"])
    parsed = json.loads(ident)  # must be valid JSON
    assert parsed["Account"] == FAKE_AWS_ACCOUNT
    assert "honeypot-canary" in parsed["Arn"]
    assert isinstance(fake_aws_output(["s3", "ls"]), str)
    assert isinstance(fake_aws_output([]), str)
    assert isinstance(fake_aws_output(["ec2", "describe-instances"]), str)

    print(f"[self-test] OK: {len(files)} canary files, disclosure labels "
          f"absent, fake markers present, "
          f"AWS key id 20 chars, deterministic, aws stubs canned")


if __name__ == "__main__":
    self_test()
