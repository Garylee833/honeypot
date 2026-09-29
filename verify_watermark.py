#!/usr/bin/env python3
"""
verify_watermark.py — trace a leaked decoy back to its fortress.

Educational, defensive. Scans a suspect file for vault deployment
watermarks ("vault-id: <id>" comment markers) and compares them against
this deployment's id.

Exit codes / first-line result:
    MATCH <id>       (0)  the file carries OUR deployment id -> leaked from here
    NO-MATCH <ids>   (2)  only FOREIGN deployment id(s) -> another fortress leaked
    NO-WATERMARK     (1)  no watermark found -> stripped, normalized, or never ours

Usage:
    python3 verify_watermark.py <suspect-file> [--id-file vault_id.txt]
    python3 verify_watermark.py            # runs the built-in self-test
"""

import argparse
import os
import re
import sys
import tempfile

# Matches `-- vault-id: <hex>`, `# vault-id = <hex>`, `/* vault-id:<hex> */`,
# plus the degraded "unpersisted-<hex>" fallback id. We regex the whole text
# on purpose — no comment parsing — so sloppily-stripped copies still hit.
WM_RE = re.compile(
    r"vault-id\s*[:=]\s*(unpersisted-[0-9a-f]{8,32}|[0-9a-f]{8,32})",
    re.IGNORECASE,
)


def find_watermark_ids(text):
    """All distinct watermark ids in the text, normalized to lowercase."""
    return sorted({m.group(1).lower() for m in WM_RE.finditer(text)})


def local_deployment_id(id_file=None):
    """This deployment's id: --id-file, then VAULT_ID env, then vault.py."""
    if id_file:
        try:
            with open(id_file) as f:
                val = f.read().strip()
            if val:
                return val
        except OSError:
            pass
    env = os.environ.get("VAULT_ID")
    if env:
        return env
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import vault  # local import: only needed for this fallback path
        return vault.get_deployment_id()
    except (ImportError, AttributeError) as e:
        raise SystemExit(
            "ERROR: no deployment id available — pass --id-file vault_id.txt "
            f"or set VAULT_ID (vault.py has no get_deployment_id: {e})")


def analyze(text, our_id):
    """Return (exit_code, report_lines). Pure logic, easy to test."""
    found = find_watermark_ids(text)
    ours = our_id.strip().lower()
    if not found:
        return 1, [
            "NO-WATERMARK",
            "",
            "No vault watermark was found in this file. Either it was never "
            "one of our decoys, or an adversary stripped or normalized the "
            "comments (`grep -v '^--'`, CSV re-export, format-shifting to "
            "JSON) — a determined cleaner defeats every comment-based mark. "
            "This is the expected outcome for stripped dumps, and the reason "
            "watermarks are defense-in-depth, never proof that no leak "
            "happened.",
        ]
    foreign = [i for i in found if i != ours]
    breakdown = ["", "ids found:"]
    for i in found:
        tag = "THIS deployment" if i == ours else "FOREIGN deployment"
        breakdown.append(f"  - {i}: {tag}")
    if ours in found:
        lines = [
            f"MATCH {ours}",
            "",
            "This file carries the watermark id of THIS deployment, so it "
            "originated from this fortress's vault — treat it as a leaked "
            "decoy. The credentials inside are fake, but the leak is real: "
            "find out how it left the network, and assume whoever "
            "exfiltrated it may come back. A watermark proves the leak's "
            "SOURCE, never the leaker's identity.",
        ]
        if foreign:
            lines += ["",
                      "It also carries foreign id(s) — a mixed dump (chaff). "
                      "Ours is present, so this fortress is implicated too."]
        return 0, lines + breakdown
    lines = [
        f"NO-MATCH {' '.join(found)}",
        "",
        "This file carries watermark(s), but NOT ours — it leaked from a "
        "DIFFERENT deployment of the same honeypot family (a replica, a "
        "friend's fortress, another copy). Interesting for intel-sharing, "
        "but it is not evidence that our vault leaked.",
    ]
    return 2, lines + breakdown


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Check a suspect file for our vault deployment watermark.")
    ap.add_argument("suspect_file", nargs="?",
                    help="file to scan (omit to run the built-in self-test)")
    ap.add_argument("--id-file", default=None,
                    help="path to vault_id.txt (default: VAULT_ID env, then vault.py)")
    args = ap.parse_args(argv)
    if not args.suspect_file:
        self_test()
        return 0
    try:
        with open(args.suspect_file, errors="replace") as f:
            text = f.read()
    except OSError as e:
        print(f"ERROR: cannot read {args.suspect_file}: {e}")
        return 3
    code, lines = analyze(text, local_deployment_id(args.id_file))
    print("\n".join(lines))
    return code


def self_test():
    """Temp-file fixtures covering MATCH / NO-MATCH / NO-WATERMARK / chaff."""
    os.environ["VAULT_ID"] = "a1b2c3d4e5f60718"
    try:
        def run(content):
            with tempfile.NamedTemporaryFile("w", suffix=".sql",
                                             delete=False) as f:
                f.write(content)
                path = f.name
            try:
                import io
                from contextlib import redirect_stdout
                buf = io.StringIO()
                with redirect_stdout(buf):
                    code = main([path])
                return code, buf.getvalue()
            finally:
                os.unlink(path)

        ours = "a1b2c3d4e5f60718"
        other = "0badf00d0badf00d"

        code, out = run("-- Database dump\n"
                        f"-- vault-id: {ours} \u2014 honeypot decoy trace marker\n")
        assert code == 0 and out.startswith(f"MATCH {ours}"), out

        code, out = run(f"-- vault-id: {other} \u2014 honeypot decoy trace marker\n")
        assert code == 2 and out.startswith(f"NO-MATCH {other}"), out

        code, out = run("id,email,created\n1,a@example.com,2024-01-01\n")
        assert code == 1 and out.startswith("NO-WATERMARK"), out

        code, out = run(f"# vault-id: {ours} (row checkpoint 4000)\n"
                        f"/* vault-id={other} */\n")
        assert code == 0, out
        assert ours in out and other in out, "chaff: must report BOTH ids"
        assert "FOREIGN" in out, out

        # comment-style coverage: '#', '--', '/* */' all detected
        assert find_watermark_ids("# vault-id: abcdef12") == ["abcdef12"]
        assert find_watermark_ids("/* VAULT-ID = ABCDEF12 */") == ["abcdef12"]
        assert find_watermark_ids("vault-id:unpersisted-deadbeef") == ["unpersisted-deadbeef"]
    finally:
        del os.environ["VAULT_ID"]
    print("[+] verify_watermark self-test passed: MATCH / NO-MATCH / NO-WATERMARK / chaff")


if __name__ == "__main__":
    sys.exit(main())
