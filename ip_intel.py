#!/usr/bin/env python3
"""Who's knocking? Pull attacker IPs out of the honeypot log and enrich
them with GeoIP + ASN/ISP info via the free ip-api.com batch endpoint
(no API key needed, 45 requests/min).

Privacy tradeoff (documented, not a bug to hide): the free tier is
HTTP-only, so a network observer between you and ip-api.com sees exactly
which attacker IPs you are investigating. The payload is just IPs — no
user data — but know that the queries themselves are visible on the wire.

Usage:
    python3 ip_intel.py [logfile]     # default: logs/events.jsonl

Note: GeoIP is approximate, and an IP is not a person — scanners often run
from compromised hosts, VPNs, or cloud servers. Treat this as intel about
infrastructure, not attribution of a human.
"""

import ipaddress
import json
import sys
import urllib.request

FIELDS = "status,country,countryCode,city,isp,org,as,query"


def unique_ips(log_path):
    """ip -> hit count, skipping local/private addresses."""
    ips = {}
    try:
        f = open(log_path)
    except OSError as e:
        print(f"[!] can't open {log_path}: {e}")
        sys.exit(1)
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = e.get("src_ip", "")
            if not isinstance(ip, str):
                # A forged log line with non-string src_ip must not crash
                # this tool via AttributeError on .startswith below.
                continue
            if ip in ("", "127.0.0.1"):
                continue
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue  # not an IP at all — not worth enriching
            if addr.is_private:
                continue  # RFC1918 / loopback / link-local: not an attacker
            ips[ip] = ips.get(ip, 0) + 1
    return ips


def enrich(ips):
    """Batch-lookup IPs (15 per request). Never raises on API trouble."""
    out = {}
    batch = [{"query": ip, "fields": FIELDS} for ip in ips]
    for i in range(0, len(batch), 15):
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=json.dumps(batch[i:i + 15]).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                rows = json.loads(r.read())
        except Exception as e:
            print(f"[!] lookup failed: {e}")
            break
        for row in rows:
            if row.get("status") == "success":
                out[row["query"]] = row
    return out


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "logs/events.jsonl"
    ips = unique_ips(log_path)
    if not ips:
        print("No public IPs in the log yet. Give the scanners time.")
        return
    print(f"[*] {len(ips)} unique public IP(s) — enriching...\n")
    info = enrich(ips)
    print(f"{'IP':<16}{'HITS':<6}{'COUNTRY':<14}{'CITY':<18}{'ISP / ORG'}")
    print("-" * 90)
    for ip, hits in sorted(ips.items(), key=lambda kv: -kv[1]):
        row = info.get(ip, {})
        country = row.get("country", "?")
        city = row.get("city", "?")
        isp = row.get("isp") or row.get("org") or "?"
        asn = row.get("as", "")
        print(f"{ip:<16}{hits:<6}{country:<14}{city:<18}{isp} {asn}")


if __name__ == "__main__":
    main()
