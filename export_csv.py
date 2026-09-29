#!/usr/bin/env python3
"""Export honeypot JSONL logs to CSV spreadsheets.

Run from the honeypot folder:
    python3 export_csv.py

Produces:
    alerts.csv  -- every SIEM alert (time, severity, rule, ATT&CK, src_ip, detail)
    events.csv  -- every honeypot event (opens in any spreadsheet app)
"""
import csv
import json
import os


def export(src, dst):
    if not os.path.exists(src):
        print(f"skip: {src} not found")
        return
    rows = []
    with open(src) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    if not rows:
        print(f"skip: {src} is empty")
        return
    keys = []
    for r in rows:
        for k in r:
            if k not in keys:
                keys.append(k)
    with open(dst, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} rows: {src} -> {dst}")


if __name__ == "__main__":
    export("alerts.jsonl", "alerts.csv")
    export(os.path.join("logs", "events.jsonl"), "events.csv")
