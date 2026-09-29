#!/bin/bash
# rotate-fortress-logs.sh — keep the fortress from eating the disk.
#
# Why this is safe (no fortress code changes needed):
#   - honeypot.py opens its log in append mode PER EVENT, so moving the
#     file away never breaks the writer; the next event starts a new one.
#   - siem.py's tail detects a shrunk file and re-opens it on its own.
#
# What it does:
#   - any watched log over the size threshold gets moved to logs/archive/
#     and gzipped
#   - lab mode: archives older than 30 days are deleted
#   - live mode (LIVE_MODE=1): archives kept 90 days and ONLY pruned when
#     disk use passes 80% — evidence is never deleted on a schedule
#
# Install:  cp rotate-fortress-logs.sh ~/work/labs/harbor-pine/
#           chmod +x ~/work/labs/harbor-pine/rotate-fortress-logs.sh
# Cron (daily 3am):  crontab -e
#           0 3 * * * ~/work/labs/harbor-pine/rotate-fortress-logs.sh
# Live box cron:     0 3 * * * LIVE_MODE=1 ~/work/labs/harbor-pine/rotate-fortress-logs.sh

set -u
cd ~/work/labs/harbor-pine || exit 1

# --- mode ---------------------------------------------------------------
# Lab (default): tight rotation, prune old archives freely.
# Live (public box): logs are EVIDENCE. Rotate bigger, keep 90 days, and
# only prune when the disk is actually under pressure — never delete
# evidence just because the calendar says so.
LIVE_MODE=${LIVE_MODE:-0}

if [ "$LIVE_MODE" = "1" ]; then
    MAX_BYTES=209715200  # 200MB per log before rotation
    KEEP_DAYS=90
    DISK_GUARD=${DISK_GUARD:-80}  # prune archives only above this disk %
else
    MAX_BYTES=52428800   # 50MB
    KEEP_DAYS=30
    DISK_GUARD=${DISK_GUARD:-0}   # 0 = always prune old archives
fi
ARCHIVE="logs/archive"
mkdir -p "$ARCHIVE"

for log in logs/events.jsonl logs/tarpit.jsonl alerts.jsonl blocker.log logs/watchdog.jsonl; do
    [ -f "$log" ] || continue
    size=$(stat -c%s "$log")
    if [ "$size" -gt "$MAX_BYTES" ]; then
        stamp=$(date +%Y%m%d-%H%M%S)
        base=$(basename "$log")
        mv "$log" "$ARCHIVE/$base.$stamp"
        gzip "$ARCHIVE/$base.$stamp"
        echo "[rotate] $log was ${size} bytes -> archived as $base.$stamp.gz"
    fi
done

# prune old archives (live mode: only under real disk pressure)
if [ "$DISK_GUARD" -gt 0 ]; then
    use=$(df -P "$ARCHIVE" | awk 'NR==2 {print $5}' | tr -d '%')
    if [ "$use" -lt "$DISK_GUARD" ]; then
        echo "[rotate] disk at ${use}% — keeping archives (live mode)"
    else
        find "$ARCHIVE" -name "*.gz" -mtime +"$KEEP_DAYS" -delete
        echo "[rotate] disk at ${use}% — pruned archives older than $KEEP_DAYS days"
    fi
else
    find "$ARCHIVE" -name "*.gz" -mtime +"$KEEP_DAYS" -delete
fi
