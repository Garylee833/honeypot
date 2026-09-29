#!/bin/bash
# backup-fortress.sh — off-box backup for the fortress.
#
# Two jobs, one script:
#   1. Tarball the fortress code + configs -> DEST/fortress-YYYYMMDD-HHMMSS.tar.gz
#      (keeps the newest KEEP_TARBALLS, deletes the rest)
#   2. Rsync the compressed log archives -> DEST/log-archives/
#      (the evidence locker — never pruned by this script)
#
# DEST can be a local path OR a remote server over SSH:
#   BACKUP_DEST=~/fortress-backups            # local (USB drive, etc.)
#   BACKUP_DEST="user@backup-server:/backups/fortress"   # remote
#
# For remote + cron: set up SSH key login first (no password prompts).
#   ssh-keygen -t ed25519        # if you don't have a key yet
#   ssh-copy-id user@backup-server
#
# Install:  cp backup-fortress.sh ~/work/labs/harbor-pine/
#           chmod +x ~/work/labs/harbor-pine/backup-fortress.sh
# Cron (daily 2am):  crontab -e
#           0 2 * * * ~/work/labs/harbor-pine/backup-fortress.sh

set -u

FORTRESS_DIR=~/work/labs/harbor-pine
BACKUP_DEST=~/fortress-backups
KEEP_TARBALLS=14

cd "$FORTRESS_DIR" || { echo "[backup] cannot cd to $FORTRESS_DIR"; exit 1; }

is_remote=0
case "$BACKUP_DEST" in *:* ) is_remote=1 ;; esac

stamp=$(date +%Y%m%d-%H%M%S)
tarball="/tmp/fortress-$stamp.tar.gz"

# 1. tarball the build (skip the bulky log archive dir and caches —
#    log archives ship separately in step 2)
tar -czf "$tarball" \
    --exclude='logs/archive' \
    --exclude='__pycache__' \
    --exclude='logs/*.jsonl' \
    . || { echo "[backup] tarball failed"; exit 1; }
echo "[backup] built $tarball ($(du -h "$tarball" | cut -f1))"

# 2. ship it + the log archives to the destination
if [ "$is_remote" = 1 ]; then
    host="${BACKUP_DEST%%:*}"
    rpath="${BACKUP_DEST#*:}"
    ssh "$host" "mkdir -p $rpath/log-archives" || { echo "[backup] ssh failed"; exit 1; }
    rsync -az "$tarball" "$BACKUP_DEST/" || { echo "[backup] rsync tarball failed"; exit 1; }
    if [ -d logs/archive ]; then
        rsync -az logs/archive/ "$BACKUP_DEST/log-archives/" || echo "[backup] WARN: log archive rsync failed"
    fi
    # prune old tarballs, newest KEEP_TARBALLS survive
    # shellcheck disable=SC2029
    ssh "$host" "ls -t $rpath/fortress-*.tar.gz 2>/dev/null | tail -n +$((KEEP_TARBALLS + 1)) | xargs -r rm -f"
else
    mkdir -p "$BACKUP_DEST/log-archives"
    rsync -a "$tarball" "$BACKUP_DEST/" || { echo "[backup] copy failed"; exit 1; }
    if [ -d logs/archive ]; then
        rsync -a logs/archive/ "$BACKUP_DEST/log-archives/" || echo "[backup] WARN: log archive rsync failed"
    fi
    ls -t "$BACKUP_DEST"/fortress-*.tar.gz 2>/dev/null | tail -n +$((KEEP_TARBALLS + 1)) | xargs -r rm -f
fi

rm -f "$tarball"
echo "[backup] done -> $BACKUP_DEST"
