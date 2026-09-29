#!/bin/bash
# resurrect.sh — honeypot self-healing guard.
# Runs on a schedule (runtime cron, every 15 min). Ensures both the
# honeypot (via deathwatch -> uplink-launcher.py) and the uplink server
# are alive; starts whichever is missing, detached. Logs only when it
# takes action. Safe to run any time: no-op when everything is already up.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="$HERE/logs/resurrect.log"
STAMP="$(date '+%Y-%m-%d %H:%M:%S %Z')"
FAILED=0

start_detached() { # name, pgrep_pattern, command...
    local name="$1" pattern="$2"; shift 2
    if pgrep -f "$pattern" >/dev/null 2>&1; then
        return 0
    fi
    echo "$STAMP resurrect: no $name process found — starting" >>"$LOG"
    cd "$HERE" || { echo "$STAMP resurrect: cd failed" >>"$LOG"; return 1; }
    nohup "$@" >>"logs/${name}-stdout.log" 2>&1 &
    local newpid=$!
    sleep 3
    if kill -0 "$newpid" 2>/dev/null; then
        echo "$STAMP resurrect: started $name pid=$newpid" >>"$LOG"
    else
        echo "$STAMP resurrect: FAILED to start $name (pid $newpid died immediately)" >>"$LOG"
        FAILED=1
    fi
}

start_detached "deathwatch" "[d]eathwatch.py" /usr/bin/python3 deathwatch.py
start_detached "uplink-server" "[u]plink-server.py" /usr/bin/python3 uplink-server.py

# The honeypot itself runs under deathwatch as uplink-launcher.py. If
# deathwatch is up but the launcher is missing (shouldn't happen —
# deathwatch only exits when its child dies), note it; the next
# deathwatch start covers it.
if pgrep -f "[d]eathwatch.py" >/dev/null 2>&1; then
    if ! pgrep -f "[u]plink-launcher.py" >/dev/null 2>&1; then
        echo "$STAMP resurrect: WARNING deathwatch up but uplink-launcher.py missing" >>"$LOG"
    fi
fi

exit "$FAILED"
