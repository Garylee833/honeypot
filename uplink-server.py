#!/usr/bin/env python3
"""uplink-server.py — honeypot uplink: collector + monitor.

Two jobs, one small stdlib server (127.0.0.1 only, never public):

  COLLECTOR — honeypots POST each catch to /event. Every event is appended
  to logs/uplink-events.jsonl (under ~/workspace, survives VM replacement)
  stamped with when it arrived and which sensor sent it. Built for more
  than one honeypot: the Oracle box will ship here too when it exists.

  MONITOR — GET /status answers in one glance: is the honeypot alive,
  when did the last event land, how many events total.

No dependencies beyond the standard library. Never raises on a bad
request — a malformed POST is rejected, never a crash.
"""
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
LOGDIR = os.path.join(HERE, "logs")
UPLINK_LOG = os.path.join(LOGDIR, "uplink-events.jsonl")
BIND = "127.0.0.1"
PORT = 8899
MAX_BODY = 64 * 1024  # one event never legitimately exceeds this

_started_at = time.time()
_lock = threading.Lock()
_stats = {"events_received": 0, "last_event_at": None, "sensors": {}}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def honeypot_alive():
    """True if the honeypot launcher process is running. Never raises."""
    try:
        out = subprocess.run(
            ["pgrep", "-f", "[u]plink-launcher.py"],
            capture_output=True, text=True, timeout=5,
        )
        pids = [p for p in out.stdout.split() if p.strip().isdigit()]
        return (len(pids) > 0, pids[0] if pids else None)
    except Exception:
        return (False, None)


class Handler(BaseHTTPRequestHandler):
    server_version = "uplink/1.0"

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802 (http.server naming)
        if self.path != "/event":
            self._json(404, {"ok": False, "error": "unknown path"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            self._json(400, {"ok": False, "error": "bad content length"})
            return
        try:
            raw = self.rfile.read(length)
            event = json.loads(raw.decode("utf-8"))
            if not isinstance(event, dict):
                raise ValueError("event must be a JSON object")
        except Exception as e:
            self._json(400, {"ok": False, "error": f"bad event: {e}"})
            return
        sensor = str(event.get("sensor") or "local")
        record = {
            "received_at": now_iso(),
            "sensor": sensor,
            "event": event,
        }
        try:
            os.makedirs(LOGDIR, exist_ok=True)
            with open(UPLINK_LOG, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except OSError as e:
            self._json(500, {"ok": False, "error": f"store failed: {e}"})
            return
        with _lock:
            _stats["events_received"] += 1
            _stats["last_event_at"] = record["received_at"]
            _stats["sensors"][sensor] = _stats["sensors"].get(sensor, 0) + 1
        self._json(200, {"ok": True})

    def do_GET(self):  # noqa: N802
        if self.path != "/status":
            self._json(404, {"ok": False, "error": "unknown path"})
            return
        alive, pid = honeypot_alive()
        with _lock:
            snap = {
                "events_received": _stats["events_received"],
                "last_event_at": _stats["last_event_at"],
                "sensors": dict(_stats["sensors"]),
            }
        self._json(200, {
            "ok": True,
            "server_uptime_s": int(time.time() - _started_at),
            "honeypot_alive": alive,
            "honeypot_pid": pid,
            **snap,
        })

    def log_message(self, fmt, *args):  # keep stdout quiet; not an audit log
        pass


def main():
    os.makedirs(LOGDIR, exist_ok=True)
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"[*] uplink-server on {BIND}:{PORT} (-> {UPLINK_LOG})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
