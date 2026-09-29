"""uplink-shipper.py — push every honeypot event to the uplink server.

Imported by uplink-launcher.py (never by honeypot.py directly). Registers
a @honeypot.on_event hook: each event is queued to a background thread
that POSTs it to 127.0.0.1:8899/event.

Design rules (same as the honeypot's own session recorder):
- Shipping must NEVER break the honeypot. Every failure path is
  try/except; a dead server means dropped ships, not a dead trap.
  The local events.jsonl remains the source of truth.
- The background thread is a daemon: it can never block shutdown.
- Sensor name comes from UPLINK_SENSOR env (default "local") so the
  Oracle box can ship as sensor "oracle" with zero code changes.
"""
import json
import os
import queue
import threading
import urllib.request

import honeypot

UPLINK_URL = os.environ.get("UPLINK_URL", "http://127.0.0.1:8899/event")
SENSOR = os.environ.get("UPLINK_SENSOR", "local")
TIMEOUT_S = 2
MAX_QUEUE = 1000  # drop oldest beyond this; a flood must not OOM the trap

_q = queue.Queue(maxsize=MAX_QUEUE)


def _sender():
    while True:
        event = _q.get()
        try:
            body = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                UPLINK_URL, data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                resp.read(1024)  # drain; we only care it accepted
        except Exception:
            pass  # shipper never raises, never retries, never blocks
        finally:
            _q.task_done()


threading.Thread(target=_sender, daemon=True, name="uplink-shipper").start()


@honeypot.on_event
def _ship(event):
    try:
        payload = dict(event)
        payload["sensor"] = SENSOR
        try:
            _q.put_nowait(payload)
        except queue.Full:
            try:
                _q.get_nowait()  # make room: drop oldest, keep newest
            except queue.Empty:
                pass
            try:
                _q.put_nowait(payload)
            except queue.Full:
                pass
    except Exception:
        pass  # the hook must never break event logging
