#!/usr/bin/env python3
"""pd_bridge.py: wire peripheral-defense into the fortress honeypot.

Plain language: the honeypot calls this module before answering a
visitor. It asks the peripheral-defense tool "how should I answer this
one?" and applies the answer: wait a little (throttle), or serve the
harmless decoy page instead of the normal fake page.

SAFETY:
- Disabled by default. Set PD_ENABLED=1 in the environment to turn it on.
  When disabled, every function here is a no-op and the honeypot behaves
  exactly as before (byte-identical responses, no delays).
- The honeypot keeps its cover banners (RouterOS, OpenSSH, ...). Banner
  minimization is for REAL services; a honeypot that says "service ready"
  blows its own cover. This bridge never touches banners.
- Delays are applied by the honeypot (time.sleep here, in the owning
  service), capped by the tool at 5 seconds. Visitors that trip
  trip-points get slowed; nobody gets blocked.
- If the peripheral-defense folder is missing or broken, the bridge
  disables itself with a warning. The honeypot never depends on it.

Wiring (all in honeypot.py, all guarded by is_enabled()):
- _guarded_handler: observe one port_probe per connection, before the
  service handler runs; sleep the advised delay.
- handle_ssh / handle_telnet: after the username is read, observe one
  login_attempt; sleep the advised delay before the password prompt.
- handle_http: after the path is parsed, observe one http_request; if the
  tool says decoy, serve its decoy page instead of the normal fake page;
  sleep the advised delay before responding.
"""
import os
import sys
import time

_pd = None
_disabled_reason = None


def _load():
    global _pd, _disabled_reason
    if _pd is not None or _disabled_reason is not None:
        return
    if os.environ.get("PD_ENABLED") != "1":
        _disabled_reason = "PD_ENABLED != 1 (default off)"
        return
    tool_dir = os.path.expanduser("~/workspace/your_files/peripheral-defense")
    try:
        sys.path.insert(0, tool_dir)
        from peripheral_defense import PeripheralDefense
        journal = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "logs", "pd-evidence.jsonl")
        _pd = PeripheralDefense(journal_path=journal)
    except Exception as e:  # never break the honeypot over this
        _disabled_reason = "load failed: %s" % e
        _pd = None


def is_enabled():
    """True only when PD_ENABLED=1 and the tool loaded cleanly."""
    _load()
    return _pd is not None


def why_disabled():
    _load()
    return _disabled_reason


def _apply(decision):
    """Sleep the advised delay. Returns the decoy page text, or None."""
    delay = decision.get("delay_seconds", 0) or 0
    if delay > 0:
        time.sleep(min(delay, 5.0))
    which = decision.get("respond_with")
    if which:
        return _pd.page(which)
    return None


def port_touch(service, addr):
    """One visitor connected to one fake service. Returns decoy text/None."""
    if not is_enabled():
        return None
    try:
        d = _pd.observe({"type": "port_probe", "src_ip": addr[0],
                         "service": service})
        return _apply(d)
    except Exception:
        return None  # the tool must never break a session


def login_try(service, addr, username):
    """One visitor tried one username. Returns decoy text/None."""
    if not is_enabled():
        return None
    try:
        d = _pd.observe({"type": "login_attempt", "src_ip": addr[0],
                         "service": service, "username": username})
        return _apply(d)
    except Exception:
        return None


def http_hit(addr, path):
    """One visitor requested one web path. Returns decoy text/None."""
    if not is_enabled():
        return None
    try:
        d = _pd.observe({"type": "http_request", "src_ip": addr[0],
                         "path": path if path.startswith("/") else "/"})
        return _apply(d)
    except Exception:
        return None
