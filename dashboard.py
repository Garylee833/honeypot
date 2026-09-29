#!/usr/bin/env python3
"""mini-SIEM web dashboard — a SOC-style interface for the honeypot.

    python3 dashboard.py [--log logs/events.jsonl] [--port 8080]

Then open http://127.0.0.1:8080 in your browser.
Stdlib only — no installs needed.
"""
import argparse
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from siem import Engine, follow

engine = Engine(quiet=True, alert_log=None)  # SIEM owns the alert log; dashboard only replays
lock = threading.Lock()
event_count = 0
sessions_dir = None  # set in main(): <logdir>/sessions (fake-shell transcripts)


def watch(log_path):
    global event_count
    for ev in follow(log_path, replay=False):
        with lock:
            # Synthetic aliveness noise is theater, not attacker activity:
            # don't inflate the event counter with it. (The SIEM skips it
            # entirely in Engine.handle.)
            if not ev.get("synthetic"):
                event_count += 1
            engine.handle(ev)


SESSION_ID_RE = re.compile(r"^[0-9a-fA-F]{1,32}$")


def list_sessions():
    """Newest-first summaries of recorded shell sessions. Never raises."""
    out = []
    if not sessions_dir or not os.path.isdir(sessions_dir):
        return out
    try:
        names = [f for f in os.listdir(sessions_dir) if f.endswith(".jsonl")]
    except OSError:
        return out
    for name in sorted(names)[:500]:
        sid = name[:-len(".jsonl")]
        if not SESSION_ID_RE.fullmatch(sid):
            continue
        meta = {"session": sid, "started": "", "src_ip": "?",
                "service": "?", "commands": 0}
        try:
            with open(os.path.join(sessions_dir, name), encoding="utf-8",
                      errors="replace") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    d = e.get("dir")
                    if d == "meta":
                        meta["started"] = e.get("t", "")
                        try:
                            m = json.loads(e.get("text") or "{}")
                        except ValueError:
                            m = {}
                        for k in ("src_ip", "service"):
                            if m.get(k):
                                meta[k] = m[k]
                    elif d == "in":
                        meta["commands"] += 1
        except OSError:
            continue
        out.append(meta)
    out.sort(key=lambda m: m.get("started", ""), reverse=True)
    return out[:200]


def read_session(sid):
    """Full transcript for one session id. Never raises; [] if unknown."""
    if not SESSION_ID_RE.fullmatch(sid or ""):
        return []
    path = os.path.join(sessions_dir or "", sid + ".jsonl")
    rows = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if len(rows) >= 2000:
                    break
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                rows.append({"t": e.get("t", ""), "dir": e.get("dir", ""),
                             "text": str(e.get("text", ""))[:4000]})
    except OSError:
        return []
    return rows


PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>mini-SIEM // SOC Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }
  h1 { font-size: 20px; margin-bottom: 4px; }
  h1 .live { color: #3fb950; }
  .sub { color: #8b949e; font-size: 12px; margin-bottom: 16px; }
  .cards { display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
          padding: 12px 18px; min-width: 130px; }
  .card .n { font-size: 26px; font-weight: bold; }
  .card .l { font-size: 11px; color: #8b949e; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: #8b949e; font-weight: normal; font-size: 11px;
       padding: 8px; border-bottom: 1px solid #30363d; }
  td { padding: 8px; border-bottom: 1px solid #21262d; vertical-align: top; }
  tr.alert-row { animation: flash 1s; }
  @keyframes flash { from { background: #3fb95033; } to { background: transparent; } }
  .sev { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
  .CRITICAL { background: #f8514933; color: #f85149; border: 1px solid #f85149; }
  .HIGH     { background: #d2992233; color: #d29922; border: 1px solid #d29922; }
  .MEDIUM   { background: #e3b34133; color: #e3b341; border: 1px solid #e3b341; }
  .LOW      { background: #58a6ff33; color: #58a6ff; border: 1px solid #58a6ff; }
  .empty { color: #8b949e; padding: 20px; text-align: center; }
  .rule { color: #79c0ff; } .attack { color: #8b949e; }
  h2.sect { font-size: 15px; margin: 24px 0 4px; color: #c9d1d9; }
  #replay-pre { background: #010409; border: 1px solid #30363d; border-radius: 6px;
                padding: 12px; font-size: 12px; max-height: 420px; overflow: auto;
                white-space: pre-wrap; word-break: break-word; }
  #replay-pre .rin { color: #3fb950; } #replay-pre .rout { color: #8b949e; }
  tr.clickable { cursor: pointer; } tr.clickable:hover td { background: #161b22; }
</style></head>
<body>
  <h1>MINI-SIEM <span class="live">&#9679; LIVE</span></h1>
  <div class="sub">honeypot detection dashboard &mdash; refreshes every 2s</div>
  <div class="cards">
    <div class="card"><div class="n" id="c-events">0</div><div class="l">EVENTS SEEN</div></div>
    <div class="card"><div class="n" id="c-alerts">0</div><div class="l">ALERTS</div></div>
    <div class="card"><div class="n" id="c-crit" style="color:#f85149">0</div><div class="l">CRITICAL</div></div>
    <div class="card"><div class="n" id="c-high" style="color:#d29922">0</div><div class="l">HIGH</div></div>
    <div class="card"><div class="n" id="c-med" style="color:#e3b341">0</div><div class="l">MEDIUM</div></div>
  </div>
  <table><thead><tr>
    <th>TIME (UTC)</th><th>SEVERITY</th><th>RULE</th><th>ATT&amp;CK</th><th>SRC IP</th><th>DETAIL</th>
  </tr></thead><tbody id="rows"><tr><td colspan="6" class="empty">listening for attacks&hellip;</td></tr></tbody></table>
  <h2 class="sect">SESSION REPLAYS</h2>
  <div class="sub">fake-shell transcripts &mdash; newest first, click a row to replay</div>
  <table><thead><tr>
    <th>SESSION</th><th>STARTED (UTC)</th><th>SRC IP</th><th>SERVICE</th><th>COMMANDS</th>
  </tr></thead><tbody id="srows"><tr><td colspan="5" class="empty">no shell sessions recorded yet</td></tr></tbody></table>
  <div id="replay-wrap" style="display:none">
    <h2 class="sect">REPLAY <span id="replay-id" class="rule"></span></h2>
    <pre id="replay-pre"></pre>
  </div>
<script>
let seen = 0;
function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
async function replay(sid) {
  const r = await fetch('/api/session?id=' + encodeURIComponent(sid));
  const rows = await r.json();
  document.getElementById('replay-id').textContent = sid;
  const pre = document.getElementById('replay-pre');
  pre.innerHTML = '';
  for (const e of rows) {
    const line = document.createElement('div');
    line.className = e.dir === 'in' ? 'rin' : 'rout';
    line.textContent = (e.dir === 'in' ? '$ ' : '') + e.text;
    pre.appendChild(line);
  }
  document.getElementById('replay-wrap').style.display = 'block';
  document.getElementById('replay-wrap').scrollIntoView();
}
async function tick() {
  const [aRes, sRes] = await Promise.all([fetch('/api/alerts'), fetch('/api/stats')]);
  const alerts = await aRes.json(), stats = await sRes.json();
  document.getElementById('c-events').textContent = stats.events;
  document.getElementById('c-alerts').textContent = stats.total;
  document.getElementById('c-crit').textContent = stats.by_severity.CRITICAL || 0;
  document.getElementById('c-high').textContent = stats.by_severity.HIGH || 0;
  document.getElementById('c-med').textContent = stats.by_severity.MEDIUM || 0;
  const tb = document.getElementById('rows');
  if (!alerts.length) return;
  tb.innerHTML = alerts.map((a, i) =>
    `<tr class="${i < alerts.length - seen ? '' : ''}"><td>${esc(a.time)}</td>` +
    `<td><span class="sev ${esc(a.severity)}">${esc(a.severity)}</span></td>` +
    `<td class="rule">${esc(a.rule)}</td><td class="attack">${esc(a.attack_id)}</td>` +
    `<td>${esc(a.src_ip)}</td><td>${esc(a.detail)}</td></tr>`).join('');
  seen = alerts.length;
  try {
    const sess = await (await fetch('/api/sessions')).json();
    const st = document.getElementById('srows');
    st.innerHTML = sess.length ? sess.map(m =>
      `<tr class="clickable" onclick="replay('${esc(m.session)}')"><td class="rule">${esc(m.session)}</td>` +
      `<td>${esc(m.started)}</td><td>${esc(m.src_ip)}</td>` +
      `<td>${esc(m.service)}</td><td>${m.commands}</td></tr>`).join('')
      : '<tr><td colspan="5" class="empty">no shell sessions recorded yet</td></tr>';
  } catch (e) { /* sessions are a bonus; never break the alert table */ }
}
setInterval(tick, 2000); tick();
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            body = PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/alerts":
            with lock:
                data = list(reversed(engine.alerts[-100:]))
            self._json(data)
        elif self.path == "/api/stats":
            with lock:
                by_sev = {}
                for a in engine.alerts:
                    by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
                self._json({"events": event_count, "total": len(engine.alerts),
                            "by_severity": by_sev})
        elif self.path == "/api/sessions":
            with lock:
                data = list_sessions()
            self._json(data)
        elif self.path.startswith("/api/session?"):
            sid = ""
            for part in self.path.split("?", 1)[1].split("&"):
                if part.startswith("id="):
                    sid = part[3:]
            with lock:
                data = read_session(sid)
            self._json(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass  # keep the console clean


def main():
    ap = argparse.ArgumentParser(description="mini-SIEM web dashboard")
    ap.add_argument("--log", default="logs/events.jsonl")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    global sessions_dir
    sessions_dir = os.path.join(os.path.dirname(args.log) or ".", "sessions")

    threading.Thread(target=watch, args=(args.log,), daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[*] dashboard live at http://127.0.0.1:{args.port}")
    print(f"[*] watching {args.log}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] dashboard stopped.")


if __name__ == "__main__":
    main()
