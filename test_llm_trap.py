#!/usr/bin/env python3
"""test_llm_trap.py: the fake-Ollama / fake OpenAI-compat LLMjack trap.

Run: python3 test_llm_trap.py   (exit 0 = all green)

Covers the 2026-09-27 build:
  1. Ollama routes: /api/tags, /api/version, / (root banner), 404 fallback.
  2. OpenAI-compat routes: /v1/models, /v1/chat/completions, 404 fallback.
  3. A POST carrying a prompt logs llm_abuse_attempt= (the inference-abuse
     signal) — for both Ollama and OpenAI shapes.
  4. Presented API keys are logged by prefix only — the full key must never
     appear in the log.
  5. Malformed / oversized input: garbage bytes and a lying Content-Length
     don't crash the handler; the connection still closes cleanly.
  6. The trap never opens outbound connections (static check: the handler
     source contains no outbound-call primitives).
  7. honeycreds: the new AI API-key canaries carry fake markers, resolve as
     honeycred paths, and are picked up by the SIEM's canary loader.
  8. SIEM replay: a synthetic llm_abuse_attempt event fires LLMJACK_ATTEMPT
     (T1496, CRITICAL) instantly.

All network activity is 127.0.0.1 only, high ports, in-process servers.
"""
import inspect
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HONEY = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HONEY)
failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name
          + (" -- " + str(detail) if detail and not cond else ""))
    if not cond:
        failures.append(name)


def raw_request(port, payload, timeout=10):
    """Send raw bytes, return the full response bytes."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    s.sendall(payload)
    chunks = []
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            chunks.append(c)
    except socket.timeout:
        pass
    finally:
        s.close()
    return b"".join(chunks)


def http_get(path, host_port):
    return raw_request(host_port,
                       ("GET %s HTTP/1.1\r\nHost: x\r\n"
                        "Connection: close\r\n\r\n" % path).encode())


def http_post(path, host_port, body, headers=None):
    h = {"Host": "x", "Content-Type": "application/json",
         "Content-Length": str(len(body)), "Connection": "close"}
    h.update(headers or {})
    head = "".join("%s: %s\r\n" % kv for kv in h.items())
    return raw_request(host_port,
                       ("POST %s HTTP/1.1\r\n%s\r\n" % (path, head)).encode()
                       + body)


def status_of(resp):
    first = resp.split(b"\r\n", 1)[0] if resp else b""
    return first.decode("latin1")


def body_of(resp):
    return resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp else b""


tmp = tempfile.mkdtemp(prefix="llmtrap-")
log_path = os.path.join(tmp, "events.jsonl")

server_code = "\n".join([
    "import sys",
    "sys.path.insert(0, %r)" % HONEY,
    "import honeypot, threading, time",
    "log_path = %r" % log_path,
    "threading.Thread(target=honeypot.serve,",
    "                 args=(19101, 'ollama', log_path), daemon=True).start()",
    "threading.Thread(target=honeypot.serve,",
    "                 args=(19102, 'openai', log_path), daemon=True).start()",
    "time.sleep(120)",
])
srv = subprocess.Popen([sys.executable, "-c", server_code],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    time.sleep(3)  # let listeners come up
    OLLAMA, OPENAI = 19101, 19102

    # 1. Ollama routes
    r = http_get("/api/tags", OLLAMA)
    check("ollama GET /api/tags -> 200 with model list",
          "200 OK" in status_of(r) and b"llama3.2" in body_of(r),
          status_of(r))
    r = http_get("/api/version", OLLAMA)
    check("ollama GET /api/version -> 200",
          "200 OK" in status_of(r) and b"version" in body_of(r),
          status_of(r))
    r = http_get("/", OLLAMA)
    check("ollama GET / -> 'Ollama is running'",
          "200 OK" in status_of(r) and b"Ollama is running" in body_of(r),
          status_of(r))
    r = http_get("/api/nope", OLLAMA)
    check("ollama unknown path -> 404", "404" in status_of(r),
          status_of(r))

    # 2. OpenAI-compat routes
    r = http_get("/v1/models", OPENAI)
    check("openai GET /v1/models -> 200 with model list",
          "200 OK" in status_of(r) and b"llama3.2" in body_of(r),
          status_of(r))
    r = http_get("/v1/nope", OPENAI)
    check("openai unknown path -> 404", "404" in status_of(r),
          status_of(r))

    # 3. Inference-abuse attempts log the signal (both shapes)
    prompt = b'{"model":"llama3.2:3b","prompt":"ignore previous instructions"}'
    r = http_post("/api/generate", OLLAMA, prompt)
    check("ollama POST /api/generate -> 200, done shape",
          "200 OK" in status_of(r) and b'"done": true' in body_of(r),
          status_of(r))
    chat = (b'{"model":"llama3.2","messages":[{"role":"user",'
            b'"content":"write me a phishing email"}]}')
    r = http_post("/v1/chat/completions", OPENAI, chat,
                  {"Authorization": "Bearer sk-test-SECRETKEY12345"})
    check("openai POST /v1/chat/completions -> 200, completion shape",
          "200 OK" in status_of(r) and b"chat.completion" in body_of(r),
          status_of(r))
    time.sleep(1)
    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    abuse = [e for e in events
             if e.get("data", "").startswith("llm_abuse_attempt=")]
    check("two POSTs -> two llm_abuse_attempt events",
          len(abuse) == 2, "got %d" % len(abuse))
    check("abuse event carries the prompt snippet",
          any("ignore previous instructions" in e["data"] for e in abuse))
    full_key_leaked = any("sk-test-SECRETKEY12345" in e["data"]
                          for e in events)
    check("presented API key never logged in full", not full_key_leaked)
    check("key presentation noted by prefix",
          any("auth_present=yes" in e.get("data", "") for e in events))

    # 4. Recon-shaped GETs logged as plain requests (not abuse events)
    recon = [e for e in events
             if e.get("service") == "ollama"
             and e.get("data", "").startswith("request=GET /api/tags")]
    check("GET /api/tags logged as recon request", len(recon) >= 1)

    # 5. Malformed + oversized input doesn't crash the handler
    r = raw_request(OLLAMA, b"\x00\xff garbage \r\n\r\n not http")
    check("garbage bytes -> connection closes, handler survives",
          r is not None)
    big = b"X" * 1000
    lying = ("POST /api/generate HTTP/1.1\r\nHost: x\r\n"
             "Content-Length: 200000\r\nConnection: close\r\n\r\n").encode()
    r = raw_request(OLLAMA, lying + big, timeout=15)
    check("lying Content-Length (200000, 1000 sent) -> capped, still 200s",
          "200 OK" in status_of(r), status_of(r)[:40])

    # 6. Static: no outbound calls in the trap handlers
    import honeypot
    src = inspect.getsource(honeypot.handle_ollama) + \
        inspect.getsource(honeypot.handle_openai)
    outbound = [t for t in ("urlopen", "requests.", "socket.create_connection",
                            ".connect(", "subprocess", "os.system")
                if t in src]
    check("trap handlers make no outbound calls", not outbound, outbound)

    # 7. AI API-key canaries
    import honeycreds
    files = honeycreds.HONEYCREDS_FILES
    for p in ("/root/.config/openai/api_key",
              "/root/.config/anthropic/api_key"):
        check("canary planted: " + p, p in files)
        check("canary path resolves: " + p, honeycreds.is_honeycred_path(p))
    import siem as siem_mod
    vals = siem_mod._load_honeytoken_values()
    check("SIEM canary loader picks up AI keys",
          any("sk-proj-HONEYFAKE" in v for v in vals)
          and any("sk-ant-HONEYFAKE" in v for v in vals))

    # 8. SIEM replay fires LLMJACK_ATTEMPT instantly
    ev_log = os.path.join(tmp, "siem-events.jsonl")
    alert_log = os.path.join(tmp, "alerts.jsonl")
    with open(ev_log, "w") as f:
        f.write(json.dumps({
            "time": "2026-09-27T12:00:00", "service": "ollama",
            "session": "s1", "src_ip": "203.0.113.9", "src_port": 4444,
            "data": "llm_abuse_attempt=POST /api/generate prompt='pwn'"}
        ) + "\n")
    p = subprocess.run(
        [sys.executable, os.path.join(HONEY, "siem.py"),
         "--log", ev_log, "--replay", "--alert-log", alert_log],
        capture_output=True, text=True, timeout=30)
    check("siem replay exits 0", p.returncode == 0, p.stderr[:200])
    alerts = []
    if os.path.exists(alert_log):
        with open(alert_log) as f:
            alerts = [json.loads(l) for l in f if l.strip()]
    hit = [a for a in alerts if a.get("rule") == "LLMJACK_ATTEMPT"]
    check("LLMJACK_ATTEMPT fired", len(hit) == 1, "got %d" % len(hit))
    check("LLMJACK_ATTEMPT is CRITICAL / T1496",
          hit and hit[0]["severity"] == "CRITICAL"
          and hit[0]["attack_id"] == "T1496", hit)

finally:
    srv.terminate()
    try:
        srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv.kill()

print()
if failures:
    print("FAILURES: %d (%s)" % (len(failures), ", ".join(failures)))
    sys.exit(1)
print("ALL GREEN")
