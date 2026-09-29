# Honeypot in a sandbox: if anyone ever exploits a bug in the honeypot
# itself, they're trapped in this container — no host access, no tools,
# read-only filesystem, almost no Linux capabilities.
FROM python:3.12-slim

WORKDIR /app

# Only the honeypot code goes in. No build tools, no extras.
# Every module honeypot.py imports must ship: vault (hard import) plus the
# optional integrations (chainlog, exploitwatch, aliveness, honeycreds,
# ed_shell degrade gracefully if missing, but ship them anyway).
COPY honeypot.py vault.py chainlog.py exploitwatch.py aliveness.py \
     honeycreds.py ed_shell.py siem.py ./
COPY soft-target-banners.json ./
COPY profiles/ ./profiles/

# Run as a non-root user. Docker grants CAP_NET_BIND_SERVICE by default,
# so binding privileged ports (21, 22, 23, 25, 80) still works.
RUN useradd --system --uid 10000 --no-create-home honey \
    && mkdir -p /app/logs \
    && chown honey:honey /app/logs
USER honey

EXPOSE 21 22 23 25 80 1433 2375 3306 3389 5432 5900 6379 9200 27017

CMD ["python3", "honeypot.py", "--log", "/app/logs/events.jsonl"]
