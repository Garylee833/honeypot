# Honeypot Replicas

Run **three honeypots on one machine** with zero port conflicts. Same
fortress, parallel dimensions: each replica is an identical copy of the
honeypot, but it answers on a different set of host ports and writes its
own log file.

## Why

- Run a practice replica (attack it freely) next to a "clean" replica
  (watch what background scanners do untouched).
- Triple your sensor coverage on one box.
- Test the blocker/SIEM against one replica without disturbing the others.

## Start / stop

From the honeypot folder:

```bash
docker compose -f docker-compose.replicas.yml up --build -d   # start all three
docker compose -f docker-compose.replicas.yml ps              # check they're up
docker compose -f docker-compose.replicas.yml logs honeypot-b # follow one replica's output
docker compose -f docker-compose.replicas.yml down            # stop and remove all three
```

## Port map

Replica A uses the standard ports (identical to `docker-compose.yml`).
Replica B adds 100, replica C adds 200 — same container ports underneath.

| Service        | Container | A (standard) | B (+100) | C (+200) |
|----------------|-----------|-------------:|---------:|---------:|
| FTP            | 21        | 21           | 121      | 221      |
| SSH            | 22        | 22           | 122      | 222      |
| Telnet         | 23        | 23           | 123      | 223      |
| SMTP           | 25        | 25           | 125      | 225      |
| HTTP           | 80        | 80           | 180      | 280      |
| MSSQL          | 1433      | 1433         | 1533     | 1633     |
| Docker         | 2375      | 2375         | 2475     | 2575     |
| MySQL          | 3306      | 3306         | 3406     | 3506     |
| RDP            | 3389      | 3389         | 3489     | 3589     |
| Postgres       | 5432      | 5432         | 5532     | 5632     |
| VNC            | 5900      | 5900         | 6000     | 6100     |
| Redis          | 6379      | 6379         | 6479     | 6579     |
| Elasticsearch  | 9200      | 9200         | 9300     | 9400     |
| MongoDB        | 27017     | 27017        | 27117    | 27217    |

Example: attack replica B's fake SSH with `nc 127.0.0.1 122`;
replica B's fake web login lives at `http://127.0.0.1:180/`.

## Logs

Each replica writes its own `events.jsonl` into its own host folder —
they never mix:

- Replica A → `./logs-a/events.jsonl`
- Replica B → `./logs-b/events.jsonl`
- Replica C → `./logs-c/events.jsonl`

(The plain `docker-compose.yml` single-instance setup still uses `./logs/`.)

## Pointing the SIEM at one replica

`siem.py` tails a log file. Run it against whichever replica you want to
watch — e.g. to monitor replica B:

```bash
python3 siem.py --log ./logs-b/events.jsonl
```

Add `--replay` to analyze the existing log instead of tailing it live.
The dashboard and blocker follow the SIEM's alerts, so they
automatically watch the same replica.

## Safety

Same rules as the single honeypot: these are fake services that only
*listen*. Never point scanners at anything you don't own — attack only
your own replicas (127.0.0.1 or your own host).
