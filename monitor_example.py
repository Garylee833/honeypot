"""Example: import the honeypot and monitor it from your own Python code.

Run with:  python3 monitor_example.py
"""
import threading
import time

import honeypot  # the honeypot.py file, sitting next to this script

seen_ips = set()


@honeypot.on_event
def watch(event):
    # This runs the instant any visitor does anything.
    ip = event["src_ip"]
    if ip not in seen_ips:
        seen_ips.add(ip)
        print(f"[ALERT] new visitor {ip} probing {event['service']}", flush=True)
    if "password=" in event["data"]:
        print(f"[ALERT] {ip} tried a password on {event['service']}: "
              f"{event['data']}", flush=True)


# Start whatever fake services you want, each in its own thread.
threading.Thread(target=honeypot.serve, args=(2222, "ssh", "logs/events.jsonl"),
                 daemon=True).start()
threading.Thread(target=honeypot.serve, args=(2324, "telnet", "logs/events.jsonl"),
                 daemon=True).start()

print("Monitoring... press Ctrl+C to stop.")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print(f"\nDone. Saw {len(seen_ips)} unique visitor(s).")
