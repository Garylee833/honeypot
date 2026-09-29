# Honeypot Hardening Runbook — Oracle Cloud deployment day

Follow top to bottom. Don't skip steps. Each one is a layer; the layers
are the whole point.

---

## 0. Prerequisites

- Oracle Cloud account approved (Always Free)
- An SSH key on your machine: `ssh-keygen -t ed25519 -f ~/.ssh/oracle-honeypot`
- This honeypot folder copied to the new VM (via `scp` after step 2)

---

## 1. Create the VM

- Shape: **VM.Standard.E2.1.Micro** (Always Free)
- Image: **Ubuntu 22.04**
- Networking: public subnet, **assign a public IP**
- Paste your `~/.ssh/oracle-honeypot.pub` as the SSH key
- Name it something boring: `research-01` (not "honeypot" — don't advertise)

---

## 2. First login + non-root user

```bash
ssh -i ~/.ssh/oracle-honeypot ubuntu@<PUBLIC_IP>

sudo adduser deploy
sudo usermod -aG sudo deploy
sudo mkdir -p /home/deploy/.ssh
sudo cp ~/.ssh/authorized_keys /home/deploy/.ssh/
sudo chown -R deploy:deploy /home/deploy/.ssh
sudo chmod 700 /home/deploy/.ssh && sudo chmod 600 /home/deploy/.ssh/authorized_keys
```

From now on, log in as `deploy`, never `ubuntu`.

---

## 3. Lock down SSH

```bash
sudo nano /etc/ssh/sshd_config
```
Set:
```
PasswordAuthentication no
PermitRootLogin no
ChallengeResponseAuthentication no
```
```bash
sudo systemctl restart ssh
```
Test a **new** login in a second terminal before closing the first. If the
new login works, password auth is dead and keys are the only way in.

---

## 4. Automatic security updates

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades   # answer Yes
```

---

## 5. fail2ban (brute-force protection for the real SSH)

```bash
sudo apt install -y fail2ban
sudo systemctl enable --now fail2ban
```
Defaults are fine: 5 failed logins → 10-minute ban.

---

## 6. Host firewall — the big one

Default-deny everything, then open only what's needed. The honeypot should
**never initiate outbound connections** — if it tries, that's your alarm.

```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default deny outgoing

# outbound: DNS + updates only
sudo ufw allow out 53
sudo ufw allow out 80
sudo ufw allow out 443

# inbound: honeypot services
for p in 21 22 23 25 80 1433 2375 3306 3389 5432 5900 6379 9200 27017; do
  sudo ufw allow in $p
done

# inbound: YOUR admin SSH — restrict to your IP if you have a stable one:
#   sudo ufw allow in from <YOUR_HOME_IP> to any port 22
# otherwise (dynamic IP):
sudo ufw allow in 22

sudo ufw enable
sudo ufw status verbose
```

Also mirror this in the Oracle Cloud console: VCN → Security List for the
public subnet → same inbound rules. Two firewalls, same policy.

**Do NOT open port 8080.** The dashboard binds to 127.0.0.1 — reach it
through an SSH tunnel instead:
```bash
ssh -L 8080:127.0.0.1:8080 -i ~/.ssh/oracle-honeypot deploy@<PUBLIC_IP>
# then open http://127.0.0.1:8080 on YOUR machine
```

---

## 7. Install Docker + deploy the honeypot

```bash
sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker deploy
# log out and back in for the group to apply

mkdir -p ~/honeypot && cd ~/honeypot
# copy the honeypot files here (scp from your machine):
#   scp -i ~/.ssh/oracle-honeypot -r honeypot/* deploy@<PUBLIC_IP>:~/honeypot/

docker compose up --build -d
docker ps   # honeypot container should be Up
```

Verify from your machine:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://<PUBLIC_IP>/
nmap <PUBLIC_IP>   # you should see your 14 trap ports
```

---

## 8. Monitoring

On the VM, in a persistent session (or tmux):
```bash
cd ~/honeypot && python3 siem.py
```
Watch for `SHELL_ACCESS` (CRITICAL) — someone reached the fake shell — and
sustained `BRUTE_FORCE`/`PORT_SCAN` storms.

---

## 9. Log backups (attackers wipe local logs first)

```bash
crontab -e
# add:
0 * * * * tar -czf ~/honeypot-backup-$(date +\%F-\%H).tar.gz -C ~/honeypot logs/ && ls -t ~/honeypot-backup-* | tail -n +25 | xargs -r rm
```
Hourly compressed logs, keeps the last 24. When you have a second machine,
add an `rsync`/`scp` of the newest archive off the box.

---

## 10. Snapshot before going live

OCI Console → Compute → your instance → Boot Volume → **Create Manual
Backup**. If the box ever gets owned, recovery is: terminate, restore,
re-harden. One click instead of one weekend.

---

## 11. Verification checklist (do this before telling anyone the IP)

- [ ] `ssh` with password fails; key login works; root login fails
- [ ] `sudo ufw status` shows deny-by-default + only expected ports
- [ ] Container is `Up` and all 14 ports answer
- [ ] `siem.py` fires BRUTE_FORCE when you attack it yourself
- [ ] Dashboard reachable **only** via SSH tunnel, not directly
- [ ] Unattended upgrades enabled, fail2ban active
- [ ] Boot volume backup exists
- [ ] You have the SSH private key backed up somewhere safe

---

## 12. If you suspect compromise

1. **Don't log in to investigate from the box** — snapshot the boot volume
   first (evidence), then terminate the instance.
2. Check your off-box log copies: what did they touch? (`SHELL_ACCESS`
   alerts, outbound connection attempts blocked by the firewall.)
3. Restore from the pre-live snapshot or rebuild fresh — never try to
   "clean" a owned box.
4. Rotate the SSH key.

Remember: the honeypot is bait. A compromise of the *bait* is the system
working as designed — the layers above are what keep it from becoming a
compromise of *you*.
