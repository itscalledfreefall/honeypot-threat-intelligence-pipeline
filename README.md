# Honeypot Threat Intelligence Pipeline

This repository is the implementation space for the COMP490/498 graduation project: an autonomous honeypot network and threat-intelligence pipeline.

## What This Project Is

A honeypot is a decoy system that is designed to attract attackers. Instead of trying to prevent every attack up front, a honeypot lets us safely observe malicious behavior and collect useful telemetry such as:

- attacker IP addresses
- login attempts
- commands entered after access
- payload download attempts
- connection patterns

The long-term goal of this project is to:

1. deploy one or more honeypots in a controlled environment
2. collect and centralize the generated logs
3. normalize the logs into a consistent event format
4. enrich attacker data with threat-intelligence APIs such as AbuseIPDB and VirusTotal
5. automate response actions such as firewall blocking
6. visualize activity in dashboards

## Current Scope

This repository starts with the safest and most practical first slice:

1. read honeypot log events from a file
2. normalize them into a structured schema
3. extract simple indicators of compromise (IOCs)
4. classify the observed attack behavior
5. export structured records and batch summaries for later analysis

This is the right first step because all later features depend on trustworthy event parsing.

## Initial Architecture

- `src/honeypot_pipeline/models.py`
  Defines the normalized event structure used across the pipeline.
- `src/honeypot_pipeline/parsers/`
  Parses and normalizes honeypot-specific logs such as Cowrie JSON lines.
- `src/honeypot_pipeline/analysis/`
  Extracts indicators, classifies behavior, builds records, tracks summaries, and scores risk.
- `src/honeypot_pipeline/enrichment/`
  Queries AbuseIPDB and VirusTotal for threat intelligence on attacker IPs.
- `src/honeypot_pipeline/storage/`
  Provides persistent SQLite storage and JSON output helpers.
- `src/honeypot_pipeline/api/`
  Runs a read-only Flask dashboard API over processed event records and summaries.
- `src/honeypot_pipeline/reporting/`
  Generates markdown reports, malicious-event exports, and blocklist outputs.
- `src/honeypot_pipeline/response/`
  Provides safe-by-default iptables firewall blocking from pipeline threat intelligence.
- `src/honeypot_pipeline/cli.py`
  Command-line entry point for normalizing Cowrie logs and running enrichment.
- `frontend/`
  React dashboard application served by the frontend container.
- `tests/`
  Automated tests for parsers, classification, enrichment, database, response, and API.

More detailed design notes are available in:

- `docs/architecture.md`
  End-to-end component model, data flow, deployment shape, and extension points.
- `docs/safety-model.md`
  Lab safety assumptions, trust boundaries, response safety, and known limitations.
- `docs/deployment.md`
  Demo-server setup, container rebuild guidance, and ignored runtime output paths.

## Why Cowrie First

Cowrie is a widely used SSH/Telnet honeypot. It produces structured JSON logs and matches the project brief directly. Starting here keeps the first implementation simple and relevant.

## Project Roadmap

### Phase 1

Local parser and normalized schema for Cowrie events.

### Phase 2

Threat-intelligence enrichment:

- AbuseIPDB lookup
- VirusTotal lookup
- maliciousness scoring

### Phase 3

Storage and visualization:

- save normalized events
- save enrichment results
- build dashboards

### Phase 4

Automated response:

- firewall blocklist generation ✓
- safe review workflow before blocking ✓
- optional automatic enforcement in a lab environment ✓
- persistent SQLite storage with deduplication ✓
- attack session tracking and timeline ✓

## Quick Start

Create a virtual environment and install the package:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run the included example:

```bash
PYTHONPATH=src python3 -m honeypot_pipeline.cli examples/cowrie.sample.ndjson
```

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Important Safety Notes

1. Treat all captured data as untrusted.
2. Do not execute attacker payloads.
3. Do not expose a real production system while testing.
4. Keep API keys in environment variables, not in source control.

## Current Features

The pipeline currently supports:

1. Cowrie JSON log normalization with structured event schema
2. rule-based attack categorization (brute force, malware download, recon, persistence, command execution)
3. IOC extraction (IPs, usernames, passwords, commands, URLs)
4. dual threat-intelligence enrichment (AbuseIPDB + VirusTotal) with confidence scoring
5. persistent SQLite storage with 60-second deduplication window
6. attack session tracking with timeline views
7. read-only Flask JSON API backend
8. React dashboard with Overview, Events, Sessions, Timeline, Devices, and Monitoring tabs
9. exportable blocklists, malicious record exports, and markdown reports
10. automated iptables firewall blocking with dry-run safety and shell script generation
11. Docker-based Cowrie lab environment with a helper script for live demos
12. Prometheus + Grafana monitoring for historical device and attack graphs

## Device Monitoring

The **Devices** tab lists the machines where the honeypot service runs and shows
their live health (uptime, RAM, CPU load, disk, hostname/IP) based on agent
heartbeats. With one device it shows a single card; with several it becomes a grid.

Enroll a device from the Devices tab. This returns a one-time agent token and a
copy-paste install command — the token is shown only once and is stored hashed.
On the target Linux machine, paste the command (any directory): it downloads the
agent from the dashboard and starts reporting. Requires Python 3 and `curl`.

```bash
# Generated by the Devices tab — host:port and token are filled in for you.
# Installs a systemd service (honeypot-agent) that auto-starts on boot.
curl -fsSL http://<dashboard-host>:5173/api/devices/agent.py -o device-agent.py && \
  sudo python3 device-agent.py --install-service --api-url http://<dashboard-host>:5173 --token <agent-token>

# Manage it:
systemctl status honeypot-agent
journalctl -u honeypot-agent -f
sudo systemctl disable --now honeypot-agent   # stop and remove from boot

# For a quick foreground test instead of a service:
python3 device-agent.py --api-url http://<dashboard-host>:5173 --token <agent-token> --once
```

The agent uses only safe local reads (`/proc`, `shutil`, `socket`) — it runs no
shell commands and posts nothing attacker-controlled. The systemd service reports
every 30s, restarts on failure, and survives reboots. The token is baked into the
root-only unit file, keeping the service linked to its device. A device is **online** when
seen within 60s, **stale** within 10 minutes, and **offline** after that. The agent
token authorizes heartbeats only — it is not a user login token. Devices can be
removed from the Devices tab via the **Remove** button on each card.

## Grafana Monitoring

The **Monitoring** tab embeds Grafana for historical graphs while the React
dashboard remains the source of truth for user login, device enrollment, and
current device state.

Docker Compose now starts:

- Grafana at `http://localhost:3000`
- Prometheus at `http://localhost:9090`

Prometheus scrapes the backend `/metrics` endpoint every 15 seconds. Grafana is
provisioned automatically with a `Honeypot Monitoring` dashboard showing:

- online and stale device counts
- RAM, disk, CPU load, uptime, and last-seen age over time
- event volume, malicious event volume, and unique attacker IPs
- attack category, protocol, and risk-level breakdowns

The embedded Grafana dashboard defaults to the logged-in user's `user_id` as a
dashboard variable. This is a display filter only; device ownership remains
enforced by the Flask API and React app.

## Automated Firewall Response

After the pipeline identifies malicious IPs, you can apply iptables
blocking rules.  All operations default to **dry-run** for safety.

```bash
# Review what would be blocked (safe, no root needed)
scripts/apply-blocklist.sh review

# Generate a standalone shell script for manual review
scripts/apply-blocklist.sh script

# Apply the blocklist (requires root)
sudo scripts/apply-blocklist.sh apply

# List currently blocked IPs
scripts/apply-blocklist.sh list

# Remove previously applied blocks
sudo scripts/apply-blocklist.sh unblock
```

Or use the CLI directly:

```bash
# Dry-run (default)
honeypot-block --db data/honeypot.db

# Apply
sudo honeypot-block --db data/honeypot.db --apply

# Generate a standalone shell script
honeypot-block --db data/honeypot.db --generate-script reports/generated/blocklist.sh

# Block specific IPs directly
sudo honeypot-block --ip 10.0.0.99 --ip 192.168.1.100 --apply
```

## Environment Variables

Copy values from `.env.example` into your shell or local environment:

```bash
export ABUSEIPDB_API_KEY="your-key-here"
export VIRUSTOTAL_API_KEY="your-key-here"
```

Run the CLI with enrichment enabled:

```bash
PYTHONPATH=src python3 -m honeypot_pipeline.cli \
  examples/cowrie.sample.ndjson \
  --enrich-abuseipdb
```

Run the CLI with both providers:

```bash
PYTHONPATH=src python3 -m honeypot_pipeline.cli \
  examples/cowrie.sample.ndjson \
  --enrich-abuseipdb \
  --enrich-virustotal
```

Write processed records to disk:

```bash
PYTHONPATH=src python3 -m honeypot_pipeline.cli \
  examples/cowrie.sample.ndjson \
  --output-file exports/cowrie.records.jsonl \
  --summary-file reports/generated/cowrie.summary.json
```

Follow a live Cowrie log file and keep appending processed records:

```bash
PYTHONPATH=src python3 -m honeypot_pipeline.cli \
  /path/to/cowrie.json \
  --follow \
  --poll-interval 1 \
  --output-file exports/cowrie.records.jsonl \
  --summary-file reports/generated/cowrie.summary.json
```

Run the dashboard against saved output:

```bash
honeypot-dashboard \
  --records-file exports/cowrie.records.jsonl \
  --summary-file reports/generated/cowrie.summary.json
```

Then open `http://127.0.0.1:5000`.

For a live demo, add `?refresh=3` to the events page URL to auto-refresh every 3 seconds.

Generate a report bundle from saved output:

```bash
honeypot-report \
  --records-file exports/cowrie.records.jsonl \
  --summary-file reports/generated/cowrie.summary.json \
  --output-dir reports/generated/demo-bundle
```

## Live Lab Demo

This repository now includes:

- a Cowrie Docker setup in [docker-compose.yml](/home/fe/honeypot-threat-intelligence-pipeline/docker/cowrie/docker-compose.yml)
- a lab helper script in [lab-demo.sh](/home/fe/honeypot-threat-intelligence-pipeline/scripts/lab-demo.sh)
- a full walkthrough in [live-lab-demo.md](/home/fe/honeypot-threat-intelligence-pipeline/docs/live-lab-demo.md)

Quick flow:

```bash
scripts/lab-demo.sh up-cowrie
scripts/lab-demo.sh pipeline
scripts/lab-demo.sh dashboard
```

Then, from another machine:

```bash
ssh -p 2222 root@<target-ip>
```

Open:

`http://127.0.0.1:5000/events?refresh=3`
