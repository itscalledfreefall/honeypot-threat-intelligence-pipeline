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
- `src/honeypot_pipeline/cowrie.py`
  Parses and normalizes Cowrie JSON log lines.
- `src/honeypot_pipeline/ioc.py`
  Extracts indicators such as IP addresses, usernames, passwords, commands, and URLs.
- `src/honeypot_pipeline/classification.py`
  Assigns a simple attack category and severity to each event.
- `src/honeypot_pipeline/cli.py`
  Small command-line entry point for normalizing a Cowrie log file and exporting results.
- `src/honeypot_pipeline/dashboard.py`
  Runs a read-only web dashboard over processed event records and summaries.
- `tests/`
  Automated tests for the parser, classification, enrichment, and output helpers.

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

- firewall blocklist generation
- safe review workflow before blocking
- optional automatic enforcement in a lab environment

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

## What We Will Build Next

The next coding step after this scaffold is API enrichment:

1. take a normalized event
2. extract the attacker IP
3. query a threat-intelligence provider
4. attach the result to the event
5. save the enriched output

The pipeline now also supports:

1. rule-based attack categorization
2. writing processed events to a JSONL output file
3. writing a batch summary JSON document

The project now also includes:

1. a local Flask dashboard for browsing processed honeypot events
2. event filtering by IP, event type, attack category, and protocol
3. detail views for enrichment and raw event inspection
4. optional auto-refresh for a live demo while new records are appended
5. safe action outputs like downloadable blocklists and markdown reports
6. a Docker-based Cowrie lab path and helper script for live demos

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
