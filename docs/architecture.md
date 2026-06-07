# Architecture

This project is a reproducible honeypot threat-intelligence lab. It collects
attacker interaction data from Cowrie, normalizes events into a stable schema,
extracts indicators, enriches source IPs with threat-intelligence providers,
stores the results, and exposes them through reports and a dashboard.

## System Goals

1. Keep raw honeypot telemetry separate from processed intelligence outputs.
2. Normalize every event before enrichment, storage, reporting, or response.
3. Treat commands, payload URLs, credentials, and raw log fields as hostile data.
4. Make the demo environment repeatable with Docker Compose and environment
   variables.
5. Keep response actions reviewable and safe by default.

## Components

### Cowrie Honeypot

Cowrie runs as the SSH/Telnet decoy and writes JSON log events. In the Docker
lab, Cowrie logs are stored in the `cowrie-logs` volume and mounted read-only
into the backend container.

### Pipeline CLI

The backend container starts `honeypot_pipeline.cli` in follow mode. The CLI
reads Cowrie JSON lines, normalizes each event, extracts indicators, classifies
the behavior, optionally enriches the source IP, writes JSONL exports, writes a
summary file, and persists events into SQLite.

### Normalized Event Schema

`NormalizedEvent` in `src/honeypot_pipeline/models.py` is the shared input
schema for downstream analysis. Parser-specific fields remain available through
`raw_event`, but downstream code should use normalized fields first.

### IOC Extraction

`src/honeypot_pipeline/ioc.py` extracts indicators from normalized fields and
from attacker-controlled text such as commands and URLs. Extracted indicators
are structured by type so future enrichers can operate on IPs, URLs, domains,
hashes, file paths, and payload references independently.

### Classification And Risk

`src/honeypot_pipeline/classification.py` assigns deterministic categories such
as brute force, reconnaissance, malware download, persistence, and command
execution. `src/honeypot_pipeline/risk.py` converts event and session evidence
into a risk score, risk level, and explainable reason list.

### Threat-Intelligence Enrichment

`src/honeypot_pipeline/enrichment.py` supports AbuseIPDB and VirusTotal lookups.
Provider results are merged into a common score, while provider-specific raw
results remain attached for auditability.

### SQLite Storage

`src/honeypot_pipeline/database.py` stores events, enrichment results, and
attack sessions. SQLite is used because it is reproducible, container-friendly,
and sufficient for the lab scope. The schema is designed so it can later move to
PostgreSQL if multi-node ingestion is needed.

### API And Dashboard

`src/honeypot_pipeline/dashboard.py` exposes a read-only Flask JSON API. The
React frontend consumes that API to show summaries, events, sessions, timelines,
and export links.

### Reporting And Response

`src/honeypot_pipeline/reporting.py` builds markdown reports, malicious-event
exports, and blocklists. `src/honeypot_pipeline/response.py` turns reviewed
blocklist candidates into iptables rules. Response actions are dry-run by
default.

## Data Flow

```text
Attacker
  |
  v
Cowrie SSH honeypot
  |
  v
Raw Cowrie JSON log volume
  |
  v
Pipeline CLI
  |
  +--> normalize Cowrie event
  +--> extract indicators
  +--> classify behavior
  +--> score event risk
  +--> enrich source IP, when API keys are configured
  |
  +--> processed JSONL export
  +--> summary JSON
  +--> SQLite events, threat intel, sessions, and session risk
          |
          v
      Flask API
          |
          +--> React dashboard
          +--> markdown report
          +--> malicious-event export
          +--> blocklist export
```

## Deployment Shape

The primary deployment target is a lab demo server:

- Cowrie container exposes the honeypot port.
- Backend container runs the pipeline and API.
- Frontend container serves the dashboard.
- Docker volumes hold logs, SQLite data, exports, and reports.
- `.env` provides optional API keys and runtime paths.

This is not a production internet service architecture. It is a repeatable lab
environment suitable for demonstration, controlled data collection, and
graduation-project evaluation.

## Extension Points

The project is intentionally structured so future work can be added without
rewriting the pipeline:

- Add another honeypot parser beside `cowrie.py`.
- Add another IOC type in `ioc.py`.
- Add another enrichment provider beside AbuseIPDB and VirusTotal.
- Add another storage backend behind the database API.
- Add new risk factors in `risk.py`.
- Add dashboard views without changing parser logic.

