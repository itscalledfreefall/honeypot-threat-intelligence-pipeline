# Safety Model

This project is designed for a controlled honeypot lab. It intentionally
collects hostile input, so the system must never treat collected data as trusted
program input.

## Trust Boundaries

### Untrusted Inputs

The following values are attacker-controlled and must be treated as hostile:

- Cowrie raw log events
- usernames and passwords
- shell commands
- URLs and domains
- file names and file paths
- payload references
- source IP metadata
- any copied payload content

These values may be stored, parsed, displayed, or exported, but they must not be
executed.

### Trusted Configuration

The following values are considered operator-controlled:

- `.env` values
- Docker Compose service definitions
- local SQLite database path
- API keys provided through environment variables
- explicit command-line flags

Secrets must stay in environment variables or local files excluded from source
control.

## Safety Rules

1. Do not execute collected commands or payloads.
2. Do not download attacker payloads unless the repository policy is updated for
   a controlled malware-sample workflow.
3. Do not commit `.env`, API keys, private keys, raw captures, large generated
   datasets, or live infrastructure details.
4. Keep raw logs under `data/raw/` or Docker volumes and processed outputs under
   `data/processed/`, `exports/`, or `reports/generated/`.
5. Keep automated blocking dry-run by default.
6. Only apply firewall rules in a lab environment after reviewing blocklist
   candidates.
7. Sanitize examples used in reports, screenshots, and documentation.

## Response Safety

The firewall response module is intentionally conservative:

- `honeypot-block` defaults to dry-run output.
- `--apply` is required before iptables rules are changed.
- generated scripts include review instructions.
- rules are tagged with a comment prefix so they can be listed and removed.

The response layer is suitable for lab containment and demonstration. It should
not be used as an unattended production firewall controller without additional
approval workflow, logging, authentication, and rollback controls.

## Dashboard Safety

The dashboard is read-only. It displays attacker-controlled fields such as
commands and URLs, but it does not execute them. Future dashboard changes should
continue to render these values as text and avoid injecting them into HTML.

## Threat-Intelligence API Safety

AbuseIPDB and VirusTotal API keys are optional and must be supplied through
environment variables. The pipeline should still run without API keys by
skipping enrichment.

Provider failures should be recorded as enrichment status, not treated as
pipeline failures. This keeps demonstrations reproducible even when external
services are unavailable.

## Lab Deployment Assumptions

The intended demo environment is:

- isolated VM or lab server
- Docker Compose controlled by the project operator
- Cowrie exposed only as needed for demonstration
- no production credentials reused
- no real production systems colocated with the honeypot

If the honeypot is exposed to the public internet, the operator must treat the
host as a high-risk lab asset and isolate it from personal, university, and
production networks.

## Known Limitations

- The current pipeline enriches primarily by source IP.
- The current response model is local iptables blocking, not enterprise
  orchestration.
- SQLite is appropriate for a single demo server but not for high-volume
  multi-node ingestion.
- Cowrie captures interaction behavior, but it does not prove attribution.
- Threat-intelligence provider scores are reputation signals, not definitive
  evidence of attacker identity.

