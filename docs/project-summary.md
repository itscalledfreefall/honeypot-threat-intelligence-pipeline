# Project Summary

This file translates the COMP490/498 proposal into implementation terms.

## Proposal Summary

Project title:
`Autonomous Honeypot Network and Threat Intelligence Pipeline`

Main idea:

1. deploy honeypot services such as SSH and web decoys
2. collect attacker activity logs centrally
3. analyze events in near real time
4. query threat-intelligence services for attacker reputation
5. automate response actions such as firewall blocking
6. support repeatable deployment with infrastructure automation

## Required Capabilities

From the proposal, the system should eventually support:

- honeypot deployment
- log collection
- extraction of attacker IPs and metadata
- threat-intelligence enrichment
- automated incident response
- dashboard visualization

## Technologies Mentioned In The Proposal

- Ubuntu Server
- Python
- Docker / Docker Compose
- Terraform or Ansible
- Cowrie
- Dionaea or a web honeypot
- ELK Stack
- AbuseIPDB API
- VirusTotal API

## Evaluation Criteria Converted To Engineering Tasks

- `System functionality`
  We need to reliably collect and store honeypot logs.
- `Detection capability`
  We need a parser that extracts attacker IPs and key fields correctly.
- `Threat intelligence correlation`
  We need enrichment logic and API clients with clear output.
- `Automation effectiveness`
  We need a controlled response layer that can update firewall rules.
- `Scalability`
  We need repeatable deployment and support for multiple honeypot instances.
- `Visualization`
  We need a dashboard or at least structured outputs that can feed one.

## Practical First Milestone

The first milestone in this repo is intentionally smaller than the full proposal:

1. normalize Cowrie log events
2. extract indicators from each event
3. create a clean interface for later enrichment
4. classify the attack behavior for reporting
5. export processed records and batch summaries

This de-risks the rest of the project because enrichment, dashboards, and automation all depend on having a stable event schema.
