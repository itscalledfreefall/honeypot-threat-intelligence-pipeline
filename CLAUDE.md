# CLAUDE.md

## Repository Intent

Build a honeypot threat intelligence pipeline for the COMP490 project. The codebase should evolve toward safe collection, normalization, enrichment, indicator extraction, and reporting for honeypot telemetry.

## Default Expectations

1. Prefer Python for implementation unless the repo later standardizes on something else.
2. Keep the design modular: ingestion, parsing, enrichment, storage, and reporting should be separable.
3. Treat raw telemetry, payload references, and attacker commands as untrusted data.
4. Keep generated artifacts and large datasets out of git.

## Working Conventions

1. Read the repository state before editing.
2. Avoid destructive commands unless explicitly requested.
3. Do not overwrite user changes.
4. Make the smallest correct change that moves the project forward.
5. Add or update docs when behavior or setup changes.

## Security Conventions

1. Never commit secrets or local lab credentials.
2. Do not run captured payloads.
3. Prefer offline parsing and enrichment flows where possible.
4. Keep examples sanitized if they include sensitive data.

## Suggested Near-Term Build Order

1. Create a `README.md` that defines scope, architecture, and setup.
2. Add a minimal source layout under `src/` and `tests/`.
3. Implement a first ingestion path for honeypot logs.
4. Add normalization and indicator extraction.
5. Add persistence and reporting outputs.

## Ignore Policy

This repository uses a broad `.gitignore` to exclude editor files, Python artifacts, container state, logs, databases, captures, processed data, and secrets. Keep tracked files limited to source, tests, docs, and safe fixtures.
