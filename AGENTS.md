# AGENTS.md

## Project

This repository will contain a honeypot threat intelligence pipeline derived from the COMP490 project brief. The expected direction is:

1. Collect attacker interaction data from one or more honeypots.
2. Normalize and enrich the events.
3. Extract indicators such as IPs, URLs, domains, hashes, commands, and payload references.
4. Store results in structured outputs for analysis and reporting.
5. Keep the system reproducible, container-friendly, and safe to run in a lab environment.

## Priorities

1. Default to Python for pipeline code unless the repository establishes another standard.
2. Keep raw captures separate from parsed or enriched outputs.
3. Never commit secrets, live credentials, private keys, or large generated datasets.
4. Treat any captured payloads or attacker commands as untrusted input.
5. Prefer small, testable modules over large scripts.

## Expected Structure

Suggested layout as the project grows:

- `src/` application code
- `tests/` automated tests
- `data/raw/` local uncommitted capture data
- `data/processed/` derived local artifacts
- `docs/` project notes and reports
- `docker/` container assets
- `scripts/` operator and maintenance scripts

## Engineering Rules

1. Use environment variables for configuration.
2. Add an `.env.example` instead of committing real secrets.
3. Write clear README setup steps before adding complex tooling.
4. Add tests for parser, enrichment, and transformation logic.
5. Log enough to debug ingestion and parsing failures without leaking secrets.

## Security Rules

1. Assume all network data is hostile.
2. Do not execute collected payloads.
3. Do not commit malware samples or binaries unless the user explicitly wants a controlled sample set and the repository policy is updated.
4. Sanitize any data shown in examples when it contains sensitive infrastructure details.
5. Keep lab-only configuration isolated from production-like settings.

## Agent Workflow

1. Inspect the current repository before making assumptions.
2. Preserve existing user changes.
3. Prefer focused edits over broad rewrites.
4. Update documentation when adding new commands, directories, or services.
5. Verify changes with tests or linting when the project contains those checks.

## Behavioral Guidelines

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

Tradeoff: These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

Minimum code that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

Touch only what you must. Clean up only your own mess.

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

Define success criteria. Loop until verified.

Transform tasks into verifiable goals:
- "Add validation" -> "Write tests for invalid inputs, then make them pass"
- "Fix the bug" -> "Write a test that reproduces it, then make it pass"
- "Refactor X" -> "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] -> verify: [check]
2. [Step] -> verify: [check]
3. [Step] -> verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.
