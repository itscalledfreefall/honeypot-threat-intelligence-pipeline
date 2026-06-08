# Deployment

This project is intended to run as a reproducible lab demo stack. Docker Compose
starts the Cowrie honeypot, the Python backend pipeline/API, and the React
frontend.

## Quick Start

```bash
cp .env.example .env
docker compose up -d --build
docker compose ps
```

Open the dashboard at:

```text
http://localhost:5173
```

The backend API is available at:

```text
http://localhost:5000/api/summary
```

Cowrie listens on the demo SSH port:

```text
localhost:2222
```

## Rebuild Guidance

Rebuild only the services affected by the change:

- Python pipeline, API, storage, reporting, or response changes: `docker compose up -d --build backend`
- Frontend UI changes: `docker compose up -d --build frontend`
- Cowrie config changes: restart or recreate `cowrie`
- Dockerfile or Compose changes: rebuild the affected service

For a full clean rebuild:

```bash
docker compose up -d --build
```

## Runtime Outputs

The following local paths are runtime outputs and are intentionally ignored by
git:

- `data/raw/`
- `data/processed/`
- `exports/`
- `reports/generated/`

Docker volumes are used for the normal compose deployment:

- `cowrie-logs`
- `cowrie-lib`
- `pipeline-data`
- `pipeline-exports`
- `pipeline-reports`

Do not commit raw honeypot logs, generated reports, SQLite databases, payload
captures, API keys, or local `.env` files.

## Useful Commands

```bash
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f cowrie
```

Stop the stack:

```bash
docker compose down
```

Stop the stack and remove Docker volumes:

```bash
docker compose down -v
```

Use `down -v` only when you intentionally want to delete collected lab data.

