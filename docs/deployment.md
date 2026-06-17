# Deployment

This project is intended to run as a reproducible lab demo stack. Docker Compose
starts the Cowrie honeypot, the Python backend pipeline/API, the React
frontend, Prometheus, and Grafana.

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

Open Grafana at:

```text
http://localhost:3000
```

Open Prometheus at:

```text
http://localhost:9090
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
- Prometheus scrape config changes: `docker compose up -d --build prometheus`
- Grafana provisioning/dashboard changes: `docker compose up -d --build grafana`
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
docker compose logs -f prometheus
docker compose logs -f grafana
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

## GitHub Actions CD to a Local VM

Pushes to `main` run `.github/workflows/deploy-vm.yml`. The workflow builds
the backend and frontend Docker images, pushes them to GitHub Container
Registry, then runs the deploy job on a self-hosted GitHub Actions runner
installed on the VM. The local deploy job pulls the latest repository changes,
pulls the new images, and restarts the Docker Compose stack.

This self-hosted runner approach is intended for a VM on a local or private
network where GitHub-hosted runners cannot connect over SSH.

The workflow uses the GitHub Environment named:

```text
production-vm
```

Create that environment in GitHub repository settings before relying on the
deployment. Add required reviewers there if deploys should wait for approval.

### Required GitHub Environment Variable

Set `VM_DEPLOY_PATH` as a GitHub Environment variable on `production-vm`. This
is the repository path on the VM, for example:

```text
/opt/honeypot-threat-intelligence-pipeline
```

No VM SSH host, user, port, or private key secrets are needed when deployment
runs on the self-hosted runner.

### First-Time VM Setup

Install Git and Docker with the Compose plugin on the VM. Then clone the
repository into the deploy path and create the local runtime `.env`:

```bash
sudo apt-get update
sudo apt-get install -y git docker.io docker-compose-plugin
sudo usermod -aG docker "$USER"
git clone https://github.com/OWNER/REPOSITORY.git /opt/honeypot-threat-intelligence-pipeline
cd /opt/honeypot-threat-intelligence-pipeline
cp .env.example .env
```

Log out and back in after adding the deploy user to the `docker` group.

### Self-Hosted Runner Setup

In GitHub, open the repository settings and add a new self-hosted runner:

```text
Settings -> Actions -> Runners -> New self-hosted runner
```

Choose Linux and run the commands GitHub shows on the VM. When configuring the
runner, give it this label in addition to the default labels:

```text
honeypot-vm
```

Install and start the runner service so deploys continue after reboot:

```bash
sudo ./svc.sh install
sudo ./svc.sh start
```

The application `.env` file stays on the VM and is not committed. GitHub Actions
creates `.env.deploy` during deployment with only the image registry prefix and
commit tag used by `docker-compose.vm.yml`.

### Manual VM Deploy Command

For testing the VM compose path without GitHub Actions, set the image variables
and run:

```bash
cat > .env.deploy <<'EOF'
GHCR_IMAGE_PREFIX=ghcr.io/OWNER/REPOSITORY
IMAGE_TAG=latest
EOF

docker compose --env-file .env.deploy -f docker-compose.yml -f docker-compose.vm.yml pull backend frontend
docker compose --env-file .env.deploy -f docker-compose.yml -f docker-compose.vm.yml up -d --no-build
```
