#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker/cowrie/docker-compose.yml"
COWRIE_LOG="${ROOT_DIR}/data/raw/cowrie/log/cowrie.json"
RECORDS_FILE="${ROOT_DIR}/exports/cowrie.records.jsonl"
SUMMARY_FILE="${ROOT_DIR}/reports/generated/cowrie.summary.json"
REPORT_DIR="${ROOT_DIR}/reports/generated/demo-bundle"
DB_FILE="${ROOT_DIR}/data/honeypot.db"
FRONTEND_DIR="${ROOT_DIR}/frontend"

usage() {
  cat <<'EOF'
Usage: scripts/lab-demo.sh <command>

Commands:
  up-cowrie       Start the Cowrie Docker container for the isolated lab demo
  down-cowrie     Stop and remove the Cowrie Docker container
  cowrie-logs     Follow Cowrie container logs
  pipeline        Run the threat-intelligence pipeline in live follow mode
  api             Run the Flask JSON API backend (port 5000)
  dashboard       Run the Sharingan React frontend (port 5173)
  report          Generate the report bundle from current saved outputs
  block           Review and apply iptables blocklist rules
  paths           Print the important file paths and attack target
EOF
}

require_venv() {
  if [[ ! -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    echo "Missing .venv. Create it with: python3 -m venv .venv && .venv/bin/pip install -e ."
    exit 1
  fi
}

ensure_dirs() {
  mkdir -p \
    "${ROOT_DIR}/data/raw/cowrie/log" \
    "${ROOT_DIR}/data/raw/cowrie/lib" \
    "${ROOT_DIR}/data" \
    "${ROOT_DIR}/exports" \
    "${ROOT_DIR}/reports/generated"
}

ensure_files() {
  ensure_dirs
  touch "${COWRIE_LOG}"
  touch "${RECORDS_FILE}"
}

compose_cmd() {
  docker compose -f "${COMPOSE_FILE}" "$@"
}

case "${1:-}" in
  up-cowrie)
    ensure_dirs
    compose_cmd up -d
    ;;
  down-cowrie)
    compose_cmd down
    ;;
  cowrie-logs)
    compose_cmd logs -f
    ;;
  pipeline)
    require_venv
    ensure_files
    # Source .env if it exists
    if [[ -f "${ROOT_DIR}/.env" ]]; then
      set -a
      source "${ROOT_DIR}/.env"
      set +a
    fi
    ENRICH_FLAGS=""
    if [[ -n "${ABUSEIPDB_API_KEY:-}" && "${ABUSEIPDB_API_KEY}" != "replace-with-your-api-key" ]]; then
      ENRICH_FLAGS="${ENRICH_FLAGS} --enrich-abuseipdb"
    fi
    if [[ -n "${VIRUSTOTAL_API_KEY:-}" && "${VIRUSTOTAL_API_KEY}" != "replace-with-your-api-key" ]]; then
      ENRICH_FLAGS="${ENRICH_FLAGS} --enrich-virustotal"
    fi
    exec "${ROOT_DIR}/.venv/bin/python" -m honeypot_pipeline.cli \
      "${COWRIE_LOG}" \
      --follow \
      --poll-interval 1 \
      ${ENRICH_FLAGS} \
      --output-file "${RECORDS_FILE}" \
      --summary-file "${SUMMARY_FILE}" \
      --db "${DB_FILE}"
    ;;
  api)
    require_venv
    ensure_files
    # Source .env if it exists
    if [[ -f "${ROOT_DIR}/.env" ]]; then
      set -a
      source "${ROOT_DIR}/.env"
      set +a
    fi
    exec "${ROOT_DIR}/.venv/bin/honeypot-dashboard" \
      --records-file "${RECORDS_FILE}" \
      --summary-file "${SUMMARY_FILE}" \
      --db "${DB_FILE}" \
      --host 0.0.0.0
    ;;
  dashboard)
    if [[ ! -d "${FRONTEND_DIR}/node_modules" ]]; then
      echo "Installing frontend dependencies..."
      (cd "${FRONTEND_DIR}" && npm install)
    fi
    exec npx --prefix "${FRONTEND_DIR}" vite --host 0.0.0.0
    ;;
  report)
    require_venv
    exec "${ROOT_DIR}/.venv/bin/honeypot-report" \
      --records-file "${RECORDS_FILE}" \
      --summary-file "${SUMMARY_FILE}" \
      --output-dir "${REPORT_DIR}"
    ;;
  block)
    require_venv
    exec "${ROOT_DIR}/.venv/bin/honeypot-block" \
      --db "${DB_FILE}" \
      --records-file "${RECORDS_FILE}" \
      "${@:2}"
    ;;
  paths)
    cat <<EOF
Cowrie SSH target: ssh -p 2222 root@<vm-or-host-ip>
Cowrie JSON log:   ${COWRIE_LOG}
Records JSONL:     ${RECORDS_FILE}
Summary JSON:      ${SUMMARY_FILE}
SQLite Database:   ${DB_FILE}
Report bundle:     ${REPORT_DIR}
API URL:           http://127.0.0.1:5000/api/summary
Dashboard URL:     http://127.0.0.1:5173/dashboard
EOF
    ;;
  *)
    usage
    exit 1
    ;;
esac
