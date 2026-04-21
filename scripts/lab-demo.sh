#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${ROOT_DIR}/docker/cowrie/docker-compose.yml"
COWRIE_LOG="${ROOT_DIR}/data/raw/cowrie/log/cowrie.json"
RECORDS_FILE="${ROOT_DIR}/exports/cowrie.records.jsonl"
SUMMARY_FILE="${ROOT_DIR}/reports/generated/cowrie.summary.json"
REPORT_DIR="${ROOT_DIR}/reports/generated/demo-bundle"

usage() {
  cat <<'EOF'
Usage: scripts/lab-demo.sh <command>

Commands:
  up-cowrie       Start the Cowrie Docker container for the isolated lab demo
  down-cowrie     Stop and remove the Cowrie Docker container
  cowrie-logs     Follow Cowrie container logs
  pipeline        Run the threat-intelligence pipeline in live follow mode
  dashboard       Run the local dashboard against the generated outputs
  report          Generate the report bundle from current saved outputs
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
    "${ROOT_DIR}/exports" \
    "${ROOT_DIR}/reports/generated"
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
    ensure_dirs
    exec "${ROOT_DIR}/.venv/bin/python" -m honeypot_pipeline.cli \
      "${COWRIE_LOG}" \
      --follow \
      --poll-interval 1 \
      --enrich-abuseipdb \
      --enrich-virustotal \
      --output-file "${RECORDS_FILE}" \
      --summary-file "${SUMMARY_FILE}"
    ;;
  dashboard)
    require_venv
    exec "${ROOT_DIR}/.venv/bin/honeypot-dashboard" \
      --records-file "${RECORDS_FILE}" \
      --summary-file "${SUMMARY_FILE}"
    ;;
  report)
    require_venv
    exec "${ROOT_DIR}/.venv/bin/honeypot-report" \
      --records-file "${RECORDS_FILE}" \
      --summary-file "${SUMMARY_FILE}" \
      --output-dir "${REPORT_DIR}"
    ;;
  paths)
    cat <<EOF
Cowrie SSH target: ssh -p 2222 root@<vm-or-host-ip>
Cowrie JSON log:   ${COWRIE_LOG}
Records JSONL:     ${RECORDS_FILE}
Summary JSON:      ${SUMMARY_FILE}
Report bundle:     ${REPORT_DIR}
Dashboard URL:     http://127.0.0.1:5000/events?refresh=3
EOF
    ;;
  *)
    usage
    exit 1
    ;;
esac
