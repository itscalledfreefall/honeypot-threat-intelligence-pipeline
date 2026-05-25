#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECORDS_FILE="${ROOT_DIR}/exports/cowrie.records.jsonl"
DB_FILE="${ROOT_DIR}/data/honeypot.db"
BLOCKLIST_SCRIPT="${ROOT_DIR}/reports/generated/blocklist.sh"

usage() {
  cat <<'EOF'
Usage: scripts/apply-blocklist.sh <command>

Commands:
  review      Dry-run: show what would be blocked (safe, no root needed)
  script      Generate a standalone shell script to review before applying
  apply       Apply the blocklist via iptables (requires root)
  unblock     Remove previously applied blocklist rules (requires root)
  list        List currently blocked IPs
EOF
}

require_venv() {
  if [[ ! -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    echo "Missing .venv. Create it with: python3 -m venv .venv && .venv/bin/pip install -e ."
    exit 1
  fi
}

case "${1:-}" in
  review)
    require_venv
    exec "${ROOT_DIR}/.venv/bin/honeypot-block" \
      --db "${DB_FILE}" \
      --records-file "${RECORDS_FILE}"
    ;;
  script)
    require_venv
    mkdir -p "$(dirname "${BLOCKLIST_SCRIPT}")"
    exec "${ROOT_DIR}/.venv/bin/honeypot-block" \
      --db "${DB_FILE}" \
      --records-file "${RECORDS_FILE}" \
      --generate-script "${BLOCKLIST_SCRIPT}"
    ;;
  apply)
    require_venv
    exec "${ROOT_DIR}/.venv/bin/honeypot-block" \
      --db "${DB_FILE}" \
      --records-file "${RECORDS_FILE}" \
      --apply
    ;;
  unblock)
    require_venv
    exec "${ROOT_DIR}/.venv/bin/honeypot-block" \
      --db "${DB_FILE}" \
      --records-file "${RECORDS_FILE}" \
      --unblock
    ;;
  list)
    require_venv
    exec "${ROOT_DIR}/.venv/bin/honeypot-block" --list
    ;;
  *)
    usage
    exit 1
    ;;
esac
