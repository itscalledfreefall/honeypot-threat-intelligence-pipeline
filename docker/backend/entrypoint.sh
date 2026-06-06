#!/usr/bin/env bash
set -euo pipefail

# ── Load environment ──────────────────────────────────────────────
# env vars are injected by docker compose via env_file: — no manual sourcing needed
# but keep this block for backward compat with direct docker run
if [[ -f /app/.env ]]; then
  set -a
  source /app/.env
  set +a
fi

# ── Default paths ─────────────────────────────────────────────────
COWRIE_LOG="${COWRIE_LOG:-/logs/cowrie.json}"
DB_PATH="${DB_PATH:-/data/honeypot.db}"
RECORDS_FILE="${RECORDS_FILE:-/exports/cowrie.records.jsonl}"
SUMMARY_FILE="${SUMMARY_FILE:-/reports/cowrie.summary.json}"
API_HOST="${API_HOST:-0.0.0.0}"
API_PORT="${API_PORT:-5000}"

# ── Ensure data dirs exist ────────────────────────────────────────
mkdir -p /data /logs /exports /reports

# ── Wait for Cowrie log file ──────────────────────────────────────
echo "[entrypoint] Waiting for Cowrie log at ${COWRIE_LOG}..."
for i in $(seq 1 30); do
  if [[ -f "${COWRIE_LOG}" ]]; then
    echo "[entrypoint] Cowrie log found."
    break
  fi
  sleep 2
done
touch "${COWRIE_LOG}" 2>/dev/null || true

# ── Build enrichment flags ────────────────────────────────────────
ENRICH_FLAGS=""
if [[ -n "${ABUSEIPDB_API_KEY:-}" && "${ABUSEIPDB_API_KEY}" != "replace-with-your-api-key" ]]; then
  ENRICH_FLAGS="${ENRICH_FLAGS} --enrich-abuseipdb"
fi
if [[ -n "${VIRUSTOTAL_API_KEY:-}" && "${VIRUSTOTAL_API_KEY}" != "replace-with-your-api-key" ]]; then
  ENRICH_FLAGS="${ENRICH_FLAGS} --enrich-virustotal"
fi

# ── Start pipeline in background ──────────────────────────────────
echo "[entrypoint] Starting pipeline in follow mode..."
python -m honeypot_pipeline.cli \
  "${COWRIE_LOG}" \
  --follow \
  --poll-interval 2 \
  ${ENRICH_FLAGS} \
  --output-file "${RECORDS_FILE}" \
  --summary-file "${SUMMARY_FILE}" \
  --db "${DB_PATH}" \
  > /tmp/pipeline-stdout.log 2>&1 &
PIPELINE_PID=$!
echo "[entrypoint] Pipeline PID: ${PIPELINE_PID}"

# ── Pipeline watchdog (background) ────────────────────────────────
# If the pipeline process dies, kill the container so docker compose
# restarts it. Pipe failures should not go unnoticed.
(
  while kill -0 "${PIPELINE_PID}" 2>/dev/null; do
    sleep 10
  done
  echo "[entrypoint] FATAL: pipeline (PID ${PIPELINE_PID}) died — shutting down container"
  kill 1  # signal the main process (Flask) to exit
) &
WATCHDOG_PID=$!

# ── Cleanup on exit ───────────────────────────────────────────────
cleanup() {
  echo "[entrypoint] Shutting down..."
  kill "${PIPELINE_PID}" 2>/dev/null || true
  kill "${WATCHDOG_PID}" 2>/dev/null || true
  wait "${PIPELINE_PID}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── Start Flask API in foreground ─────────────────────────────────
echo "[entrypoint] Starting Flask API on ${API_HOST}:${API_PORT}..."
exec honeypot-dashboard \
  --records-file "${RECORDS_FILE}" \
  --summary-file "${SUMMARY_FILE}" \
  --db "${DB_PATH}" \
  --host "${API_HOST}" \
  --port "${API_PORT}"
