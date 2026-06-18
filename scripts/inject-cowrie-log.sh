#!/usr/bin/env bash
# Inject a Cowrie JSONL file into the running honeypot's live log volume so the
# pipeline follower ingests it. Use this to replay offline-generated attacks
# (e.g. scripts/attack-simulator.py --offline-output <file> ...) into the live
# dashboard without making a real SSH connection.
#
# Usage: scripts/inject-cowrie-log.sh <cowrie-jsonl-file>
set -euo pipefail

FILE="${1:?usage: scripts/inject-cowrie-log.sh <cowrie-jsonl-file>}"
[[ -f "${FILE}" ]] || { echo "No such file: ${FILE}" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "${ROOT_DIR}")}"
VOLUME="${PROJECT}_cowrie-logs"

docker volume inspect "${VOLUME}" >/dev/null 2>&1 || {
  echo "Volume '${VOLUME}' not found. Is the stack up (docker compose up -d)?" >&2
  exit 1
}

# The cowrie image ships no shell and the backend mounts this volume read-only,
# so append through a throwaway container that mounts it read-write. The live
# pipeline follower (now rotation/truncation-aware) picks up the appended lines.
docker run --rm -i -v "${VOLUME}:/logs" busybox \
  sh -c 'cat >> /logs/cowrie.json' < "${FILE}"

echo "Injected $(wc -l < "${FILE}") line(s) into ${VOLUME}:/logs/cowrie.json"
