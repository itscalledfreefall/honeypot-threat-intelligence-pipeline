#!/usr/bin/env bash
# Brute Force Attack
# Credential spraying — multiple login attempts with common username/password pairs.
#
# Usage:  scripts/attack-brute-force.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: brute_force category, multiple login.failed events

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Brute Force Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Sessions:  50"
echo "  Category:  brute_force"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario brute-force \
  --sessions 50 --brute-only
echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=brute_force&limit=3 | python3 -m json.tool"
echo ""
