#!/usr/bin/env bash
# Destructive Action Attack
# rm -rf, dd if=/dev/zero, mkfs, fork bomb — wiper-like destructive commands.
#
# Usage:  scripts/attack-destructive-action.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: destructive_action category, critical risk level

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Destructive Action Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Sessions:  2"
echo "  Category:  destructive_action"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario destructive-action \
  --sessions 2 --allow-impactful-live
echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=destructive_action&limit=3 | python3 -m json.tool"
echo ""
