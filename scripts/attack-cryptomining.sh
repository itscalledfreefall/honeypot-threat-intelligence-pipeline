#!/usr/bin/env bash
# Cryptomining Attack
# XMRig deployment, mining pool connection, wallet configuration.
#
# Usage:  scripts/attack-cryptomining.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: cryptomining category, stratum+tcp in indicators

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Cryptomining Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Sessions:  5"
echo "  Category:  cryptomining"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario cryptomining \
  --sessions 5 
echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=cryptomining&limit=3 | python3 -m json.tool"
echo ""
