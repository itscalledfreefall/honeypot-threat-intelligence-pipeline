#!/usr/bin/env bash
# Obfuscation Attack
# Base64-encoded payloads, eval execution, piped bash decoding.
#
# Usage:  scripts/attack-obfuscation.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: obfuscation category, base64/eval in commands

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Obfuscation Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Sessions:  5"
echo "  Category:  obfuscation"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario obfuscation \
  --sessions 5 
echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=obfuscation&limit=3 | python3 -m json.tool"
echo ""
