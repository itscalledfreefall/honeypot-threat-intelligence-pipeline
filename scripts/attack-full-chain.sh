#!/usr/bin/env bash
# Full Attack Chain — All Categories in One Session
# Runs the complete attack lifecycle: recon → credentials → privesc → download
# → cryptomining → persistence → obfuscation → evasion → destructive.
# Hits every major classification category in a single demonstration.
#
# Usage:  scripts/attack-full-chain.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: all attack categories filled, critical risk session

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  FULL ATTACK CHAIN — ALL CATEGORIES"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Scenarios: recon → creds → privesc → download → mining → persist"
echo "             → obfuscation → evasion → destructive"
echo "  Risk:      CRITICAL (all categories + combos)"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario full-chain \
  --sessions 3 \
  --allow-impactful-live
echo ""
echo "  ✓ Full chain complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/summary | python3 -m json.tool"
echo ""
