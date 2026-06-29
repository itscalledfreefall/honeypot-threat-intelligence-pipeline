#!/usr/bin/env bash
# Reconnaissance Attack
# Host enumeration — whoami, uname, ifconfig, netstat, process listing, user discovery.
#
# Usage:  scripts/attack-recon.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: reconnaissance category, host enum commands in events table

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Reconnaissance Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Sessions:  5"
echo "  Category:  reconnaissance"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario recon \
  --sessions 5 
echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=reconnaissance&limit=3 | python3 -m json.tool"
echo ""
