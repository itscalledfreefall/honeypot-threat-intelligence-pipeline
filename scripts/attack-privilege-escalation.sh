#!/usr/bin/env bash
# Privilege Escalation Attack
# sudo -l enumeration, SUID binary search, pkexec abuse, sudoers modification.
#
# Usage:  scripts/attack-privilege-escalation.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: privilege_escalation category, sudo/find commands

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Privilege Escalation Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Sessions:  5"
echo "  Category:  privilege_escalation"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario privilege-escalation \
  --sessions 5 
echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=privilege_escalation&limit=3 | python3 -m json.tool"
echo ""
