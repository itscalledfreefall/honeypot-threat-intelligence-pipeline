#!/usr/bin/env bash
# Defense Evasion Attack
# Log clearing, history wiping, firewall disable, SELinux bypass.
#
# Usage:  scripts/attack-defense-evasion.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: defense_evasion category, rm -rf /var/log/history -c

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Defense Evasion Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Sessions:  5"
echo "  Category:  defense_evasion"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario defense-evasion \
  --sessions 5 
echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=defense_evasion&limit=3 | python3 -m json.tool"
echo ""
