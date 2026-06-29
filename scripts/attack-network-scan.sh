#!/usr/bin/env bash
# Network Scan Attack
# nmap, masscan, nc -zv — scanning internal networks for open ports.
#
# Usage:  scripts/attack-network-scan.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: network_scan category, nmap/masscan in commands

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Network Scan Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Category:  network_scan"
echo "==================================================================="
echo ""

sshpass -p "password" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 \
  -p 2222 \
  admin@$IP \
  "nmap -sS -p 22,80,443 192.168.1.0/24 ; nc -zv 192.168.1.1 22 ; masscan -p22,80,443 192.168.1.0/24 --rate=100" 2>&1 || true

echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=network_scan&limit=3 | python3 -m json.tool"
echo ""
