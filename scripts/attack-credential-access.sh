#!/usr/bin/env bash
# Credential Access Attack
# Reading /etc/shadow, SSH private keys, AWS credentials, database configs.
#
# Usage:  scripts/attack-credential-access.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: credential_access category, id_rsa/shadow in commands

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Credential Access Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Sessions:  5"
echo "  Category:  credential_access"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/attack-simulator.py" \
  --host "$IP" --port 2222 \
  --scenario credential-access \
  --sessions 5 
echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=credential_access&limit=3 | python3 -m json.tool"
echo ""
