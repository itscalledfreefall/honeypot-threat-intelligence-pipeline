#!/usr/bin/env bash
# DDoS Attack — Botnet Flood
# Simulates a distributed denial-of-service attack with multiple bot IPs
# flooding the honeypot with rapid SSH connections + DDoS tools.
#
# Usage:  scripts/attack-ddos.sh [VM-IP] [bots] [connections]
# Default: 20 bots, 10 connections each (200 total connections)
#
# Dashboard: http://<VM-IP>:5173
# What to look for: ddos + brute_force categories, massive event spike, 20+ new source IPs

set -euo pipefail
IP="${1:-192.168.1.79}"
BOTS="${2:-20}"
CONN="${3:-10}"
echo ""
echo "==================================================================="
echo "  DDoS ATTACK — BOTNET FLOOD"
echo "==================================================================="
echo "  Target:       $IP:2222"
echo "  Bots:         $BOTS"
echo "  Connections:  $CONN/bot ($(( BOTS * CONN )) total)"
echo "  Categories:   ddos + brute_force"
echo "==================================================================="
echo ""
python3 "$(dirname "$0")/ddos-attack.py" \
  --host "$IP" --port 2222 \
  --bots "$BOTS" --connections "$CONN"
echo ""
echo "  ✓ Flood complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/summary | python3 -m json.tool"
echo ""
