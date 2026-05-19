#!/bin/bash
# 11 - Credential Collection
# Trigger: GenCollectionLin IOA
# Tactic: Collection / Automated Collection
set -e
echo "=== [11] Credential Collection ==="

# The exact pattern from the detection-container repo (wraps in sh -c)
sh -c "/bin/grep 'x:0:' /etc/passwd > /tmp/passwords"

# Additional collection patterns
cat /etc/shadow > /tmp/shadow_copy 2>/dev/null || true
find / -name "*.pem" -o -name "*.key" -o -name "id_rsa" 2>/dev/null | head -5 > /tmp/keys_found || true
cat /proc/self/environ > /tmp/env_dump 2>/dev/null || true

# Cleanup
rm -f /tmp/passwords /tmp/shadow_copy /tmp/keys_found /tmp/env_dump 2>/dev/null || true

echo "[11] Done — GenCollectionLin IOA should trigger"
