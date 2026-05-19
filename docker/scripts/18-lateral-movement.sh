#!/bin/bash
# 18 - Lateral Movement (port scanning)
# Trigger: May not trigger reliably
# Tactic: Discovery / Network Service Discovery
set -e
echo "=== [18] Lateral Movement (best-effort) ==="

# Network scanning — may trigger network-based IOAs
if command -v nmap &>/dev/null; then
    nmap -sT -p 22,80,443,8080,3306,5432 172.17.0.0/24 --max-retries 1 --host-timeout 5s 2>/dev/null || true
else
    # Fallback: bash TCP scan
    for port in 22 80 443 8080; do
        (echo >/dev/tcp/172.17.0.1/$port) 2>/dev/null && echo "  Port $port open on 172.17.0.1" || true
    done
fi

# SSH brute force attempt (will fail, triggers attempt pattern)
for i in $(seq 1 3); do
    ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no -o BatchMode=yes \
      root@172.17.0.1 'id' 2>/dev/null || true
done

echo "[18] Done — Lateral movement (best-effort, may not trigger detection)"
