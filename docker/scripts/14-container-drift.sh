#!/bin/bash
# 14 - Container Drift (new binary execution)
# Trigger: ContainerDrift IOA
# Tactic: Execution / Container Drift
set -e
echo "=== [14] Container Drift ==="

# Copy a binary and execute it — this is "drift" (new executable not in original image)
cp /bin/id /bin/id2 2>/dev/null || cp /usr/bin/id /bin/id2 2>/dev/null || true
chmod +x /bin/id2 2>/dev/null || true
/bin/id2 2>/dev/null || true

# Additional drift: write and execute a new script
cat > /tmp/drifted_binary.sh << 'EOF'
#!/bin/bash
echo "This is a drifted binary"
whoami
EOF
chmod +x /tmp/drifted_binary.sh
/tmp/drifted_binary.sh 2>/dev/null || true

# Cleanup
rm -f /bin/id2 /tmp/drifted_binary.sh 2>/dev/null || true

echo "[14] Done — ContainerDrift IOA should trigger"
