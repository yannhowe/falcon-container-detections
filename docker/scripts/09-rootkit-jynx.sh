#!/bin/bash
# 09 - Rootkit Installation (Jynx-style)
# Trigger: JynxRootkitInstall IOA
# Tactic: Defense Evasion / Rootkit
set -e
echo "=== [09] Rootkit Installation (Jynx) ==="

# Simulate Jynx rootkit installation by manipulating ld.so.preload
# This is the exact pattern that triggers JynxRootkitInstall

# Create a fake shared library (harmless)
cat > /tmp/jynx.c << 'EOF'
// Fake preload library - does nothing
int placeholder(void) { return 0; }
EOF

gcc -shared -fPIC -o /tmp/libjynx.so /tmp/jynx.c 2>/dev/null || \
  touch /tmp/libjynx.so

# The key trigger: write to /etc/ld.so.preload and chgrp
touch /etc/ld.so.preload 2>/dev/null || true
echo "/tmp/libjynx.so" > /etc/ld.so.preload 2>/dev/null || true
chgrp 0 /etc/ld.so.preload 2>/dev/null || true

# Cleanup immediately
echo "" > /etc/ld.so.preload 2>/dev/null || true
rm -f /tmp/jynx.c /tmp/libjynx.so 2>/dev/null || true

echo "[09] Done — JynxRootkitInstall IOA should trigger"
