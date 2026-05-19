#!/bin/bash
# 10 - Suspicious CLI Execution
# Trigger: GenExecutionLin IOA
# Tactic: Execution / Command and Scripting Interpreter
set -e
echo "=== [10] Suspicious CLI Execution ==="

# Pattern that triggers GenExecutionLin — encoded command execution
sh -c 'whoami [S];pwd;echo [E]' 2>/dev/null || true

# Additional suspicious CLI patterns
sh -c 'cat /etc/passwd | base64' 2>/dev/null || true
sh -c 'echo cm0gLXJmIC8K | base64 -d' 2>/dev/null || true
bash -c 'eval $(echo "aWQ=" | base64 -d)' 2>/dev/null || true

echo "[10] Done — GenExecutionLin IOA should trigger"
