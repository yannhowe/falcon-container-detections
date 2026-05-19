#!/bin/bash
# 13 - Ransomware Simulation (LockBit)
# Trigger: LinProcRansomware IOA
# Tactic: Impact / Data Encrypted for Impact
set -e
echo "=== [13] Ransomware Simulation (LockBit) ==="

# Create test files to "encrypt"
mkdir -p /tmp/ransom_test
for i in $(seq 1 5); do
    echo "Important document $i - confidential data" > "/tmp/ransom_test/document_${i}.txt"
done

# Simulate ransomware: rename files with .lockbit extension
for f in /tmp/ransom_test/*.txt; do
    mv "$f" "${f}.lockbit" 2>/dev/null || true
done

# Create ransom note (typical ransomware behavior)
cat > /tmp/ransom_test/README.txt << 'EOF'
All your files have been encrypted by LockBit.
This is a SIMULATION for detection testing purposes only.
EOF

# Cleanup
rm -rf /tmp/ransom_test 2>/dev/null || true

echo "[13] Done — LinProcRansomware IOA should trigger"
