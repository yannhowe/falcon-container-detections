#!/bin/bash
# run-all.sh — Orchestrator: runs all detection scripts sequentially with gaps
# Usage: docker run --rm --privileged falcon-detections /opt/scripts/run-all.sh
set -o pipefail

SCRIPTS_DIR="$(dirname "$0")"
DELAY=${DELAY:-30}  # seconds between scripts (override with env var)

echo "============================================"
echo " Falcon Container Detection Suite"
echo " Running all scenarios with ${DELAY}s gaps"
echo " Started: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================"
echo ""

TOTAL=0
PASSED=0
FAILED=0

for script in "$SCRIPTS_DIR"/[0-9][0-9]-*.sh; do
    [ -f "$script" ] || continue
    TOTAL=$((TOTAL + 1))
    SCRIPT_NAME=$(basename "$script")

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "▶ Running: $SCRIPT_NAME"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if bash "$script"; then
        PASSED=$((PASSED + 1))
    else
        FAILED=$((FAILED + 1))
        echo "  ⚠ Script exited with error (continuing)"
    fi

    echo ""

    # Delay between scripts (skip after last one)
    if [ "$script" != "$(ls "$SCRIPTS_DIR"/[0-9][0-9]-*.sh | tail -1)" ]; then
        echo "  Waiting ${DELAY}s before next scenario..."
        sleep "$DELAY"
    fi
done

echo ""
echo "============================================"
echo " Complete: $PASSED/$TOTAL passed, $FAILED failed"
echo " Finished: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================"
echo ""
echo "Run 'python verify/check.py' to validate detections in Falcon console."
