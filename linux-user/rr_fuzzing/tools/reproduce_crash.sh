#!/bin/bash
# Crash Reproduction Script
# 
# Usage: ./reproduce_crash.sh <crash_directory>
# Example: ./reproduce_crash.sh /tmp/fuzzing_output_vulnerable_success/crashes

set -e

CRASH_DIR="$1"
if [ -z "$CRASH_DIR" ]; then
    echo "Usage: $0 <crash_directory>"
    echo "Example: $0 /tmp/fuzzing_output_vulnerable_success/crashes"
    exit 1
fi

# Find crash files
CRASH_META=$(find "$CRASH_DIR" -name "*.meta" | head -n 1)
if [ -z "$CRASH_META" ]; then
    echo "Error: Crash metadata file not found"
    exit 1
fi

CRASH_ID=$(basename "$CRASH_META" .meta)
CRASH_TRACE="$CRASH_DIR/${CRASH_ID}.bin"

echo "========================================"
echo "Crash Reproduction Script"
echo "========================================"
echo "Crash ID: $CRASH_ID"
echo "Metadata: $CRASH_META"
echo "Trace File: $CRASH_TRACE"
echo ""

# Display crash info
echo "Crash Metadata:"
cat "$CRASH_META" | jq -r '
  "  Status: \(.status_name) (code: \(.status))",
  "  Trace ID: \(.trace_id)",
  "  Timestamp: \(.timestamp)",
  "  Mutation Count: \(.mutations | length)"
'

# Display critical mutations
echo ""
echo "Critical Mutations:"
cat "$CRASH_META" | jq -r '.mutations[] | select(.cmd == 2) | 
  "  syscall_\(.syscall_index): REPLACE_BUFFER, size=\(.size) bytes"
'

echo ""
echo "Starting crash reproduction..."
echo ""

# Set environment variables and run
export RR_MODE=fuzzing
export RR_TRACE_FILE="$CRASH_TRACE"
export RR_FUZZING_ENABLED=1
export RR_DEBUG_LEVEL=0

QEMU="/home/webfuzz/Documents/qemu/build/qemu-x86_64"
TARGET="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/programs/vulnerable/fuzz_target_vulnerable"

if [ ! -f "$QEMU" ]; then
    echo "Error: QEMU not found at: $QEMU"
    exit 1
fi

if [ ! -f "$TARGET" ]; then
    echo "Error: Target binary not found at: $TARGET"
    exit 1
fi

# Run and capture results
set +e
timeout 2 "$QEMU" "$TARGET" 2>&1 | tee /tmp/crash_reproduction_output.log
EXIT_CODE=$?
set -e

echo ""
echo "========================================"
if [ $EXIT_CODE -eq 134 ]; then
    echo "Crash successfully reproduced!"
    echo "   Exit code: $EXIT_CODE (SIGABRT)"
    grep -q "stack smashing detected" /tmp/crash_reproduction_output.log && \
        echo "   Type: Stack Buffer Overflow"
    exit 0
elif [ $EXIT_CODE -eq 139 ]; then
    echo "Crash successfully reproduced!"
    echo "   Exit code: $EXIT_CODE (SIGSEGV)"
    exit 0
elif [ $EXIT_CODE -eq 124 ] || [ $EXIT_CODE -eq 143 ]; then
    echo "Warning: Process timed out (possible hang or infinite loop)"
    exit 2
else
    echo "Warning: Process exited with code: $EXIT_CODE"
    echo "   (Expected: 134=SIGABRT or 139=SIGSEGV)"
    exit 2
fi
