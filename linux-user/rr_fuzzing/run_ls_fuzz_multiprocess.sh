#!/bin/bash
# run_ls_fuzz_multiprocess.sh

TRACE_FILE="linux-user/rr_fuzzing/trace_ls.txt"
export RR_DEBUG_LEVEL=4
SYNC_DIR="linux-user/rr_fuzzing/fuzzing_sync_ls"

echo "=== [1/3] Cleanup ==="
echo "Removing old trace and sync directory..."
rm -vf "$TRACE_FILE"
rm -vrf "$SYNC_DIR"

echo "=== [2/3] Record Trace ==="
echo "Recording /bin/ls execution..."
RR_MODE=record RR_TRACE_FILE="$TRACE_FILE" RR_DEBUG_LEVEL=4 ./build/qemu-x86_64 /bin/ls -la > /dev/null

if [ -f "$TRACE_FILE" ]; then
    echo "✅ Trace recorded: $(ls -lh $TRACE_FILE | awk '{print $5}')"
    echo "DEBUG: Checking trace content immediately after recording:"
    od -t u4 -v -w16 ${TRACE_FILE}.bbl | head -n 20
    od -t u4 -v -w16 ${TRACE_FILE}.bbl | awk '$4 != 0 {print "FOUND NON-ZERO SYSCALL: " $0; exit}'
else
    echo "❌ Trace recording failed!"
    exit 1
fi

# Optimization: Focus on one fork point at a time with many mutations to direct persistent reuse
export RR_BATCH_SIZE=1
export RR_MUTATIONS_PER_FORK=10

echo "=== [3/3] Start Multi-Worker Fuzzing ==="
echo "Starting fuzzer (4 workers, 60s timeout)..."
# Using absolute path for trace to avoid ambiguity in child processes
ABS_TRACE=$(realpath "$TRACE_FILE")

python3 linux-user/rr_fuzzing/fuzzing/fuzz_multiprocess.py \
    --qemu ./build/qemu-x86_64 \
    --target /bin/ls \
    --trace "$ABS_TRACE" \
    --sync-dir "$SYNC_DIR" \
    --workers 4 \
    --smart \
    --timeout 300
