#!/bin/bash
# run_ls_fuzz_test.sh

TRACE_FILE="linux-user/rr_fuzzing/trace_ls.txt"
export RR_DEBUG_LEVEL=1

echo "=== [1/3] Cleanup ==="
echo "Removing old trace and output..."
rm -vf "$TRACE_FILE"
rm -vrf linux-user/rr_fuzzing/fuzzing_output_ls_report

echo "=== [2/3] Record Trace ==="
echo "Recording /bin/ls execution..."
RR_MODE=record RR_TRACE_FILE="$TRACE_FILE" RR_DEBUG_LEVEL=4 ./build/qemu-x86_64 /bin/ls -la > record.log 2>&1

if [ -f "$TRACE_FILE" ]; then
    echo "✅ Trace recorded: $(ls -lh $TRACE_FILE | awk '{print $5}')"
    echo "DEBUG: Checking trace content immediately after recording:"
    od -t u4 -v -w16 ${TRACE_FILE}.bbl | head -n 20
    od -t u4 -v -w16 ${TRACE_FILE}.bbl | awk '$4 != 0 {print "FOUND NON-ZERO SYSCALL: " $0; exit}'
else
    echo "❌ Trace recording failed!"
    exit 1
fi

echo "=== [3/3] Start Fuzzing ==="
echo "Starting fuzzer (500 iterations)..."

# Optimization: Focus on one fork point at a time with many mutations to direct persistent reuse
export RR_BATCH_SIZE=1
export RR_MUTATIONS_PER_FORK=10
export RR_DEBUG_LEVEL=4

python3 linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
    --qemu ./build/qemu-x86_64 \
    --target /bin/ls \
    --trace "$TRACE_FILE" \
    --output linux-user/rr_fuzzing/fuzzing_output_ls_report \
    --iterations 500
