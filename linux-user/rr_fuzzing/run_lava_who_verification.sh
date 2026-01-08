#!/bin/bash
# run_lava_who_verification.sh

TARGET_BIN="linux-user/rr_fuzzing/data/lava_corpus/LAVA-M/who/coreutils-8.24-lava-safe/src/who"
TRACE_FILE="linux-user/rr_fuzzing/trace_who_authentic.txt"
SYNC_DIR="linux-user/rr_fuzzing/sync_lava_who"
QEMU_BIN="./build/qemu-x86_64"

export RR_DEBUG_LEVEL=1

echo "=== [1/3] Cleanup ==="
rm -vf "$TRACE_FILE"
rm -vrf "$SYNC_DIR"
mkdir -p linux-user/rr_fuzzing/seeds

echo "=== [2/3] Record Authentic LAVA Trace ==="
# Note: who needs a valid utmp-like structure if fuzzed heavily, but standard run works
RR_MODE=record RR_TRACE_FILE="$TRACE_FILE" RR_DEBUG_LEVEL=1 "$QEMU_BIN" "$TARGET_BIN" -a > /dev/null 2>&1

if [ -f "$TRACE_FILE" ]; then
    echo "✅ Authentic LAVA trace recorded: $(ls -lh $TRACE_FILE | awk '{print $5}')"
else
    echo "❌ Trace recording failed!"
    exit 1
fi

echo "=== [3/3] Start Sustained Multi-Worker Fuzzing (5 min) ==="
# Optimization for LAVA: Smaller batches to increase diversity, but keep persistence
export RR_BATCH_SIZE=1 
export RR_MUTATIONS_PER_FORK=10

ABS_TRACE=$(realpath "$TRACE_FILE")

python3 linux-user/rr_fuzzing/fuzzing/fuzz_multiprocess.py \
    --qemu "$QEMU_BIN" \
    --target "$TARGET_BIN" \
    --trace "$ABS_TRACE" \

    --sync-dir "$SYNC_DIR" \
    --workers 4 \
    --smart \
    --timeout 300
