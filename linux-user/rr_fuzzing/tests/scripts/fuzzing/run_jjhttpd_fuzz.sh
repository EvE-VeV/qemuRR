#!/bin/bash
set -e

# Configuration
RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
IMG_ROOT="${RR_ROOT}/tests/images/DLink/DIR820L"
SIM_ROOT="${RR_ROOT}/tests/images/DLink/DIR820L_sim_root"

TARGET="${SIM_ROOT}/sbin/jjhttpd"
TRACE="${IMG_ROOT}/traces/jjhttpd_full.txt"
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-mips"
OUTPUT_DIR="${RR_ROOT}/fuzz_output_jjhttpd"

# Important for MIPS emulation
export QEMU_LD_PREFIX="${SIM_ROOT}"

cd "$RR_ROOT"

echo "[*] Starting jjhttpd (DIR-820L) Fuzzing..."
echo "    Target: $TARGET"
echo "    Trace:  $TRACE"
echo "    Output: $OUTPUT_DIR"

# Fuzz jjhttpd (no args, listens on port 8080 by dummy config)
python3 $RR_ROOT/fuzzing/fuzz_main.py \
    --qemu "$QEMU_BIN" \
    --trace "$TRACE" \
    --target "$TARGET" \
    --output "$OUTPUT_DIR" \
    --word-size 32 \
    --infinite \
    --persistence
