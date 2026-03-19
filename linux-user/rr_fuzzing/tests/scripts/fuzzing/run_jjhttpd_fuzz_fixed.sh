#!/bin/bash
# D-Link DIR-820L jjhttpd Fuzzing Campaign
set -e

SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PROJECT_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
VT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets"
ROOTFS="${VT}/DLink_DIR820L/rootfs"
RR_TRACE_FILE="${SIM_ROOT}/tests/images/DLink/DIR820L/traces/jjhttpd_init.txt"
OUTPUT_DIR="$SIM_ROOT/fuzz_output_jjhttpd"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting D-Link DIR-820L (JJ-HTTP) Fuzzing..."

# Run the fuzzer
PYTHONPATH="$PROJECT_ROOT" \
QEMU_LD_PREFIX="$ROOTFS" \
exec python3 "$PROJECT_ROOT/fuzzing/fuzz_main.py" \
    --trace "$RR_TRACE_FILE" \
    --target "$ROOTFS/sbin/jjhttpd" \
    --qemu "$SIM_ROOT/../../build/qemu-mips" \
    --ld-prefix "$ROOTFS" \
    --word-size 32 \
    --infinite \
    --persistence \
    --output "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/launch.log"
