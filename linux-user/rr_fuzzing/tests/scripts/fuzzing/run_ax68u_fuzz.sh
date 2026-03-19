#!/bin/bash
# Asus RT-AC68U Fuzzing Campaign
set -e

SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PROJECT_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Asus_RTAC68U/rootfs"
RR_TRACE_FILE="$SIM_ROOT/tests/seeds/Asus_RTAC68U.trace"
OUTPUT_DIR="$SIM_ROOT/fuzz_output_rtac68u"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Asus RT-AC68U (AS-68U) Fuzzing..."

# Run the fuzzer
PYTHONPATH="$PROJECT_ROOT" \
QEMU_LD_PREFIX="$ROOTFS" \
exec python3 "$PROJECT_ROOT/fuzzing/fuzz_main.py" \
    --trace "$RR_TRACE_FILE" \
    --target "$ROOTFS/usr/sbin/httpd" \
    --qemu "$SIM_ROOT/../../build/qemu-arm" \
    --ld-prefix "$ROOTFS" \
    --infinite \
    --persistence \
    --output "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/launch.log"
