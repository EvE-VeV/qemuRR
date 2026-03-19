#!/bin/bash

# Configuration for Fuzzing (User Mode)
IMAGE_DIR="$(dirname $(realpath $0))"
ROOTFS="$IMAGE_DIR/_axe75v1-up-ver1-2-2-P1[20240827-rel68051]_nosign_2024-08-27_19.30.26.bin.extracted/squashfs-root"
TRACE_FILE="$IMAGE_DIR/axe75_test_v1.trace"
OUTPUT_DIR="${IMAGE_DIR}/../../../../fuzzing_output_axe75"
MOCK_LIB="$IMAGE_DIR/libubus_mock.so"
FUZZ_PY="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/fuzz_main.py"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Fuzzing for TP-Link AXE75..."
echo "    Trace: $TRACE_FILE"
echo "    Output: $OUTPUT_DIR"

# We must pass LD_PRELOAD via env to the fuzzer so it propagates to QEMU fork server
# The python script might need modification if it filters envs, but usually it passes os.environ.

export QEMU_LD_PREFIX="$ROOTFS"
export LD_PRELOAD="$MOCK_LIB"

# Note: In User Mode, we don't need sudo.
python3 "$FUZZ_PY" \
    --trace "$TRACE_FILE" \
    --target "$ROOTFS/usr/sbin/uhttpd" \
    --qemu "/home/webfuzz/Documents/qemu/build/qemu-arm" \
    --iterations 10000 \
    --infinite \
    --output "$OUTPUT_DIR"
