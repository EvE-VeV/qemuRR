#!/bin/bash
set -e

# Configuration
RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
IMG_ROOT="${RR_ROOT}/tests/images/RAX30"
SIM_ROOT="${IMG_ROOT}/sim_root"

TARGET="${SIM_ROOT}/bin/upnp"
TRACE="${IMG_ROOT}/traces/upnp_full.txt"
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-arm"
MOCK_LIB="${IMG_ROOT}/libcms_mock.so"
OUTPUT_DIR="${RR_ROOT}/fuzz_output_upnp"

# Important for ARM emulation and mock injection
export QEMU_LD_PREFIX="${SIM_ROOT}"
export QEMU_LD_PRELOAD="${MOCK_LIB}"

cd "$RR_ROOT"

echo "[*] Starting UPNP (RAX30) Fuzzing..."
echo "    Target: $TARGET"
echo "    Trace:  $TRACE"
echo "    Mock:   $MOCK_LIB"
echo "    Output: $OUTPUT_DIR"

# Fuzz upnp -L ens33 -m 1234
python3 fuzzing/fuzz_main.py \
    --qemu "$QEMU_BIN" \
    --trace "$TRACE" \
    --target "$TARGET" \
    --args "-L ens33 -m 1234" \
    --output "$OUTPUT_DIR" \
    --word-size 32 \
    --infinite \
    --persistence
