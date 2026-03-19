#!/bin/bash
set -e

# Configuration
RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
SIM_ROOT="${RR_ROOT}/tests/images/Totolink/extracted_firmware/sim_root"

TARGET="${SIM_ROOT}/bin/boa"
TRACE="${RR_ROOT}/tests/seeds/TOTOLINK/boa_totolink_v2.trace"
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-mips"
OUTPUT_DIR="${RR_ROOT}/fuzz_output_boa"

# Important for MIPS emulation
export QEMU_LD_PREFIX="${SIM_ROOT}"

cd "$RR_ROOT"

echo "[*] Starting BOA (TOTOLINK) Fuzzing..."
echo "    Target: $TARGET"
echo "    Trace:  $TRACE"
echo "    Output: $OUTPUT_DIR"

# Clean previous output
# rm -rf "$OUTPUT_DIR"

# Fuzz boa -c . -d
python3 $RR_ROOT/fuzzing/fuzz_main.py \
    --qemu "$QEMU_BIN" \
    --trace "$TRACE" \
    --target "$TARGET" \
    --args "-c . -d" \
    --output "$OUTPUT_DIR" \
    --word-size 32 \
    --infinite \
    --persistence
