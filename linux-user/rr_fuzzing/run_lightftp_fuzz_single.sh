#!/bin/bash
set -e

# Configuration
RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PROFUZZ_DIR="${RR_ROOT}/data/ProFuzzBench/subjects/FTP/LightFTP"

TARGET="${PROFUZZ_DIR}/fftp_fuzz"
CONFIG="${PROFUZZ_DIR}/fftp.conf"
TRACE="${PROFUZZ_DIR}/lightftp_seed.trace"
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-x86_64"
OUTPUT_DIR="${RR_ROOT}/fuzz_output_lightftp"

# Ensure we are in the RR root to allow python imports to work
cd "$RR_ROOT"

echo "[*] Starting LightFTP Single-Process Fuzzing..."
echo "    Target: $TARGET"
echo "    Config: $CONFIG"
echo "    Trace:  $TRACE"
echo "    Output: $OUTPUT_DIR"

# Clean previous output
rm -rf "$OUTPUT_DIR"

# Run single-process fuzzer
# Note: arguments must include the config file and port.
# We pass them as a single string to --args.
python3 fuzzing/fuzz_main.py \
    --qemu "$QEMU_BIN" \
    --trace "$TRACE" \
    --target "$TARGET" \
    --args "$CONFIG 2200" \
    --output "$OUTPUT_DIR" \
    --infinite \
    --persistence
