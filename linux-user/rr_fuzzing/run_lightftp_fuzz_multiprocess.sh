#!/bin/bash
set -e

# Configuration
RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PROFUZZ_DIR="${RR_ROOT}/data/ProFuzzBench/subjects/FTP/LightFTP"

TARGET="${PROFUZZ_DIR}/fftp_fuzz"
CONFIG="${PROFUZZ_DIR}/fftp.conf"
TRACE="${PROFUZZ_DIR}/lightftp_seed.trace"
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-x86_64"

# Ensure we are in the RR root to allow python imports to work
cd "$RR_ROOT"

echo "[*] Starting LightFTP Multi-Process Fuzzing..."
echo "    Target: $TARGET"
echo "    Config: $CONFIG"
echo "    Trace:  $TRACE"

# Note: arguments must include the config file and port.
# We pass them as a single string to --args.
python3 fuzzing/fuzz_multiprocess.py \
    --qemu "$QEMU_BIN" \
    --trace "$TRACE" \
    --target "$TARGET" \
    --args "$CONFIG 2200" \
    --workers 4 \
    --smart \
    --timeout 3600 \
    --display-interval 2
