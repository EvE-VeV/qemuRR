#!/bin/bash

# Configuration
RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
SIM_ROOT="${RR_ROOT}/tests/images/RAX30/sim_root"
TARGET_BIN="${SIM_ROOT}/webs/cgi-bin/rex_cgi.real"
TRACE_FILE="${RR_ROOT}/traces/rax30_cgi.trace"
OUTPUT_DIR="${RR_ROOT}/out_rax30"
QEMU_PATH="/home/webfuzz/Documents/qemu/build/qemu-arm"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# CGI Environment Variables (Exported for QEMU inheritance)
export LD_LIBRARY_PATH="$SIM_ROOT/lib:$SIM_ROOT/usr/lib:."
export REQUEST_METHOD="POST"
export CONTENT_TYPE="application/json"
export SCRIPT_NAME="/cgi-bin/rex_cgi"
export REQUEST_URI="/cgi-bin/rex_cgi"
export SERVER_NAME="127.0.0.1"
export SERVER_PORT="8080"
export HTTP_HOST="127.0.0.1:8080"
export GATEWAY_INTERFACE="CGI/1.1"
export REMOTE_ADDR="127.0.0.1"

cd "$RR_ROOT"

echo "[*] Starting RAX30 rex_cgi Fuzzing..."
echo "[*] Trace: $TRACE_FILE"
echo "[*] Output: $OUTPUT_DIR"

# Launch Fuzzer using the standard main entry point
python3 fuzzing/fuzz_main.py \
    --qemu "$QEMU_PATH" \
    --trace "$TRACE_FILE" \
    --target "$TARGET_BIN" \
    --output "$OUTPUT_DIR" \
    --word-size 32 \
    --persistence \
    --infinite
