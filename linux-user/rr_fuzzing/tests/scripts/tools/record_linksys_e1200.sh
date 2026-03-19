#!/bin/bash
set -e

# Configuration
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-mipsel"
ROOTFS="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Linksys_E1200/rootfs"
BINARY="$ROOTFS/usr/sbin/httpd"
TRACE_OUTPUT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/seeds/Linksys_E1200/linksys_e1200_seed.bin"
LOG_file="tests/fuzz_output_linksys/record_linksys_e1200.log"

echo "[*] Clean old traces"
rm -f "$TRACE_OUTPUT" "${TRACE_OUTPUT}.bbl"
mkdir -p tests/fuzz_output_linksys

echo "[*] Starting QEMU recording..."
export QEMU_LD_PREFIX="$ROOTFS"
export RR_ENABLED=1
export RR_MODE="record"
export RR_DEBUG_LEVEL=3
export RR_TRACE_FILE="$TRACE_OUTPUT"

# Start QEMU in background
"$QEMU_BIN" -L "$ROOTFS" "$BINARY" -p 8081 > "$LOG_file" 2>&1 &
QEMU_PID=$!

echo "[*] Waiting for httpd to start..."
sleep 3

echo "[*] Sending seed request..."
curl -s -d "test=123" http://127.0.0.1:8081/apply.cgi || true

echo "[*] Stopping QEMU..."
kill -SIGTERM $QEMU_PID || true
sleep 1
kill -SIGKILL $QEMU_PID 2>/dev/null || true
wait $QEMU_PID 2>/dev/null || true

echo "[*] Recording finished. Checking trace file..."
ls -lh "$TRACE_OUTPUT" || true
