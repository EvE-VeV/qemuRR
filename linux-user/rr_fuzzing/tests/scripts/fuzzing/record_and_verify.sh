#!/bin/bash
# record_and_verify.sh - A robust recording script for firmware traces

TARGET_NAME=$1
ROOTFS=$2
BINARY=$3
QEMU=$4
TRACE_PATH=$5
EXTRA_ENV=${6:-""}

echo "[*] Recording $TARGET_NAME..."
echo "    Rootfs: $ROOTFS"
echo "    Binary: $BINARY"
echo "    Trace:  $TRACE_PATH"

mkdir -p "$(dirname "$TRACE_PATH")"
rm -f "$TRACE_PATH"

# Run in background
export RR_ENABLED=1
export RR_MODE=RECORD
export RR_TRACE_FILE="$TRACE_PATH"
export QEMU_LD_PREFIX="$ROOTFS"

# Apply extra env
if [ -n "$EXTRA_ENV" ]; then
    export $EXTRA_ENV
fi

$QEMU -L "$ROOTFS" "$BINARY" -d > recording.log 2>&1 &
PID=$!

echo "[*] PID: $PID. Waiting for startup..."
sleep 10

# Check if alive
if kill -0 $PID 2>/dev/null; then
    echo "[*] Process is alive. Sending requests..."
    # Try common ports
    curl -s --connect-timeout 2 http://127.0.0.1:80/ -o /dev/null || true
    curl -s --connect-timeout 2 http://127.0.0.1:8080/ -o /dev/null || true
    sleep 2
    echo "[*] Terminating..."
    kill $PID
    sleep 2
    kill -9 $PID 2>/dev/null || true
else
    echo "[!] Process died early. Checking logs..."
    tail -n 20 recording.log
fi

if [ -f "$TRACE_PATH" ] && [ -s "$TRACE_PATH" ]; then
    echo "[+] Trace saved: $(ls -lh "$TRACE_PATH")"
    exit 0
else
    echo "[!] Trace missing or empty!"
    exit 1
fi
