#!/bin/bash

# Configuration for User Mode (Non-Root) Execution
IMAGE_DIR="$(dirname $(realpath $0))"
ROOTFS="$IMAGE_DIR/_axe75v1-up-ver1-2-2-P1[20240827-rel68051]_nosign_2024-08-27_19.30.26.bin.extracted/squashfs-root"
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-arm"
MOCK_LIB="$IMAGE_DIR/libubus_mock.so"
LOG_FILE="$IMAGE_DIR/axe75_uhttpd_user.log"

# Skip network setup (br0 assumed to exist from previous tasks)

# Cleanup previous (try pkill, might fail if root owned)
pkill -f "uhttpd.*axe75" 2>/dev/null
pkill -f "qemu-arm.*axe75" 2>/dev/null

echo "[*] Launching uhttpd (USER MODE) on port 8080..."
echo "    Root: $ROOTFS"
echo "    Mock: $MOCK_LIB"

# No sudo. Port changed to 8080.
QEMU_LD_PREFIX="$ROOTFS" \
"$QEMU_BIN" \
    -E LD_PRELOAD="$MOCK_LIB" \
    -L "$ROOTFS" \
    "$ROOTFS/usr/sbin/uhttpd" \
    -f -p 8080 -h "$ROOTFS/www" -x /cgi-bin -t 60 \
    > "$LOG_FILE" 2>&1 &

PID=$!
echo "[*] QEMU started with PID $PID. Logs at $LOG_FILE"
echo "[*] Waiting for startup..."
sleep 5
echo "[*] Checking process..."
pgrep -a qemu-arm
echo "[*] Checking port 8080..."
netstat -tulpn | grep 8080
