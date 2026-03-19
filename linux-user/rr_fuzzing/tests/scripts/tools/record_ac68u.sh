#!/bin/bash
set -e

SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="$SIM_ROOT/tests/verified_targets/Asus_RTAC68U/rootfs"
RR_TRACE_FILE="$SIM_ROOT/tests/seeds/Asus_RTAC68U.trace"
QEMU_ARM="$SIM_ROOT/../../build/qemu-arm"

echo "[*] Killing old httpd processes"
pkill -f "$ROOTFS/usr/sbin/httpd" || true
sleep 1

echo "[*] Removing old empty trace"
rm -f "$RR_TRACE_FILE"

echo "[*] Starting QEMU in RECORD mode..."
QEMU_LD_PREFIX=$ROOTFS RR_MODE=RECORD RR_TRACE_FILE="$RR_TRACE_FILE" \
    $QEMU_ARM -L $ROOTFS $ROOTFS/usr/sbin/httpd &
QEMU_PID=$!

echo "[*] Waiting for httpd to start..."
sleep 4

echo "[*] Sending traffic to generate IO syscalls..."
curl -s -m 2 http://127.0.0.1:80/ > /dev/null || echo "Request 1 failed"
curl -s -m 2 http://127.0.0.1:8080/ > /dev/null || echo "Request 2 failed"
curl -s -m 2 http://127.0.0.1:80/login.cgi > /dev/null || echo "Request 3 failed"

sleep 2
echo "[*] Terminating QEMU..."
kill $QEMU_PID || true
wait $QEMU_PID 2>/dev/null || true

echo "[*] Trace generated:"
ls -lh "$RR_TRACE_FILE"
