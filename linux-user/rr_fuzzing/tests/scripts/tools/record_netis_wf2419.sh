#!/bin/bash

# Configuration
PROJECT_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="$PROJECT_ROOT/tests/verified_targets/Netis_WF2419/rootfs"
QEMU="/home/webfuzz/Documents/qemu/build/qemu-mips"
TRACE_FILE="$PROJECT_ROOT/tests/seeds/Netis_WF2419/netis_wf2419_seed.bin"
PORT=8080

mkdir -p "$PROJECT_ROOT/tests/seeds/Netis_WF2419"

# Cleanup previous instances
killall -9 qemu-mips 2>/dev/null

echo "[*] Starting Netis WF2419 Recording..."

# Start QEMU in record mode
export RR_ENABLED=1
export RR_MODE=record
export RR_TRACE_FILE="$TRACE_FILE"

"$QEMU" -L "$ROOTFS" "$ROOTFS/bin/boa" -p /bin/boa -f /etc/boa.conf &
QEMU_PID=$!

# Wait for service to start
sleep 3

echo "[*] Sending trigger request..."
curl -v "http://127.0.0.1:$PORT/cgi-bin/test.cgi"

# Allow some time for processing
sleep 1

# Terminate
echo "[*] Stopping QEMU..."
kill -SIGINT $QEMU_PID
wait $QEMU_PID

echo "[*] Recording Finished. Trace saved to $TRACE_FILE"
ls -l "$TRACE_FILE"
