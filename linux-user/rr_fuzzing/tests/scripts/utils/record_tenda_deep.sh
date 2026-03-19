#!/bin/bash
# Script to record a deep trace of Tenda AC15 httpd
set -x

TRACE_FILE="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/crashes/real_world_repro/TENDA_AC15/traces/tenda_test_v28.trace"
SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"

# Cleanup
sudo pkill -9 qemu-arm || true
rm -f "$TRACE_FILE"

# Launch recording
sudo RR_ENABLED=1 RR_MODE=record RR_TRACE_FILE="$TRACE_FILE" \
     /home/webfuzz/Documents/qemu/build/qemu-arm \
     -L "$SIM_ROOT" \
     "$SIM_ROOT/bin/httpd" > /tmp/tenda_v28_record.log 2>&1 &

REC_PID=$!
sleep 20 # Wait for init

# Trigger web logic
curl -I http://192.168.0.1/
curl -X POST -d "deviceName=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" http://192.168.0.1/formSetDeviceName
sleep 5

# Graceful stop
sudo pkill -INT qemu-arm
sleep 10

# Final cleanup
sudo pkill -9 qemu-arm || true

# Check result
ls -lh "$TRACE_FILE"
