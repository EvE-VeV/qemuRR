#!/bin/bash
# Recording script for Asus RT-AX56U

RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="${RR_ROOT}/tests/images/Asus/RT-AX56U_CLEAN_V3/278916373/rootfs_ubifs"
TARGET_BIN="/usr/sbin/httpd"
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-arm"
TRACE_OUT="${RR_ROOT}/tests/seeds/Asus_RTAX56U.trace"

mkdir -p "$(dirname "$TRACE_OUT")"

echo "[*] Recording Asus RT-AX56U..."
# Added dummy certs if needed, or check if they exist in this rootfs
mkdir -p "$ROOTFS/tmp"
touch "$ROOTFS/tmp/cert.pem" "$ROOTFS/tmp/key.pem"

export QEMU_LD_PREFIX="$ROOTFS"

# Record the trace
# We use -L to point to libraries in the rootfs
# We use RR_MODE=RECORD to enable the recording plugin
env RR_MODE=RECORD \
    RR_TRACE_FILE="$TRACE_OUT" \
    "$QEMU_BIN" -L "$ROOTFS" "$ROOTFS$TARGET_BIN"
