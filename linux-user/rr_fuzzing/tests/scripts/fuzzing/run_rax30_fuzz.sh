#!/bin/bash
set -e

# Configuration
SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Netgear/upgrade/NetgearRax30/_RAX30-V1.0.9.92_1.img.extracted/squashfs-root"
RR_TRACE_FILE="$SIM_ROOT/tests/images/Netgear/upgrade/traces/init.txt"
OUTPUT_DIR="$SIM_ROOT/fuzz_output_rax30_cve"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Netgear RAX30 (CVE-2023-40478) Fuzzing..."

# Launch Fuzzer
sudo QEMU_LD_PREFIX="$ROOTFS" \
     python3 $SIM_ROOT/fuzzing/fuzz_main.py \
    --trace "$RR_TRACE_FILE" \
    --target "$ROOTFS/usr/sbin/utelnetd" \
    --qemu "$SIM_ROOT/../build/qemu-arm" \
    --iterations 10000 \
    --infinite \
    --output "$OUTPUT_DIR" \
    --input "$SIM_ROOT/tests/inputs/rax30"
