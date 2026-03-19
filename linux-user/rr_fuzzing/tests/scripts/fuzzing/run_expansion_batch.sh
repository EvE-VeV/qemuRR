#!/bin/bash
# Consolidated Launch Script for Multi-target Expansion

RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PYTHON_BIN="/usr/bin/python3"
QEMU_ARM_BIN="/home/webfuzz/Documents/qemu/build/qemu-arm"

# 1. Netgear RAX30
RAX30_ROOTFS="${RR_ROOT}/tests/images/Netgear/upgrade/NetgearRax30/_RAX30-V1.0.9.92_1.img.extracted/squashfs-root"
RAX30_TRACE="${RR_ROOT}/tests/verified_targets/Netgear_RAX30/artifacts/upnp_full.txt"
RAX30_OUTPUT="${RR_ROOT}/fuzz_output_rax30"

mkdir -p "$RAX30_OUTPUT"
echo "[*] Launching Netgear RAX30 Campaign..."
nohup env QEMU_LD_PREFIX="$RAX30_ROOTFS" \
    "$PYTHON_BIN" "$RR_ROOT/fuzzing/fuzz_main.py" \
    --trace "$RAX30_TRACE" \
    --target "$RAX30_ROOTFS/usr/sbin/utelnetd" \
    --qemu "$QEMU_ARM_BIN" \
    --iterations 50000 \
    --infinite \
    --output "$RAX30_OUTPUT" > "$RAX30_OUTPUT/launch.log" 2>&1 &

# 2. Tenda AC15
TENDA_ROOTFS="${RR_ROOT}/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"
TENDA_TRACE="${RR_ROOT}/crashes/real_world_repro/TENDA_AC15/traces/tenda_test_v28.trace"
TENDA_OUTPUT="${RR_ROOT}/fuzz_output_tenda"

mkdir -p "$TENDA_OUTPUT"
echo "[*] Launching Tenda AC15 Campaign..."
nohup env QEMU_LD_PREFIX="$TENDA_ROOTFS" \
    "$PYTHON_BIN" "$RR_ROOT/fuzzing/fuzz_main.py" \
    --trace "$TENDA_TRACE" \
    --target "$TENDA_ROOTFS/bin/httpd" \
    --qemu "$QEMU_ARM_BIN" \
    --iterations 50000 \
    --infinite \
    --output "$TENDA_OUTPUT" > "$TENDA_OUTPUT/launch.log" 2>&1 &

echo "[*] Expansion deployment initiated."
