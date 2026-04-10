#!/bin/bash
# TRENDnet TEW-827DRU uhttpd POST Fuzzing Campaign (MIPS fix, 2026-04-10)
#
# Trace: Trendnet_TEW827_post.trace (1627 syscalls)
# Key indices:
#   [1096] accept -> fd=8 (first connection)
#   [1112] accept -> fd=8 (second connection, POST)  ← auth_boundary
#   [1122] read(fd=8, 190B, aux=True)  ← HTTP request read
#   [1126+] write(fd=8) ← HTTP response writes
#
# Crashes found previously: d0de57e2 (idx=1126), e4196d86 (idx=1153) — SIGBUS, uhttpd lib

set -e
SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="$SIM_ROOT/tests/verified_targets/Trendnet_TEW827DRU/rootfs"
RR_TRACE_FILE="$SIM_ROOT/tests/seeds/Trendnet_TEW827_post.trace"
OUTPUT_DIR="$SIM_ROOT/evaluation/rq5_vulns/tew827_post2"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting TEW-827DRU uhttpd POST Fuzzing (MIPS-fixed)..."
echo "    Trace: $RR_TRACE_FILE (1627 syscalls)"
echo "    auth_boundary=1112, network read at idx=1122"
echo "    Output: $OUTPUT_DIR"

cd "$SIM_ROOT/fuzzing"

PYTHONPATH="$SIM_ROOT" \
QEMU_LD_PREFIX="$ROOTFS" \
exec python3 fuzz_main.py \
    --trace "$RR_TRACE_FILE" \
    --target "$ROOTFS/usr/sbin/uhttpd" \
    --qemu "$SIM_ROOT/../../build/qemu-mipsel" \
    --ld-prefix "$ROOTFS" \
    --args "-f -p 8099 -h /www -x /" \
    --auth-boundary 1112 \
    --fork-point 1112 \
    --infinite \
    --persistence \
    --output "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/launch.log"
