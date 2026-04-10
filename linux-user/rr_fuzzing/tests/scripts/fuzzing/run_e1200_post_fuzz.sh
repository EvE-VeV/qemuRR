#!/bin/bash
# Linksys E1200 POST /apply.cgi Fuzzing Campaign (v5 - correct params)
#
# Trace: Linksys_E1200_post.trace (171 syscalls, recorded 2026-04-09)
# Key indices:
#   [65]  accept -> fd=7  (first request, GET auth)
#   [104] accept -> fd=7  (second request, POST /apply.cgi)  ← auth_boundary
#   [136] read(fd=7, 256B)  ← POST body first chunk (aux=True)
#   [138] read(fd=7, 116B)  ← POST body second chunk (aux=True)
#
# Goal: heap overflow in realloc via EXTEND+MUTATE_AUX_BUFFER at idx 136/138

set -e
SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PROJECT_ROOT="$SIM_ROOT"
ROOTFS="$SIM_ROOT/tests/images/Linksys/rootfs"
RR_TRACE_FILE="$SIM_ROOT/tests/seeds/Linksys_E1200_post.trace"
OUTPUT_DIR="$SIM_ROOT/evaluation/rq5_vulns/e1200_post3"

mkdir -p "$OUTPUT_DIR"
mkdir -p /tmp/run && chmod 777 /tmp/run

echo "[*] Starting Linksys E1200 POST /apply.cgi Fuzzing (v5)..."
echo "    Trace: $RR_TRACE_FILE"
echo "    auth_boundary=104 (second accept, POST request)"
echo "    Key targets: idx=136 (read POST body 256B), idx=138 (read POST body 116B)"
echo "    Output: $OUTPUT_DIR"

cd "$SIM_ROOT/fuzzing"

PYTHONPATH="$PROJECT_ROOT" \
QEMU_LD_PREFIX="$ROOTFS" \
exec python3 fuzz_main.py \
    --trace "$RR_TRACE_FILE" \
    --target "$ROOTFS/usr/sbin/httpd" \
    --qemu "$SIM_ROOT/../../build/qemu-mipsel" \
    --ld-prefix "$ROOTFS" \
    --args "-p 8097" \
    --auth-boundary 104 \
    --fork-point 104 \
    --infinite \
    --persistence \
    --output "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/launch.log"
