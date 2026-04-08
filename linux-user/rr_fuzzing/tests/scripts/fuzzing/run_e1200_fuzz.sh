#!/bin/bash
# Linksys E1200 POST-AUTH Fuzzing Campaign
# auth_boundary=65 (accept() at idx=65 returns fd=7)
# Trace: authenticated GET / with Authorization: Basic YWRtaW46YWRtaW4= (admin:admin)
# Server returns 200 Ok — mutations applied to post-auth request content

SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PROJECT_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="$SIM_ROOT/tests/images/Linksys/rootfs"
RR_TRACE_FILE="$SIM_ROOT/tests/seeds/Linksys_E1200_auth.trace"
OUTPUT_DIR="$SIM_ROOT/fuzz_output_e1200"

mkdir -p "$OUTPUT_DIR"
# httpd needs /tmp/run on host filesystem
mkdir -p /tmp/run && chmod 777 /tmp/run

echo "[*] Starting Linksys E1200 POST-AUTH Fuzzing..."
echo "    Trace: $RR_TRACE_FILE (108 syscalls, 200 Ok)"
echo "    auth_boundary=65 (accept idx=65, fd=7)"
echo "    Output: $OUTPUT_DIR"

PYTHONPATH="$PROJECT_ROOT" \
QEMU_LD_PREFIX="$ROOTFS" \
exec python3 "$PROJECT_ROOT/fuzzing/fuzz_main.py" \
    --trace "$RR_TRACE_FILE" \
    --target "$ROOTFS/usr/sbin/httpd" \
    --qemu "$SIM_ROOT/../../build/qemu-mipsel" \
    --ld-prefix "$ROOTFS" \
    --args "-p 8093" \
    --auth-boundary 65 \
    --infinite \
    --persistence \
    --output "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/launch.log"
