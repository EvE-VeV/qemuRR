#!/bin/bash
# Standalone launch script for Asus RT-AX88U (AS-88U) Fuzzing Campaign

RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PYTHON_BIN="python3"
VT="${RR_ROOT}/tests/verified_targets"
QEMU_WRAPPER="${VT}/Asus_RTAX88U/qemu_wrapper.sh"
TRACE="${VT}/Asus_RTAX88U/traces/ax88u_init.trace"
TARGET="${VT}/Asus_RTAX88U/sim_root/usr/sbin/httpd"
LD_PREFIX="${VT}/Asus_RTAX88U/sim_root"
OUTPUT_DIR="${RR_ROOT}/fuzz_output_rtax88u"

mkdir -p "$OUTPUT_DIR"

echo "[*] Cleaning up SHM..."
rm -f /dev/shm/rr_* 2>/dev/null || true

echo "[*] Launching Asus RT-AX88U fuzzer..."
nohup env \
    "$PYTHON_BIN" "$RR_ROOT/fuzzing/fuzz_main.py" \
    --iterations 100000 \
    --infinite \
    --persistence \
    --output "$OUTPUT_DIR" \
    --qemu "$QEMU_WRAPPER" \
    --trace "$TRACE" \
    --target "$TARGET" \
    --ld-prefix "$LD_PREFIX" > "$OUTPUT_DIR/launch.log" 2>&1 &

echo "    PID=$! log -> $OUTPUT_DIR/launch.log"
