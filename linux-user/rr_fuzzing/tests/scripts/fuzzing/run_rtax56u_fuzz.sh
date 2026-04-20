#!/bin/bash
# Asus RT-AX56U Fuzzing Launch Script (Target #11)

RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PYTHON_BIN="python3"
VT="${RR_ROOT}/tests/verified_targets"

# Ensure output directory exists
mkdir -p "${RR_ROOT}/fuzz_output_rtax56u"

echo "[*] Launching Asus RTAX56U Campaign..."

# Remove any previous lock files if they exist
rm -f "${RR_ROOT}/fuzz_output_rtax56u/fuzzer.lock"

nohup env \
    "$PYTHON_BIN" "$RR_ROOT/fuzzing/fuzz_main.py" \
    --iterations 100000 \
    --infinite \
    --persistence \
    --output "${RR_ROOT}/fuzz_output_rtax56u" \
    --qemu "${VT}/Asus_RTAX56U/qemu_wrapper.sh" \
    --trace "${VT}/Asus_RTAX56U/traces/init.trace" \
    --target "${VT}/Asus_RTAX56U/rootfs/usr/sbin/httpd" \
    --ld-prefix "${VT}/Asus_RTAX56U/rootfs" \
    --fork-point 476 > "${RR_ROOT}/fuzz_output_rtax56u/launch.log" 2>&1 &

PID=$!
echo "    PID=$PID"
echo "    Watch progress: tail -f ${RR_ROOT}/fuzz_output_rtax56u/launch.log"
