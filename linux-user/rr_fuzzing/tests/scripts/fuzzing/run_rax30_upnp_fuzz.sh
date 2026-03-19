#!/bin/bash
# RAX30 UPnP Fuzzing Campaign (Fixed: using bin/upnp with upnp_full.txt trace)
set -e

SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PROJECT_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Netgear_RAX30/rootfs"
RR_TRACE_FILE="$SIM_ROOT/tests/verified_targets/Netgear_RAX30/artifacts/upnp_full.txt"
OUTPUT_DIR="$SIM_ROOT/fuzz_output_rax30_upnp"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Netgear RAX30 UPnP Fuzzing..."
echo "[*] Target  : $ROOTFS/bin/upnp"
echo "[*] Trace   : $RR_TRACE_FILE"
echo "[*] Output  : $OUTPUT_DIR"

# Use high-fidelity mock CMS library
MOCK_LIB="$SIM_ROOT/tests/images/RAX30/libcms_mock.so"

PYTHONPATH="$PROJECT_ROOT" \
QEMU_LD_PREFIX="$ROOTFS" \
QEMU_SET_ENV="LD_PRELOAD=$MOCK_LIB" \
python3 "$PROJECT_ROOT/fuzzing/fuzz_main.py" \
    --trace "$RR_TRACE_FILE" \
    --target "$ROOTFS/bin/upnp" \
    --args "-L ens33 -m 1234" \
    --qemu "$SIM_ROOT/../../build/qemu-arm" \
    --ld-prefix "$ROOTFS" \
    --infinite \
    --persistence \
    --output "$OUTPUT_DIR" \
    2>&1 | tee "$OUTPUT_DIR/launch.log"
