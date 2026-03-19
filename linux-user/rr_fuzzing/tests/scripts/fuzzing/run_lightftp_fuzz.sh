#!/bin/bash
# LightFTP Fuzzing Campaign (Target 18)
set -e

SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
PROJECT_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
TARGET_DIR="$SIM_ROOT/tests/realworld/LightFTP"
ROOTFS="$TARGET_DIR/fuzz_root"
TRACE="$TARGET_DIR/auto_retr.trace"
OUTPUT_DIR="$SIM_ROOT/fuzz_output_lightftp"

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting LightFTP (L-FTP) Fuzzing..."

# LightFTP is x86-64
PYTHONPATH="$PROJECT_ROOT" \
exec python3 "$PROJECT_ROOT/fuzzing/fuzz_main.py" \
    --trace "$TRACE" \
    --target "$TARGET_DIR/src/Release/fftp" \
    --qemu "$SIM_ROOT/../../build/qemu-x86_64" \
    --args "$TARGET_DIR/data/fftp.conf" \
    --infinite \
    --persistence \
    --output "$OUTPUT_DIR" \
    2>&1 >> "$OUTPUT_DIR/launch.log"
