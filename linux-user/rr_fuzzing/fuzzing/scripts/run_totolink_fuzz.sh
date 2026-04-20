#!/bin/bash
export RR_LOG_LEVEL=INFO
export RR_MOCK_IOCTLS=1
export RR_MOCK_WIRELESS=1
export RR_ENABLED=1

# Ensure directories exist
mkdir -p /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/seeds/TOTOLINK
mkdir -p /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/logs

# Launch fuzzing conductor
echo "[*] Launching TOTOLINK Fuzzing Campaign..."
PYTHONPATH=/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing \
python3 /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
    --qemu /home/webfuzz/Documents/qemu/build/qemu-mips \
    --target /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root/bin/boa \
    --trace /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/seeds/TOTOLINK/boa_totolink_v2.trace \
    --dictionary /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/config/dicts/totolink_http.dict \
    --ld-prefix /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root \
    --word-size 32 \
    --args "-c /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root/etc/boa -d" \
    --workers 4
