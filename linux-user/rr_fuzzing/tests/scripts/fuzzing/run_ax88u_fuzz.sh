#!/bin/bash
export RR_LOG_LEVEL=INFO
export RR_MOCK_IOCTLS=1
export RR_MOCK_WIRELESS=1
export RR_ENABLED=1

# Ensure directories exist
mkdir -p /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/logs

# Launch fuzzing conductor
echo "[*] Launching ASUS RT-AX88U Fuzzing Campaign..."
PYTHONPATH=/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing \
python3 /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
    --target ax88u \
    --qemu /home/webfuzz/Documents/qemu/build/qemu-arm \
    --trace /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Asus/RT-AX88U/traces/ax88u_init.trace \
    --dictionary /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing/config/dicts/http.dict \
    --workers 1
