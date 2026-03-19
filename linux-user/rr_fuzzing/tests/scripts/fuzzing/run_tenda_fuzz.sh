#!/bin/bash
# Tenda AC15 httpd Fuzzing Script
# Uses sudo to ensure QEMU can access the required network environment (br0/port 80)

export PROJECT_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
export SIM_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"
export RR_TRACE_FILE="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/crashes/real_world_repro/TENDA_AC15/traces/tenda_test_v28.trace"
export OUTPUT_DIR="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/crashes/real_world_repro/TENDA_AC15/outputs"

# Fuzzer configuration
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting Tenda AC15 Fuzzing (based on sudo execution)..."
echo "[!] Note: The fuzzer will launch QEMU via sudo to match the recording environment."

# We run the main fuzzer without sudo to prevent password prompts blocking execution
QEMU_LD_PREFIX="$SIM_ROOT" \
     exec python3 "$PROJECT_ROOT/fuzzing/fuzz_main.py" \
    --trace "$RR_TRACE_FILE" \
    --target "$SIM_ROOT/bin/httpd" \
    --qemu "/home/webfuzz/Documents/qemu/build/qemu-arm" \
    --iterations 1000 \
    --infinite \
    --output "$OUTPUT_DIR"
