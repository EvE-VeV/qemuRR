#!/bin/bash
export RR_DEBUG_LEVEL=1 
export RR_MAX_VARIANTS=1

# Ensure traces exist
RR_MODE=RECORD RR_TRACE_FILE=/tmp/ls.bin ./build/qemu-x86_64 /bin/ls / > /dev/null
RR_MODE=RECORD RR_TRACE_FILE=/tmp/date.bin ./build/qemu-x86_64 /bin/date > /dev/null
RR_MODE=RECORD RR_TRACE_FILE=/tmp/whoami.bin ./build/qemu-x86_64 /usr/bin/whoami > /dev/null
echo "NORMAL" | RR_MODE=RECORD RR_TRACE_FILE=/tmp/vuln.bin ./build/qemu-x86_64 ./linux-user/rr_fuzzing/fuzzing/target_vulnerability > /dev/null

# Go to qemu root
cd /home/webfuzz/Documents/qemu

mkdir -p results_all

echo "=== Target 1: ls (50 iterations) ==="
./linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
    --qemu build/qemu-x86_64 \
    --target /bin/ls \
    --trace /tmp/ls.bin \
    --iterations 50 \
    --args "/" \
    --output results_all/ls_long

echo "=== Target 2: date (30 iterations) ==="
./linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
    --qemu build/qemu-x86_64 \
    --target /bin/date \
    --trace /tmp/date.bin \
    --iterations 30 \
    --output results_all/date

echo "=== Target 3: whoami (30 iterations) ==="
./linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
    --qemu build/qemu-x86_64 \
    --target /usr/bin/whoami \
    --trace /tmp/whoami.bin \
    --iterations 30 \
    --output results_all/whoami

echo "=== Target 4: target_vulnerability (50 iterations) ==="
./linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
    --qemu build/qemu-x86_64 \
    --target ./linux-user/rr_fuzzing/fuzzing/target_vulnerability \
    --trace /tmp/vuln.bin \
    --iterations 50 \
    --output results_all/vuln
