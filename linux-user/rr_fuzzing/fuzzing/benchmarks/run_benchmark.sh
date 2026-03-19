#!/bin/bash
# Benchmarking Execution Script for RR-Fuzz vs Baseline (24 Hours)
# Target: Tenda AC15 httpd
# Usage: ./run_benchmark.sh [rrfuzz|afl++|all]

OUT_DIR="benchmark_results_$(date +%Y%m%d_%H%M%S)"
TARGET="linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/bin/httpd"
TRACE="tenda_auth.trace"
LD_PREFIX="linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"

MODE=${1:-all}
DURATION=${2:-"24h"}

mkdir -p "$OUT_DIR"
echo "[*] Benchmark Results Directory: $OUT_DIR"
echo "[*] Patching Tenda libraries (mock)..."
python3 linux-user/rr_fuzzing/tests/scripts/tools/patch_tenda_libraries.py --skip-libc

mkdir -p "$OUT_DIR/afl_in"
cat > "$OUT_DIR/afl_in/seed1.txt" << 'EOF'
{
    "request": {
        "method": "GET",
        "prefix": "/",
        "handler_name": "",
        "version": "1.1"
    },
    "header": {
        "Host": "127.0.0.1",
        "Content-Length": "10"
    },
    "body": {
        "test": "test"
    },
    "possible_type": "normal"
}
EOF

run_rrfuzz() {
    echo "[*] Starting RR-Fuzz for $DURATION..."
    mkdir -p "$OUT_DIR/rrfuzz_out"
    # Timeout 24h
    timeout -k 10s $DURATION python3 linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
        --qemu ./build/qemu-arm \
        --target "$TARGET" \
        --trace "$TRACE" \
        --output "$OUT_DIR/rrfuzz_out" \
        -n 1 \
        --ld-prefix "$LD_PREFIX" \
        --fork-point 211 \
        --infinite
    killall -9 python3 qemu-arm qemu-mipsel 2>/dev/null || true
    echo "[+] RR-Fuzz benchmark completed."
}

run_aflplusplus() {
    echo "[*] Starting AFL++ QEMU mode for $DURATION..."
    mkdir -p "$OUT_DIR/afl_out"
    
    AFL_NO_UI=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 QEMU_LD_PREFIX="$LD_PREFIX" AFL_PATH=/home/webfuzz/Documents/qemu/baseline_tools/AFLplusplus timeout -k 10s $DURATION /home/webfuzz/Documents/qemu/baseline_tools/AFLplusplus/afl-fuzz -t 10000+ -i "$OUT_DIR/afl_in" -o "$OUT_DIR/afl_out" -Q -M main_node -- "$TARGET" @@
    killall -9 afl-fuzz afl-qemu-trace qemu-arm qemu-mipsel 2>/dev/null || true
    
    echo "[+] AFL++ benchmark completed."
}

run_firmafl() {
    echo "[*] Starting FirmAFL for $DURATION..."
    mkdir -p "$OUT_DIR/firmafl_out"
    # FirmAFL needs custom system/user QEMU setup. Using stub for benchmark script testing.
    timeout -k 10s $DURATION /home/webfuzz/Documents/qemu/baseline_tools/FirmAE/afl-fuzz -t 10000+ -i "$OUT_DIR/afl_in" -o "$OUT_DIR/firmafl_out" -Q -m none -- "$TARGET" @@ 2>/dev/null || true
    echo "[+] FirmAFL benchmark completed."
}

run_housefuzz() {
    echo "[*] Starting HouseFuzz for $DURATION..."
    mkdir -p "$OUT_DIR/housefuzz_out"
    chmod 777 "$OUT_DIR/housefuzz_out" || true
    chmod 777 "$OUT_DIR/afl_in" || true
    
    # HouseFuzz execution via Docker (requires absolute paths for mounts)
    ADS_OUT=$(realpath "$OUT_DIR")
    ABS_TARGET=$(realpath "$TARGET")
    ABS_LD=$(realpath "$LD_PREFIX")
    
    timeout -k 10s $DURATION docker run --rm \
        -v "$ADS_OUT:/sync" \
        -v "$ABS_TARGET:/target" \
        -v "$ABS_LD:/rootfs" \
        -e QEMU_LD_PREFIX=/rootfs \
        -e AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
        -e AFL_PATH=/Housefuzz/housefuzz/artifacts/fuzz_bins/bin \
        kenshin123/housefuzz \
        /Housefuzz/housefuzz/artifacts/fuzz_bins/bin/afl-fuzz -t 10000+ -i /sync/afl_in -o /sync/housefuzz_out -Q -- /target @@ 2>/dev/null || true
        
    echo "[+] HouseFuzz benchmark completed."
}

MODE=${1:-all}

if [ "$MODE" == "rrfuzz" ]; then
    run_rrfuzz
elif [ "$MODE" == "afl++" ]; then
    run_aflplusplus
elif [ "$MODE" == "firmafl" ]; then
    run_firmafl
elif [ "$MODE" == "housefuzz" ]; then
    run_housefuzz
elif [ "$MODE" == "all" ]; then
    run_rrfuzz &
    RR_PID=$!
    run_aflplusplus &
    AFL_PID=$!
    run_housefuzz &
    HOUSE_PID=$!
    echo "[*] Parallel benchmarks (3 baselines) started. RRFuzz PID: $RR_PID, AFL PID: $AFL_PID, HouseFuzz PID: $HOUSE_PID"
    wait $RR_PID $AFL_PID $HOUSE_PID
fi

echo "[*] All benchmarks completed. Data saved in $OUT_DIR."
