#!/usr/bin/env bash
# Ablation Study script for RR-Fuzz (-SmartDict, -PathFinder)

OUT_DIR="ablation_results_$(date +%Y%m%d_%H%M%S)"
TARGET="linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/bin/httpd"
TRACE="linux-user/rr_fuzzing/crashes/real_world_repro/TENDA_AC15/traces/tenda_test_v26.trace"
LD_PREFIX="linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root"
DURATION="24h"

mkdir -p "$OUT_DIR"
echo "[*] Ablation Results Directory: $OUT_DIR"
echo "[*] Patching Tenda libraries (mock)..."
python3 linux-user/rr_fuzzing/tests/scripts/tools/patch_tenda_libraries.py --skip-libc

run_cfg2() {
    echo "[*] Starting Cfg-2: No SmartDict for $DURATION..."
    mkdir -p "$OUT_DIR/cfg2_no_smartdict_out"
    timeout -k 10s $DURATION python3 linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
        --qemu ./build/qemu-arm \
        --target "$TARGET" \
        --trace "$TRACE" \
        --output "$OUT_DIR/cfg2_no_smartdict_out" \
        -n 4 \
        --ld-prefix "$LD_PREFIX" \
        --disable-smartdict
    killall -9 python3 qemu-arm qemu-mipsel 2>/dev/null || true
    echo "[+] Cfg-2 benchmark completed."
}

run_cfg3() {
    echo "[*] Starting Cfg-3: No PathFinder for $DURATION..."
    mkdir -p "$OUT_DIR/cfg3_no_pathfinder_out"
    timeout -k 10s $DURATION python3 linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
        --qemu ./build/qemu-arm \
        --target "$TARGET" \
        --trace "$TRACE" \
        --output "$OUT_DIR/cfg3_no_pathfinder_out" \
        -n 4 \
        --ld-prefix "$LD_PREFIX" \
        --disable-pathfinder
    killall -9 python3 qemu-arm qemu-mipsel 2>/dev/null || true
    echo "[+] Cfg-3 benchmark completed."
}

MODE=${1:-all}

if [ "$MODE" == "cfg2" ] || [ "$MODE" == "all" ]; then
    run_cfg2
fi

if [ "$MODE" == "cfg3" ] || [ "$MODE" == "all" ]; then
    run_cfg3
fi

echo "[*] All ablation runs completed. Data saved in $OUT_DIR."
