#!/bin/bash
# RQ4 Ablation Study Runner
# Runs V0-V3 variants sequentially on 2 targets, 300 iterations each.
# V4 (Full) data comes from existing campaigns.
# Results written to: rr_fuzzing/evaluation/ablation/
set -e

RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
FUZZING="$RR_ROOT/fuzzing"
OUT_BASE="$RR_ROOT/evaluation/ablation"
QEMU_MIPS="/home/webfuzz/Documents/qemu/build/qemu-mips"
QEMU_ARM="/home/webfuzz/Documents/qemu/build/qemu-arm"

# Targets
BOA_TARGET="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root/bin/boa"
BOA_TRACE="$RR_ROOT/tests/seeds/TOTOLINK/boa_totolink_v2.trace"
BOA_ROOTFS="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root"

AC68U_TARGET="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Asus_RTAC68U/rootfs/usr/sbin/httpd"
AC68U_TRACE="$RR_ROOT/tests/seeds/Asus_RTAC68U.trace"
AC68U_ROOTFS="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/verified_targets/Asus_RTAC68U/rootfs"

ITERS=300        # iterations per variant
TIMEOUT=2400     # hard kill after 40min (safety)

mkdir -p "$OUT_BASE"

log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$OUT_BASE/ablation_runner.log"; }

run_variant() {
    local variant="$1"   # e.g. V0_boa
    local qemu="$2"
    local target="$3"
    local trace="$4"
    local rootfs="$5"
    local extra_args="$6"    # ablation flags
    local target_args="$7"   # binary args (e.g. "-c . -d")
    local word_size="${8:-0}"

    local out_dir="$OUT_BASE/$variant"
    mkdir -p "$out_dir"

    log "=== START $variant (${ITERS} iters) ==="

    # Memory check before starting
    local avail_mb
    avail_mb=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    if [ "$avail_mb" -lt 800 ]; then
        log "WARNING: Only ${avail_mb}MB available, waiting 30s..."
        sleep 30
    fi

    local start_ts
    start_ts=$(date +%s)

    # Sample crash count at start
    echo "0 0" > "$out_dir/crash_curve.txt"

    # Background sampler: every 60s record crash count
    (
        while true; do
            sleep 60
            elapsed=$(( $(date +%s) - start_ts ))
            n_crashes=$(ls "$out_dir/crashes/" 2>/dev/null | grep -c '\.bin' || echo 0)
            n_unique=$(ls "$out_dir/crashes/" 2>/dev/null | grep '\.bin' | \
                       sed 's/crash_[0-9]*_\([a-f0-9]*\)\.bin/\1/' | sort -u | wc -l || echo 0)
            echo "$elapsed $n_crashes $n_unique" >> "$out_dir/crash_curve.txt"
        done
    ) &
    local sampler_pid=$!

    PYTHONPATH="$FUZZING" \
    QEMU_LD_PREFIX="$rootfs" \
    timeout "$TIMEOUT" \
    python3 "$FUZZING/fuzz_main.py" \
        --qemu "$qemu" \
        --trace "$trace" \
        --target "$target" \
        --output "$out_dir" \
        --iterations "$ITERS" \
        --no-progress-timeout 1800 \
        --word-size "$word_size" \
        ${target_args:+--args "$target_args"} \
        ${rootfs:+--ld-prefix "$rootfs"} \
        $extra_args \
        2>&1 | tee "$out_dir/run.log" || true

    kill "$sampler_pid" 2>/dev/null || true

    local end_ts
    end_ts=$(date +%s)
    local wall_time=$(( end_ts - start_ts ))

    # Final stats
    local n_total n_unique
    n_total=$(find "$out_dir/crashes" -name "*.bin" 2>/dev/null | wc -l)
    n_unique=$(find "$out_dir/crashes" -name "*.bin" 2>/dev/null | \
               sed 's/.*crash_[0-9]*_\([a-f0-9]*\)\.bin/\1/' | sort -u | wc -l)
    local n_forks n_iters eps
    n_forks=$(grep -c "Fork request" "$out_dir/run.log" 2>/dev/null || echo 0)
    n_iters=$(( n_forks / 4 ))
    eps=$(python3 -c "print(round($n_iters/max($wall_time,1),3))" 2>/dev/null || echo "0")

    # Write summary (single-line values to avoid JSON heredoc newline issues)
    python3 - << PYEOF
import json
data = {
    "variant": "$variant",
    "wall_time_s": $wall_time,
    "iterations": $n_iters,
    "iterations_target": $ITERS,
    "crashes_total": $n_total,
    "crashes_unique": $n_unique,
    "iter_per_sec": $eps,
    "flags": "$extra_args"
}
with open("$out_dir/summary.json", "w") as f:
    json.dump(data, f, indent=2)
PYEOF

    log "=== DONE $variant | wall=${wall_time}s iters=${n_iters} crashes=${n_total} unique=${n_unique} ==="
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# V0: Base (no DFC, no SmartMutator, no PathFinder, no FD isolation)
run_variant "V0_boa" "$QEMU_MIPS" "$BOA_TARGET" "$BOA_TRACE" "$BOA_ROOTFS" \
    "--disable-dfc --disable-smartdict --disable-pathfinder" \
    "-c . -d" "32"

run_variant "V0_ac68u" "$QEMU_ARM" "$AC68U_TARGET" "$AC68U_TRACE" "$AC68U_ROOTFS" \
    "--disable-dfc --disable-smartdict --disable-pathfinder" \
    "" "32"

# ─────────────────────────────────────────────────────────────────────────────
# V1: +DFC (DFS checkpoint enabled, SmartMutator off, PathFinder off)
run_variant "V1_boa" "$QEMU_MIPS" "$BOA_TARGET" "$BOA_TRACE" "$BOA_ROOTFS" \
    "--disable-smartdict --disable-pathfinder" \
    "-c . -d" "32"

run_variant "V1_ac68u" "$QEMU_ARM" "$AC68U_TARGET" "$AC68U_TRACE" "$AC68U_ROOTFS" \
    "--disable-smartdict --disable-pathfinder" \
    "" "32"

# ─────────────────────────────────────────────────────────────────────────────
# V2: +DFC +SmartMutator (PathFinder off)
run_variant "V2_boa" "$QEMU_MIPS" "$BOA_TARGET" "$BOA_TRACE" "$BOA_ROOTFS" \
    "--disable-pathfinder" \
    "-c . -d" "32"

run_variant "V2_ac68u" "$QEMU_ARM" "$AC68U_TARGET" "$AC68U_TRACE" "$AC68U_ROOTFS" \
    "--disable-pathfinder" \
    "" "32"

# ─────────────────────────────────────────────────────────────────────────────
# V3: +DFC +SmartMutator +PathFinder (no FD isolation — default mode)
run_variant "V3_boa" "$QEMU_MIPS" "$BOA_TARGET" "$BOA_TRACE" "$BOA_ROOTFS" \
    "" \
    "-c . -d" "32"

run_variant "V3_ac68u" "$QEMU_ARM" "$AC68U_TARGET" "$AC68U_TRACE" "$AC68U_ROOTFS" \
    "" \
    "" "32"

# ─────────────────────────────────────────────────────────────────────────────
log "=== ALL VARIANTS COMPLETE ==="
log "Results: $OUT_BASE"
log "Run: python3 $RR_ROOT/evaluation/ablation/analyze_ablation.py"
