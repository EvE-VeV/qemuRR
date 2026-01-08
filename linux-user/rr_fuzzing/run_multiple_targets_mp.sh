#!/bin/bash
# run_multiple_targets_mp.sh

# Target definitions: "BIN ARGS"
TARGETS=(
    "/bin/ls -la" 
    "/usr/bin/who " 
    "/usr/bin/uniq linux-user/rr_fuzzing/input.txt" 
    "/usr/bin/base64 linux-user/rr_fuzzing/input.txt" 
    "/usr/bin/md5sum linux-user/rr_fuzzing/input.txt"
)
WORKERS=4
TIMEOUT=90  # 90 seconds per target
OUTPUT_BASE="linux-user/rr_fuzzing/fuzzing_reports_mp"

mkdir -p "$OUTPUT_BASE"

echo "======================================================================"
echo "MULTI-PROCESS MULTI-TARGET FUZZING TEST"
echo "======================================================================"

for TARGET_ENTRY in "${TARGETS[@]}"; do
    # Split into BIN and ARGS
    BINARY=$(echo $TARGET_ENTRY | awk '{print $1}')
    ARGS=$(echo $TARGET_ENTRY | cut -d' ' -f2-)
    NAME=$(basename $BINARY)
    
    echo "----------------------------------------------------------------------"
    echo "TESTING TARGET: $NAME (Workers: $WORKERS)"
    echo "Binary: $BINARY"
    echo "Args:   $ARGS"
    echo "----------------------------------------------------------------------"
    
    TRACE_FILE="linux-user/rr_fuzzing/trace_${NAME}_mp.txt"
    SYNC_DIR="$OUTPUT_BASE/sync_$NAME"
    
    # 1. Cleanup
    rm -f "$TRACE_FILE" "$TRACE_FILE.bbl" "$TRACE_FILE.analyzer.pkl"
    rm -rf "$SYNC_DIR"
    
    # 2. Record
    echo "[1/2] Recording trace..."
    # We must pass the arguments to QEMU as well
    RR_MODE=record RR_TRACE_FILE="$TRACE_FILE" RR_DEBUG_LEVEL=1 ./build/qemu-x86_64 $BINARY $ARGS > /dev/null 2>&1
    
    if [ ! -f "$TRACE_FILE" ]; then
        echo "❌ Failed to record trace for $NAME"
        continue
    fi
    echo "✅ Trace recorded: $(ls -lh $TRACE_FILE | awk '{print $5}')"
    ABS_TRACE=$(realpath "$TRACE_FILE")
    
    # 3. Fuzz (Multi-Process)
    echo "[2/2] Fuzzing for ${TIMEOUT}s..."
    export RR_BATCH_SIZE=1
    export RR_MUTATIONS_PER_FORK=10
    
    python3 linux-user/rr_fuzzing/fuzzing/fuzz_multiprocess.py \
        --qemu ./build/qemu-x86_64 \
        --target "$BINARY" \
        --args "$ARGS" \
        --trace "$ABS_TRACE" \
        --sync-dir "$SYNC_DIR" \
        --workers $WORKERS \
        --smart \
        --timeout $TIMEOUT
        
    if [ $? -eq 0 ]; then
        echo "✅ Fuzzing for $NAME completed."
        # Print summary from final_stats.json of the first worker if it exists
        STATS_FILE="$SYNC_DIR/worker0/final_stats.json"
        if [ -f "$STATS_FILE" ]; then
            # Since stats are per-worker, we might want to check them all, but let's just show worker0 for now
            EXECS=$(grep -oP '"total_execs": \K[0-9]+' "$STATS_FILE" | head -1)
            COV=$(grep -oP '"total_edges": \K[0-9]+' "$STATS_FILE" | head -1)
            echo "📊 Worker-0 Results: Execs=$EXECS, Edges=$COV"
        else
            echo "⚠️  Worker-0 stats not found for $NAME"
        fi
    else
        echo "❌ Fuzzing for $NAME command failed (exit code $?)."
    fi
    echo ""
done

echo "======================================================================"
echo "ALL MP TESTS COMPLETED"
echo "======================================================================"
