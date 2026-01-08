#!/bin/bash
# run_multiple_targets.sh

# Target definitions: "BIN ARGS"
TARGETS=(
    "/bin/ls -la" 
    "/usr/bin/who " 
    "/usr/bin/uniq linux-user/rr_fuzzing/input.txt" 
    "/usr/bin/base64 linux-user/rr_fuzzing/input.txt" 
    "/usr/bin/md5sum linux-user/rr_fuzzing/input.txt"
)
ITERATIONS=200
OUTPUT_BASE="linux-user/rr_fuzzing/fuzzing_reports"

mkdir -p "$OUTPUT_BASE"

for TARGET_ENTRY in "${TARGETS[@]}"; do
    # Split into BIN and ARGS
    BINARY=$(echo $TARGET_ENTRY | awk '{print $1}')
    ARGS=$(echo $TARGET_ENTRY | cut -d' ' -f2-)
    NAME=$(basename $BINARY)
    
    echo "======================================================================"
    echo "TESTING TARGET: $NAME"
    echo "Binary: $BINARY"
    echo "Args:   $ARGS"
    echo "======================================================================"
    
    TRACE_FILE="linux-user/rr_fuzzing/trace_$NAME.txt"
    REPORT_DIR="$OUTPUT_BASE/report_$NAME"
    
    # 1. Cleanup
    rm -f "$TRACE_FILE" "$TRACE_FILE.bbl" "$TRACE_FILE.analyzer.pkl"
    rm -rf "$REPORT_DIR"
    
    # 2. Record
    echo "[1/2] Recording trace..."
    # We must pass the arguments to QEMU as well
    RR_MODE=record RR_TRACE_FILE="$TRACE_FILE" RR_DEBUG_LEVEL=1 ./build/qemu-x86_64 $BINARY $ARGS > /dev/null 2>&1
    
    if [ ! -f "$TRACE_FILE" ]; then
        echo "❌ Failed to record trace for $NAME"
        continue
    fi
    echo "✅ Trace recorded: $(ls -lh $TRACE_FILE | awk '{print $5}')"
    
    # 3. Fuzz
    echo "[2/2] Fuzzing for $ITERATIONS iterations..."
    export RR_BATCH_SIZE=1
    export RR_MUTATIONS_PER_FORK=10
    
    # Use --args for the target arguments
    python3 linux-user/rr_fuzzing/fuzzing/fuzz_main.py \
        --qemu ./build/qemu-x86_64 \
        --target "$BINARY" \
        --args "$ARGS" \
        --trace "$TRACE_FILE" \
        --output "$REPORT_DIR" \
        --iterations $ITERATIONS
        
    if [ $? -eq 0 ]; then
        echo "✅ Fuzzing for $NAME completed."
        # Print summary from final_stats.json if it exists
        if [ -f "$REPORT_DIR/final_stats.json" ]; then
            EXECS=$(grep -oP '"total_execs": \K[0-9]+' "$REPORT_DIR/final_stats.json" | head -1)
            COV=$(grep -oP '"total_edges": \K[0-9]+' "$REPORT_DIR/final_stats.json" | head -1)
            echo "📊 Results: Execs=$EXECS, Edges=$COV"
        else
            echo "⚠️  final_stats.json not found for $NAME"
        fi
    else
        echo "❌ Fuzzing for $NAME failed."
    fi
    echo ""
done

echo "======================================================================"
echo "ALL TESTS COMPLETED"
echo "======================================================================"
