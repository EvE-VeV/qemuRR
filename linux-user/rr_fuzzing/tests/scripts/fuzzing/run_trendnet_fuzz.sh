#!/bin/bash
# Formal Fuzzing Script for Trendnet TEW-827DRU (CVE-2024-28353)

BASE_DIR="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
ROOTFS="$BASE_DIR/verified_targets/Trendnet_TEW827DRU/rootfs"
QEMU="/home/webfuzz/Documents/qemu/build/qemu-mipsel"
CAMPAIGN_DIR="$BASE_DIR/verified_targets/Trendnet_TEW827DRU/fuzzing_cve_2024_28353"

# Ensure sync directory exists
mkdir -p "$CAMPAIGN_DIR/sync"

# CRITICAL: Set explicit QEMU_LD_PREFIX for this target
export QEMU_LD_PREFIX="$ROOTFS"
echo "🔧 Using QEMU_LD_PREFIX: $QEMU_LD_PREFIX"

# Export RR environment for workers
export RR_MODE=REPLAY_ADVANCE
export RR_LOG_FILE="$CAMPAIGN_DIR/worker_debug.log"

# Run the FuzzMaster
cd "$BASE_DIR"
python3 -m fuzzing.multiprocess.fuzz_master \
    --qemu "$QEMU" \
    --target "$ROOTFS/usr/sbin/uhttpd" \
    --target-args "-f -p 8080 -h /www -x /" \
    --trace "$CAMPAIGN_DIR/traces/init.txt" \
    --sync-dir "$CAMPAIGN_DIR/sync" \
    --workers 4 \
    --smart \
    --architecture mipsel
