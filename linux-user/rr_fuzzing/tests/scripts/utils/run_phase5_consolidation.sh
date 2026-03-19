#!/bin/bash
set -e

# Phase 5: Result Consolidation - Concurrent Fuzzing Campaign

RR_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing"
cd "$RR_ROOT"

echo "[*] Launching JJHTTPD (MIPS) Fuzzing..."
nohup ./run_jjhttpd_fuzz.sh > fuzz_output_jjhttpd/phase5.log 2>&1 &
echo "    PID: $!"

echo "[*] Launching UPNP (ARM) Fuzzing..."
mkdir -p fuzz_output_upnp
nohup ./run_upnp_fuzz.sh > fuzz_output_upnp/phase5.log 2>&1 &
echo "    PID: $!"

echo "[*] Both campaigns launched in background."
echo "    Monitor logs at:"
echo "      - fuzz_output_jjhttpd/phase5.log"
echo "      - fuzz_output_upnp/phase5.log"
