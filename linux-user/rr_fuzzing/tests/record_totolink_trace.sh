#!/bin/bash
set -e

# Configuration
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-mips"
ROOTFS="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root"
BINARY="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root/bin/boa"
TRACE_OUTPUT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/seeds/TOTOLINK/boa_totolink_v2.trace"
LOG_file="record_totolink.log"

echo "[*] Cleaning up old trace..."
rm -f "$TRACE_OUTPUT" "${TRACE_OUTPUT}.bbl"

echo "[*] Starting QEMU recording..."
# Environment variables from totolink.json
export QEMU_LD_PREFIX="$ROOTFS"
export RR_LOG="record"
export RR_LOG_FILE="$TRACE_OUTPUT"
# QEMU runtime options
# -E LD_PRELOAD=... (if needed, but usually not for static record)

# Ensure /etc/boa exists as a DIRECTORY
if [ -L "$ROOTFS/etc/boa" ] || [ -f "$ROOTFS/etc/boa" ]; then
    rm -f "$ROOTFS/etc/boa"
fi
mkdir -p "$ROOTFS/etc/boa"

# Initialize boa.conf in /etc/boa/boa.conf
if [ ! -f "$ROOTFS/etc/boa/boa.conf" ]; then
    if [ -f "$ROOTFS/etc/boa.conf" ]; then
        cp "$ROOTFS/etc/boa.conf" "$ROOTFS/etc/boa/boa.conf"
    elif [ -f "$ROOTFS/var/boa/boa.conf" ]; then
        cp "$ROOTFS/var/boa/boa.conf" "$ROOTFS/etc/boa/boa.conf"
    fi
fi

# Ensure log and web directories exist
mkdir -p "$ROOTFS/var/log/boa"
mkdir -p "$ROOTFS/web"

# Run QEMU with timeout to capture enough trace but not hang forever
# timeout 20s is usually enough for init + some loop
# Use -c to specify absolute path to ServerRoot so chdir works
# Argument order: qemu [qemu_opts] binary [binary_args]
# Professional Mocking & Framework Enabled
export RR_MODE=record
export RR_ENABLED=1
export RR_MOCK_WIRELESS=1
export RR_DEBUG=1

# Enable full cpu and instruction tracing
timeout 20s "$QEMU_BIN" -strace -d in_asm,cpu -D /tmp/full_trace_v5.log -L "$ROOTFS" "$BINARY" -c "$ROOTFS/etc/boa" > "$LOG_file" 2>&1 || true

echo "[*] Recording finished. Checking trace file..."
ls -lh "$TRACE_OUTPUT"

if [ -f "$TRACE_OUTPUT" ]; then
    echo "[*] Trace file created successfully."
    echo "[*] Analyzing new trace..."
    /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/debug_trace_analyzer.py "$TRACE_OUTPUT"
else
    echo "[!] Trace file NOT created!"
    cat "$LOG_file"
fi
