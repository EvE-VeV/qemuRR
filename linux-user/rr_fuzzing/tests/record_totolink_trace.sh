#!/bin/bash
set -e

# Configuration
QEMU_BIN="/home/webfuzz/Documents/qemu/build/qemu-mips"
ROOTFS="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root"
BINARY="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/Totolink/extracted_firmware/sim_root/bin/boa"
TRACE_OUTPUT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/seeds/TOTOLINK/boa_totolink_v2.trace"
LOG_file="record_totolink.log"
ANALYZER_CACHE="${TRACE_OUTPUT}.analyzer.pkl"

echo "[*] Cleaning up old trace..."
rm -f "$TRACE_OUTPUT" "${TRACE_OUTPUT}.bbl" "$ANALYZER_CACHE"

echo "[*] Starting QEMU recording..."
# Environment variables from totolink.json
export QEMU_LD_PREFIX="$ROOTFS"
export RR_LOG="record"
export RR_TRACE_FILE="$TRACE_OUTPUT"
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
export RR_MOCK_IOCTLS=1
export RR_MOCK_WIRELESS=1
export RR_DEBUG=1

# Enable full cpu and instruction tracing
timeout --signal=TERM 25s "$QEMU_BIN" -strace -d in_asm,cpu -D /tmp/full_trace_v5.log -L "$ROOTFS" "$BINARY" -c "$ROOTFS/etc/boa" > "$LOG_file" 2>&1 &
QEMU_PID=$!

echo "[*] Waiting for Boa to start listening..."
for _ in $(seq 1 50); do
    if grep -q "starting server pid=" "$LOG_file" 2>/dev/null; then
        echo "[*] Boa is listening on 127.0.0.1:8080"
        break
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "[!] QEMU exited before Boa started."
        break
    fi
    sleep 0.5
done

if grep -q "starting server pid=" "$LOG_file" 2>/dev/null; then
    echo "[*] Sending GET / to force accept()..."
    curl -sS --max-time 3 --retry 10 --retry-connrefused --retry-delay 1 \
        "http://127.0.0.1:8080/" >/tmp/totolink_record_get.out 2>/tmp/totolink_record_get.err || true

    echo "[*] Sending POST /cgi-bin/cstecgi.cgi ..."
    curl -sS --max-time 3 --retry 10 --retry-connrefused --retry-delay 1 \
        -X POST "http://127.0.0.1:8080/cgi-bin/cstecgi.cgi" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "topicurl=setting/getSanvasStatus&loginUser=admin&loginPass=admin" \
        >/tmp/totolink_record_post.out 2>/tmp/totolink_record_post.err || true
fi

wait "$QEMU_PID" || true

echo "[*] Recording finished. Checking trace file..."
ls -lh "$TRACE_OUTPUT"

if [ -f "$TRACE_OUTPUT" ]; then
    echo "[*] Trace file created successfully."
    echo "[*] Analyzing new trace..."
    python3 - <<'PY'
from pathlib import Path
import sys
sys.path.insert(0, str(Path('/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/fuzzing').resolve()))
from conductor.trace_analyzer import TraceAnalyzer

trace = "/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/seeds/TOTOLINK/boa_totolink_v2.trace"
ta = TraceAnalyzer(trace, arch='mips', word_size=32)
ta.analyze()
print(f"[*] syscalls={len(ta.syscalls)} auth_boundary={ta.get_auth_boundary()}")
PY
else
    echo "[!] Trace file NOT created!"
    cat "$LOG_file"
fi
