#!/bin/bash
set -e

# Configuration
MIKRO_ROOT="/home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/tests/images/MikroTik/system_pkg"
TARGET_BINARY="$MIKRO_ROOT/nova/bin/www"
WORKERS=4
QEMU_PATH="/home/webfuzz/Documents/qemu/build/qemu-i386"

# Ensure mock supervisor is running
MOCK_SCRIPT="tests/verified_targets/MikroTik_6.48.6/mock_supervisor.py"
PID_FILE="/tmp/mikro_mock.pid"

if [ -f "$PID_FILE" ]; then
    kill $(cat "$PID_FILE") 2>/dev/null || true
    rm "$PID_FILE"
fi

echo "[*] Starting Mock Supervisor..."
nohup python3 "$MOCK_SCRIPT" > /tmp/mikro_mock_fuzz.log 2>&1 &
echo $! > "$PID_FILE"
# Wait for socket
sleep 1
ls -l /tmp/novasock

echo "[*] Launching Fuzz Master..."

# Using the patched libumsg.so in-place, so no LD_PRELOAD needed for path,
# unless we revert to clean image. Assuming patched state for now.

# We need to pass the architecture explicitly as it's x86 (i386)
# And we need to ensure the library path is correct.
# QEMU automatically handles -L for libraries.

cd /home/webfuzz/Documents/qemu/linux-user/rr_fuzzing/

# Unset QEMU_LD_PREFIX to avoid conflicts (handled by -L)
unset QEMU_LD_PREFIX

# CRITICAL: Enable RR Fuzzing Mode
export RR_MODE=REPLAY_ADVANCE

python3 -m fuzzing.multiprocess.fuzz_master \
    --target "$TARGET_BINARY" \
    --trace "tests/verified_targets/MikroTik_6.48.6/traces/init.txt" \
    --sync-dir "tests/verified_targets/MikroTik_6.48.6/sync" \
    --workers $WORKERS \
    --qemu "tests/verified_targets/MikroTik_6.48.6/qemu_wrapper.sh" \
    --architecture "i386"
