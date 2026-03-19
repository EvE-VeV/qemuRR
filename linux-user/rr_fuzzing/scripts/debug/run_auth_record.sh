#!/bin/bash
export RR_MODE=record
export RR_TRACE_FILE=tenda_auth.trace
export RR_DEBUG_LEVEL=1

# Start QEMU in background
./build/qemu-arm -L linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root linux-user/rr_fuzzing/tests/images/TENDA_AC15/_US_AC15V1.0BR_V15.03.05.19_multi_TD01.bin.extracted/squashfs-root/bin/httpd &
QEMU_PID=$!

sleep 5

# Run the auth script
bash record_auth_tenda.sh

sleep 5

# Graceful stop
kill $QEMU_PID
wait $QEMU_PID 2>/dev/null

echo "[+] Auth Recording Done: tenda_auth.trace"
